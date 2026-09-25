/**
 * @fileoverview Tests for `cisa_get_ssvc` — the assetExposure unknown both-arms
 * behavior, every Vulnrichment miss guidance variant, the
 * enrichment_source_unavailable error, the lagging-timestamp notice, and
 * assignmentAgrees.
 * @module tests/mcp-server/tools/definitions/get-ssvc.tool.test
 */

import { createFetchMock, createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getSsvcTool } from '@/mcp-server/tools/definitions/get-ssvc.tool.js';
import {
  getKevCatalog,
  initKevCatalog,
  KEV_FEED_URL,
  resetKevCatalog,
} from '@/services/kev-catalog/kev-catalog-service.js';
import { cveToVulnrichmentUrl } from '@/services/vulnrichment/paths.js';
import {
  initVulnrichment,
  resetVulnrichment,
} from '@/services/vulnrichment/vulnrichment-service.js';
import { buildKevFeedBody } from '../../../fixtures/kev-feed.js';
import {
  buildSsvcRecord,
  NO_CISA_CONTAINER_RECORD,
  NO_SSVC_METRIC_RECORD,
} from '../../../fixtures/vulnrichment-records.js';
import { firstText } from '../../../helpers/format-text.js';

async function loadCatalog() {
  const http = createFetchMock([
    {
      match: KEV_FEED_URL,
      respond: new Response(buildKevFeedBody(), {
        headers: { 'content-type': 'application/json' },
      }),
    },
  ]);
  http.install();
  try {
    await getKevCatalog().snapshot(createMockContext());
  } finally {
    http.restore();
  }
}

describe('cisa_get_ssvc', () => {
  beforeEach(() => {
    resetKevCatalog();
    resetVulnrichment();
    initKevCatalog({
      refreshCron: '*/30 * * * *',
      timeoutMs: 5000,
      now: () => new Date('2026-09-10T00:00:00Z'),
    });
    initVulnrichment({ cacheTtlSeconds: 21_600, timeoutMs: 5000 });
  });

  afterEach(() => {
    resetKevCatalog();
    resetVulnrichment();
  });

  it('assetExposure unknown returns both arms without guessing', async () => {
    await loadCatalog();
    const cveId = 'CVE-2026-30000';
    const http = createFetchMock([
      { match: cveToVulnrichmentUrl(cveId) as string, respond: Response.json(buildSsvcRecord()) },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId] });
      const result = await getSsvcTool.handler(input, ctx);
      expect(result.results[0]?.bod2604?.timelines).toHaveLength(2);
      expect(result.results[0]?.bod2604?.timelines.map((t) => t.assetExposure).sort()).toEqual([
        'not_publicly_exposed',
        'publicly_exposed',
      ]);
    } finally {
      http.restore();
    }
  });

  it('normalizes case and whitespace on cveIds before the fetch and the KEV join', async () => {
    await loadCatalog();
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl('CVE-2026-00001') as string,
        respond: Response.json(buildSsvcRecord()),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [' cve-2026-00001\t'] });
      const result = await getSsvcTool.handler(input, ctx);
      expect(result.results[0]?.cveId).toBe('CVE-2026-00001');
      expect(result.results[0]?.found).toBe(true);
      expect(result.results[0]?.inKev).toBe(true);
      expect(http.calls).toHaveLength(1);
    } finally {
      http.restore();
    }
  });

  it('a stated assetExposure returns exactly one timeline and computes assignmentAgrees', async () => {
    await loadCatalog();
    /* CVE-2026-00001 is in KEV with dueDate 2026-09-04, dateAdded 2026-09-01 (3 days). */
    const cveId = 'CVE-2026-00001';
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl(cveId) as string,
        respond: Response.json(buildSsvcRecord({ automatable: 'yes', technicalImpact: 'total' })),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId], assetExposure: 'publicly_exposed' });
      const result = await getSsvcTool.handler(input, ctx);
      const entry = result.results[0];
      expect(entry?.bod2604?.timelines).toHaveLength(1);
      expect(entry?.bod2604?.timelines[0]?.assetExposure).toBe('publicly_exposed');
      expect(entry?.kevAssigned).toMatchObject({
        dateAdded: '2026-09-01',
        dueDate: '2026-09-04',
        daysFromAdd: 3,
      });
      /* Table row 1: publicly exposed + in KEV + automatable + total = 3 days, matches kevAssigned's 3. */
      expect(entry?.assignmentAgrees).toBe(true);
    } finally {
      http.restore();
    }
  });

  it('reports disagreement when the computed timeline does not match the assigned due date', async () => {
    await loadCatalog();
    const cveId = 'CVE-2026-00002'; /* dueDate 2026-09-19, dateAdded 2026-09-05 = 14 days */
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl(cveId) as string,
        /* automatable + total under publicly exposed + in KEV computes to row 1 = 3 days, not 14. */
        respond: Response.json(buildSsvcRecord({ automatable: 'yes', technicalImpact: 'total' })),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId], assetExposure: 'publicly_exposed' });
      const result = await getSsvcTool.handler(input, ctx);
      expect(result.results[0]?.assignmentAgrees).toBe(false);
    } finally {
      http.restore();
    }
  });

  it('guidance: 404 from Vulnrichment routes to cisa_check_cve_status', async () => {
    await loadCatalog();
    const cveId = 'CVE-2026-40000';
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl(cveId) as string,
        respond: new Response('404: Not Found', { status: 404 }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId] });
      const result = await getSsvcTool.handler(input, ctx);
      expect(result.results[0]?.found).toBe(false);
      expect(result.results[0]?.guidance).toContain('cisa_check_cve_status');
      expect(result.foundCount).toBe(0);
    } finally {
      http.restore();
    }
  });

  it('guidance: a record with no CISA-authored container', async () => {
    await loadCatalog();
    const cveId = 'CVE-2026-33333';
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl(cveId) as string,
        respond: Response.json(NO_CISA_CONTAINER_RECORD),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId] });
      const result = await getSsvcTool.handler(input, ctx);
      expect(result.results[0]?.found).toBe(false);
      expect(result.results[0]?.guidance).toContain('no CISA-authored enrichment container');
    } finally {
      http.restore();
    }
  });

  it('guidance: CVSS/CWE present but no SSVC metric', async () => {
    await loadCatalog();
    const cveId = 'CVE-2026-22222';
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl(cveId) as string,
        respond: Response.json(NO_SSVC_METRIC_RECORD),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId] });
      const result = await getSsvcTool.handler(input, ctx);
      expect(result.results[0]?.found).toBe(false);
      expect(result.results[0]?.cvss).toMatchObject({ baseScore: 5.3 });
      expect(result.results[0]?.guidance).toContain('has not published SSVC decision points');
    } finally {
      http.restore();
    }
  });

  it('emits the lagging-timestamp notice when SSVC predates the KEV addition', async () => {
    await loadCatalog();
    /* CVE-2026-00005 was added to KEV on 2026-01-01; publish the SSVC decision before that. */
    const cveId = 'CVE-2026-00005';
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl(cveId) as string,
        respond: Response.json(buildSsvcRecord({ ssvcTimestamp: '2025-12-01T00:00:00Z' })),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId] });
      await getSsvcTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain('may not reflect current exploitation status');
    } finally {
      http.restore();
    }
  });

  it('emits the zero-found notice when nothing enriches', async () => {
    await loadCatalog();
    const cveId = 'CVE-2026-40001';
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl(cveId) as string,
        respond: new Response('404: Not Found', { status: 404 }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId] });
      await getSsvcTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain('Coverage is incomplete');
    } finally {
      http.restore();
    }
  });

  it('throws enrichment_source_unavailable when every fetch fails', async () => {
    await loadCatalog();
    const cveId = 'CVE-2026-50000';
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl(cveId) as string,
        respond: () => {
          throw new TypeError('network failure');
        },
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId] });
      await expect(getSsvcTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'enrichment_source_unavailable' },
      });
    } finally {
      http.restore();
    }
  }, 15000);

  it('accepts up to 50 CVE IDs and rejects 51', () => {
    const fifty = Array.from({ length: 50 }, (_, i) => `CVE-2026-${(60000 + i).toString()}`);
    expect(() => getSsvcTool.input.parse({ cveIds: fifty })).not.toThrow();
    const fiftyOne = Array.from({ length: 51 }, (_, i) => `CVE-2026-${(60000 + i).toString()}`);
    expect(() => getSsvcTool.input.parse({ cveIds: fiftyOne })).toThrow();
  });

  it('structuredContent and content[] carry the same fields', async () => {
    await loadCatalog();
    const cveId = 'CVE-2026-70000';
    const http = createFetchMock([
      { match: cveToVulnrichmentUrl(cveId) as string, respond: Response.json(buildSsvcRecord()) },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const input = getSsvcTool.input.parse({ cveIds: [cveId], assetExposure: 'publicly_exposed' });
      const result = await getSsvcTool.handler(input, ctx);
      const text = firstText(getSsvcTool.format?.(result));
      const entry = result.results[0];
      expect(text).toContain(entry?.cveId as string);
      expect(text).toContain(entry?.exploitation as string);
      expect(text).toContain(entry?.ssvcVersion as string);
      expect(text).toContain(String(entry?.cvss?.baseScore));
      expect(text).toContain(entry?.bod2604?.basis as string);
      expect(text).toContain(entry?.bod2604?.caveat as string);
    } finally {
      http.restore();
    }
  });
});
