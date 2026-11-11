/**
 * @fileoverview Tests for `cisa_get_ssvc` — the assetExposure unknown both-arms
 * behavior, every Vulnrichment miss guidance variant, the
 * enrichment_source_unavailable error, the lagging-timestamp notice, and
 * assignmentAgrees.
 * @module tests/mcp-server/tools/definitions/get-ssvc.tool.test
 */

import {
  createFetchMock,
  createMockContext,
  getEnrichment,
  runToolContract,
} from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetServerConfig } from '@/config/server-config.js';
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
import { buildKevFeedBody, KEV_RECORDS } from '../../../fixtures/kev-feed.js';
import {
  buildSsvcRecord,
  HISTORICAL_SSVC_RECORD,
  NO_CISA_CONTAINER_RECORD,
  NO_SSVC_METRIC_RECORD,
} from '../../../fixtures/vulnrichment-records.js';
import { contentText, firstText } from '../../../helpers/format-text.js';

async function loadCatalog(extraRecords: unknown[] = []) {
  const http = createFetchMock([
    {
      match: KEV_FEED_URL,
      respond: new Response(buildKevFeedBody(extraRecords), {
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
  it('separates failed fetches from confirmed misses and retries failures', async () => {
    await loadCatalog();
    const ids = ['CVE-2026-81000', 'CVE-2026-81001', 'CVE-2026-81002'];
    const http = createFetchMock(
      ids.map((id, index) => ({
        match: cveToVulnrichmentUrl(id) as string,
        respond: () =>
          index === 0
            ? new Response('', { status: 403 })
            : index === 1
              ? Response.json(buildSsvcRecord())
              : new Response('', { status: 404 }),
      })),
    );
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const result = await getSsvcTool.handler(getSsvcTool.input.parse({ cveIds: ids }), ctx);
      expect(result).toMatchObject({
        foundCount: 1,
        notFoundCount: 1,
        failedCount: 1,
        results: [{ outcome: 'fetch_failed' }, { outcome: 'ssvc' }, { outcome: 'not_found' }],
      });
      expect(firstText(getSsvcTool.format?.(result))).toContain('1 failed lookup');
      const second = await getSsvcTool.handler(
        getSsvcTool.input.parse({ cveIds: [ids[0], ids[2]] }),
        ctx,
      );
      expect(second).toMatchObject({ foundCount: 0, notFoundCount: 1, failedCount: 1 });
      expect(getEnrichment(ctx).notice).toContain('1 lookup');
      expect(getEnrichment(ctx).notice).not.toContain('None of the processed CVEs');
      expect(http.calls).toHaveLength(4);
      const contract = await runToolContract(getSsvcTool, { cveIds: ids });
      expect(contract.structuredContent).toMatchObject({ failedCount: 1, notFoundCount: 1 });
      expect(contentText(contract)).toContain('fetch_failed');
      expect(contentText(contract)).toContain('1 failed lookup');
    } finally {
      http.restore();
    }
  });
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
    vi.unstubAllEnvs();
    resetServerConfig();
  });

  it('rejects oversized batches before any upstream work when normalization is disabled', async () => {
    vi.stubEnv('CISA_CLAMP_OVERSIZED_INPUTS', 'false');
    resetServerConfig();
    const http = createFetchMock([]);
    http.install();
    try {
      const result = await runToolContract(getSsvcTool, {
        cveIds: Array(51).fill('CVE-2026-60000'),
      });
      expect(result.structuredContent).toMatchObject({
        error: { data: { reason: 'read_limit_exceeded', retryable: false } },
      });
      expect(contentText(result)).toContain('50');
      expect(contentText(result)).toContain('Send at most');
      expect(http.calls).toHaveLength(0);
    } finally {
      http.restore();
    }
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
      expect(result.results[0]).not.toHaveProperty('assignmentAgrees');
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
      expect(firstText(getSsvcTool.format?.(result))).toContain(
        'Assignment agrees with the computed timeline:** yes',
      );
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

  it.each([
    ['CVE-2026-00005', 'total', true, 'No'],
    ['CVE-2026-00001', 'partial', false, 'Yes'],
  ])(
    'reports triage disagreement for %s even when the day count matches',
    async (cveId, technicalImpact, triage, assigned) => {
      await loadCatalog();
      const http = createFetchMock([
        {
          match: cveToVulnrichmentUrl(cveId) as string,
          respond: Response.json(buildSsvcRecord({ technicalImpact })),
        },
      ]);
      http.install();
      try {
        const result = await runToolContract(getSsvcTool, {
          cveIds: [cveId],
          assetExposure: 'publicly_exposed',
        });
        expect(result.structuredContent).toMatchObject({
          results: [
            {
              assignmentAgrees: false,
              bod2604: {
                timelines: [{ remediationTimelineDays: 3, forensicTriageRequired: triage }],
              },
              kevAssigned: { daysFromAdd: 3, forensicTriage: assigned },
            },
          ],
        });
        expect(contentText(result)).toContain('Assignment agrees with the computed timeline:** no');
      } finally {
        http.restore();
      }
    },
  );

  it('resolves both timeline arms for the pinned historical record in a mixed batch', async () => {
    const cveId = 'CVE-2024-27834';
    await loadCatalog([{ ...KEV_RECORDS[0], cveID: cveId }]);
    const http = createFetchMock([
      {
        match: cveToVulnrichmentUrl('CVE-2026-00001') as string,
        respond: Response.json(buildSsvcRecord()),
      },
      {
        match: cveToVulnrichmentUrl(cveId) as string,
        respond: Response.json(HISTORICAL_SSVC_RECORD),
      },
    ]);
    http.install();
    try {
      const result = await runToolContract(getSsvcTool, { cveIds: ['CVE-2026-00001', cveId] });
      expect(result.structuredContent).toMatchObject({
        echo: { requested: 2, assetExposure: 'unknown' },
        foundCount: 2,
        notFoundCount: 0,
        failedCount: 0,
        results: [
          { cveId: 'CVE-2026-00001', outcome: 'ssvc' },
          {
            cveId,
            exploitation: 'none',
            automatable: 'yes',
            technicalImpact: 'total',
            bod2604: { timelines: [{ tableRow: 1 }, { tableRow: 9 }] },
          },
        ],
      });
      expect(contentText(result)).toContain('**Request:** 2 CVE(s), assetExposure unknown');
      expect(contentText(result)).toContain(
        'Exploitation none · Automatable yes · Technical Impact total',
      );
      expect(contentText(result)).toContain('not_publicly_exposed: row 9');
      expect(contentText(result)).not.toContain('Assignment agrees');
    } finally {
      http.restore();
    }
  });

  it.each([
    ['Automatable', { automatable: 'Contextual' }, { automatable: 'Contextual' }],
    ['Technical Impact', { technicalImpact: 'Conditional' }, { technicalImpact: 'Conditional' }],
  ])('preserves complete SSVC evidence with unsupported %s', async (point, options, expected) => {
    await loadCatalog();
    const cveId = 'CVE-2026-00001';
    const sourceUrl = cveToVulnrichmentUrl(cveId) as string;
    const http = createFetchMock([
      {
        match: sourceUrl,
        respond: Response.json(buildSsvcRecord({ ...options, exploitation: 'Pre-release' })),
      },
    ]);
    http.install();
    try {
      const result = await runToolContract(getSsvcTool, {
        cveIds: [cveId],
        assetExposure: 'publicly_exposed',
      });
      const guidance = `No BOD 26-04 timeline was computed because CISA published unsupported SSVC ${point} value.`;
      expect(result.structuredContent).toMatchObject({
        foundCount: 1,
        notFoundCount: 0,
        failedCount: 0,
        results: [
          {
            cveId,
            found: true,
            outcome: 'ssvc',
            exploitation: 'Pre-release',
            automatable: 'yes',
            technicalImpact: 'total',
            ...expected,
            ssvcVersion: '2.0.3',
            ssvcTimestamp: '2026-09-05T00:00:00Z',
            ssvcRole: 'CISA Coordinator',
            cvss: { baseScore: 9.8 },
            cwes: [{ cweId: 'CWE-20' }],
            inKev: true,
            kevAssigned: { daysFromAdd: 3, forensicTriage: 'Yes' },
            sourceUrl,
            guidance,
          },
        ],
      });
      expect(result.structuredContent).not.toHaveProperty('results.0.bod2604');
      expect(result.structuredContent).not.toHaveProperty('results.0.assignmentAgrees');
      const text = contentText(result);
      for (const value of [
        guidance,
        'Pre-release',
        Object.values(expected)[0],
        '2.0.3',
        '2026-09-05T00:00:00Z',
        'CISA Coordinator',
        '9.8',
        'CWE-20',
        'forensic triage Yes',
        sourceUrl,
      ]) {
        expect(text).toContain(value);
      }
      expect(text).not.toContain('BOD 26-04 computed timeline');
      expect(text).not.toContain('Assignment agrees');
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
      expect(result.notFoundCount).toBe(1);
      expect(firstText(getSsvcTool.format?.(result))).toContain('1 without');
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
      expect(result.results[0]?.outcome).toBe('no_cisa_container');
      expect(result.failedCount).toBe(0);
      expect(firstText(getSsvcTool.format?.(result))).toContain('no_cisa_container');
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
      expect(result.results[0]?.outcome).toBe('no_ssvc_metric');
      expect(result.results[0]?.cwes).toEqual([]);
      expect(firstText(getSsvcTool.format?.(result))).toContain('no_ssvc_metric');
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

  it('processes only the first 50 IDs and returns the normalized remainder', async () => {
    await loadCatalog();
    const ids = Array.from({ length: 52 }, (_, i) => `CVE-2026-${60000 + i}`);
    ids[50] = ' cve-2026-60050 ';
    const tailCve = 'CVE-2026-00001';
    ids[51] = tailCve;
    const http = createFetchMock([
      ...ids.slice(0, 50).map((id) => ({
        match: cveToVulnrichmentUrl(id) as string,
        respond: () => new Response('', { status: 404 }),
      })),
      {
        match: cveToVulnrichmentUrl(tailCve) as string,
        respond: () => Response.json(buildSsvcRecord()),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getSsvcTool.errors });
      const result = await getSsvcTool.handler(getSsvcTool.input.parse({ cveIds: ids }), ctx);
      expect(result).toMatchObject({
        foundCount: 0,
        notFoundCount: 50,
        failedCount: 0,
        unprocessedIds: ['CVE-2026-60050', tailCve],
      });
      expect(result.results).toHaveLength(50);
      expect(http.calls).toHaveLength(50);
      expect(firstText(getSsvcTool.format?.(result))).toContain('CVE-2026-60050');
      expect(getEnrichment(ctx).notice).toContain('follow-up');
      expect(getEnrichment(ctx).notice).toContain('Coverage is incomplete');
      const contract = await runToolContract(getSsvcTool, { cveIds: ids });
      const absence = 'None of the processed CVEs carry published SSVC decision points.';
      expect(contract.structuredContent).toMatchObject({
        unprocessedIds: ['CVE-2026-60050', tailCve],
        foundCount: 0,
        failedCount: 0,
        notFoundCount: 50,
        echo: { requested: 52 },
        notice: expect.stringContaining(absence),
      });
      expect(contentText(contract)).toContain('CVE-2026-60050');
      expect(contentText(contract)).toContain('**Request:** 52 CVE(s), assetExposure unknown');
      expect(contentText(contract)).toContain(absence);
      expect(http.calls).toHaveLength(100);
      const followUp = await runToolContract(getSsvcTool, { cveIds: [tailCve] });
      expect(followUp.structuredContent).toMatchObject({
        results: [{ cveId: tailCve, found: true, outcome: 'ssvc' }],
      });
    } finally {
      http.restore();
    }
  });

  it('keeps an oversized all-failed batch an error and never fetches its remainder', async () => {
    await loadCatalog();
    const ids = Array.from({ length: 51 }, (_, i) => `CVE-2026-${62000 + i}`);
    const http = createFetchMock(
      ids.slice(0, 50).map((id) => ({
        match: cveToVulnrichmentUrl(id) as string,
        respond: () => new Response('', { status: 403 }),
      })),
    );
    http.install();
    try {
      const result = await runToolContract(getSsvcTool, { cveIds: ids });
      expect(result.structuredContent).toMatchObject({
        error: {
          data: {
            reason: 'enrichment_source_unavailable',
            recovery: { hint: expect.stringContaining('cisa_check_cve_status') },
          },
        },
      });
      expect(contentText(result)).toContain('cisa_check_cve_status');
      expect(http.calls).toHaveLength(50);
    } finally {
      http.restore();
    }
  });

  it('accepts up to 1000 CVE IDs and rejects invalid remainders', () => {
    const fifty = Array.from({ length: 50 }, (_, i) => `CVE-2026-${(60000 + i).toString()}`);
    expect(() => getSsvcTool.input.parse({ cveIds: fifty })).not.toThrow();
    const fiftyOne = Array.from({ length: 51 }, (_, i) => `CVE-2026-${(60000 + i).toString()}`);
    expect(() => getSsvcTool.input.parse({ cveIds: fiftyOne })).not.toThrow();
    expect(() => getSsvcTool.input.parse({ cveIds: [...fifty, 'bad'] })).toThrow();
    expect(() => getSsvcTool.input.parse({ cveIds: Array(1001).fill('CVE-2026-60000') })).toThrow();
    expect(() => getSsvcTool.input.parse({ cveIds: [] })).toThrow();
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
