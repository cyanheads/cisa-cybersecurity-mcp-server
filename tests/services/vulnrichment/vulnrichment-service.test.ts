/**
 * @fileoverview Tests for the Vulnrichment service — per-CVE fetch with a TTL
 * cache, the ssvc/no_ssvc_metric/no_cisa_container/not_found/fetch_failed
 * outcome discrimination, and the pure `normalizeVulnrichment` mapper.
 * @module tests/services/vulnrichment/vulnrichment-service.test
 */

import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cveToVulnrichmentUrl } from '@/services/vulnrichment/paths.js';
import {
  getVulnrichment,
  initVulnrichment,
  normalizeVulnrichment,
  resetVulnrichment,
} from '@/services/vulnrichment/vulnrichment-service.js';
import {
  buildSsvcRecord,
  NO_CISA_CONTAINER_RECORD,
  NO_SSVC_METRIC_RECORD,
} from '../../fixtures/vulnrichment-records.js';

describe('normalizeVulnrichment', () => {
  const normalize = (raw: unknown) =>
    normalizeVulnrichment('CVE-2026-12345', 'https://example.test/record.json', raw);
  const container = (fields: Record<string, unknown>) => ({
    containers: { adp: [{ providerMetadata: { shortName: 'CISA-ADP' }, ...fields }] },
  });

  it.each([
    null,
    {},
    { containers: null },
    { containers: {} },
    { containers: { adp: [null, {}, { providerMetadata: null }] } },
  ])('preserves absent CISA enrichment as an explicit outcome for %j', (raw) => {
    expect(normalize(raw)).toMatchObject({ outcome: 'no_cisa_container', cwes: [] });
  });

  it('ignores malformed metrics and CWE entries while preserving usable sparse data', () => {
    const record = normalize(
      container({
        metrics: [
          null,
          {},
          { other: {} },
          { other: { type: 'ssvc', content: null } },
          { cvssV4_0: { baseScore: '9.0' } },
          { cvssV3_0: { baseScore: 7.5 } },
        ],
        problemTypes: [
          null,
          {},
          { descriptions: [null, {}, { cweId: ' ' }, { cweId: ' CWE-79 ', description: '' }] },
        ],
      }),
    );
    expect(record.outcome).toBe('no_ssvc_metric');
    expect(record.cvss).toEqual({
      version: 'cvssV3_0',
      baseScore: 7.5,
      baseSeverity: '',
      vectorString: '',
    });
    expect(record.cwes).toEqual([{ cweId: 'CWE-79', description: '' }]);
  });

  it.each([
    {},
    { metrics: {}, problemTypes: {} },
    { metrics: [{ other: { type: 'ssvc', content: {} } }] },
    {
      metrics: [
        {
          other: {
            type: 'ssvc',
            content: { options: [null, { Automatable: 1 }, { 'Technical Impact': 'total' }] },
          },
        },
      ],
    },
  ])('does not invent SSVC points from incomplete enrichment %j', (fields) => {
    const record = normalize(container(fields));
    expect(record).toMatchObject({ outcome: 'no_ssvc_metric', cwes: [] });
    expect(record.cvss).toBeUndefined();
    expect(record.automatable).toBeUndefined();
  });

  it('returns complete sparse SSVC points without inventing optional metadata or CVSS', () => {
    const record = normalize(
      container({
        metrics: [
          {
            other: {
              type: 'ssvc',
              content: {
                options: [{ Automatable: 'no' }, { 'Technical Impact': 'partial' }],
              },
            },
          },
        ],
      }),
    );
    expect(record).toEqual({
      cveId: 'CVE-2026-12345',
      sourceUrl: 'https://example.test/record.json',
      outcome: 'ssvc',
      automatable: 'no',
      technicalImpact: 'partial',
      cwes: [],
    });
  });

  it('prefers a usable v4 score over v3 while skipping an unusable earlier v4 score', () => {
    const record = normalize(
      container({
        metrics: [
          { cvssV4_0: {} },
          { cvssV3_1: { baseScore: 9.8 } },
          {
            cvssV4_0: {
              version: '4.0',
              baseScore: 0,
              baseSeverity: 'NONE',
              vectorString: 'CVSS:4.0/AV:N',
            },
          },
        ],
      }),
    );
    expect(record.cvss).toEqual({
      version: '4.0',
      baseScore: 0,
      baseSeverity: 'NONE',
      vectorString: 'CVSS:4.0/AV:N',
    });
  });

  it('reads exploitation, automatable, technicalImpact — Technical Impact carries a space upstream', () => {
    const record = normalizeVulnrichment(
      'CVE-2026-12345',
      'https://example.test/CVE-2026-12345.json',
      buildSsvcRecord(),
    );
    expect(record.outcome).toBe('ssvc');
    expect(record.exploitation).toBe('active');
    expect(record.automatable).toBe('yes');
    expect(record.technicalImpact).toBe('total');
    expect(record.cvss).toMatchObject({ baseScore: 9.8, version: '3.1' });
    expect(record.cwes).toEqual([
      { cweId: 'CWE-20', description: 'CWE-20 Improper Input Validation' },
    ]);
  });

  it('returns no_ssvc_metric when the CISA-ADP container carries CVSS/CWE but no SSVC metric', () => {
    const record = normalizeVulnrichment(
      'CVE-2026-22222',
      'https://example.test/CVE-2026-22222.json',
      NO_SSVC_METRIC_RECORD,
    );
    expect(record.outcome).toBe('no_ssvc_metric');
    expect(record.cvss).toMatchObject({ baseScore: 5.3 });
    expect(record.guidance).toContain('has not published SSVC decision points');
  });

  it('returns no_cisa_container when adp[] holds only a non-CISA provider', () => {
    const record = normalizeVulnrichment(
      'CVE-2026-33333',
      'https://example.test/CVE-2026-33333.json',
      NO_CISA_CONTAINER_RECORD,
    );
    expect(record.outcome).toBe('no_cisa_container');
    expect(record.cwes).toEqual([]);
    expect(record.cvss).toBeUndefined();
  });
});

describe('VulnrichmentService', () => {
  beforeEach(() => {
    resetVulnrichment();
    initVulnrichment({ cacheTtlSeconds: 21_600, timeoutMs: 5000 });
  });

  afterEach(() => {
    resetVulnrichment();
  });

  it('fetches an SSVC record and caches it under ssvc/<CVE-ID>', async () => {
    const cveId = 'CVE-2026-12345';
    const url = cveToVulnrichmentUrl(cveId) as string;
    const http = createFetchMock([
      {
        match: url,
        respond: Response.json(buildSsvcRecord(), {
          headers: { 'content-type': 'application/json' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      const [record] = await getVulnrichment().fetchMany([cveId], ctx);
      expect(record?.outcome).toBe('ssvc');
      expect(http.calls).toHaveLength(1);

      const cached = await ctx.state.get(`ssvc/${cveId}`);
      expect(cached).toMatchObject({ outcome: 'ssvc' });

      /* A second lookup reads the cache — no second fetch. */
      await getVulnrichment().fetchMany([cveId], ctx);
      expect(http.calls).toHaveLength(1);
    } finally {
      http.restore();
    }
  });

  it('returns not_found with guidance for a 404, and does not throw', async () => {
    const cveId = 'CVE-2026-99999';
    const url = cveToVulnrichmentUrl(cveId) as string;
    const http = createFetchMock([
      { match: url, respond: new Response('404: Not Found', { status: 404 }) },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      const [record] = await getVulnrichment().fetchMany([cveId], ctx);
      expect(record?.outcome).toBe('not_found');
      expect(record?.guidance).toContain('cisa_check_cve_status');
    } finally {
      http.restore();
    }
  });

  it('resolves a batch preserving input order, one result per CVE', async () => {
    const cveIds = ['CVE-2026-00001', 'CVE-2026-00002', 'CVE-2026-00003'];
    const http = createFetchMock(
      cveIds.map((cveId) => ({
        match: cveToVulnrichmentUrl(cveId) as string,
        respond: new Response('404: Not Found', { status: 404 }),
      })),
    );
    http.install();
    try {
      const ctx = createMockContext();
      const records = await getVulnrichment().fetchMany(cveIds, ctx);
      expect(records.map((r) => r.cveId)).toEqual(cveIds);
    } finally {
      http.restore();
    }
  });

  it('returns fetch_failed (not a throw) when the transport fails, after retries are exhausted', async () => {
    const cveId = 'CVE-2026-55555';
    const url = cveToVulnrichmentUrl(cveId) as string;
    const http = createFetchMock([
      {
        match: url,
        respond: () => {
          throw new TypeError('network failure');
        },
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      const [record] = await getVulnrichment().fetchMany([cveId], ctx);
      expect(record?.outcome).toBe('fetch_failed');
      expect(record?.guidance).toContain('could not be reached');
    } finally {
      http.restore();
    }
  }, 15000);

  it('a storage read/write failure falls through to a fetch rather than breaking the lookup', async () => {
    const cveId = 'CVE-2026-77777';
    const url = cveToVulnrichmentUrl(cveId) as string;
    const http = createFetchMock([
      {
        match: url,
        respond: Response.json(buildSsvcRecord(), {
          headers: { 'content-type': 'application/json' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      /* Simulate a broken cache: state.get always rejects. */
      ctx.state.get = () => Promise.reject(new Error('storage unavailable'));
      const [record] = await getVulnrichment().fetchMany([cveId], ctx);
      expect(record?.outcome).toBe('ssvc');
    } finally {
      http.restore();
    }
  });
});
