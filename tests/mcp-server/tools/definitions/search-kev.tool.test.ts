/**
 * @fileoverview Tests for `cisa_search_kev` — filters, pagination, sort,
 * invalid_date_range, and every zero-hit notice fragment.
 * @module tests/mcp-server/tools/definitions/search-kev.tool.test
 */

import { createFetchMock, createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { searchKevTool } from '@/mcp-server/tools/definitions/search-kev.tool.js';
import {
  getKevCatalog,
  initKevCatalog,
  KEV_FEED_URL,
  resetKevCatalog,
} from '@/services/kev-catalog/kev-catalog-service.js';
import { buildKevFeedBody } from '../../../fixtures/kev-feed.js';
import { firstText } from '../../../helpers/format-text.js';

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

describe('cisa_search_kev', () => {
  beforeEach(() => {
    resetKevCatalog();
    initKevCatalog({
      refreshCron: '*/30 * * * *',
      timeoutMs: 5000,
      now: () => new Date('2026-09-10T00:00:00Z'),
    });
  });

  afterEach(() => {
    resetKevCatalog();
  });

  it('AND-combines filters and paginates with cursor + hasMore', async () => {
    await loadCatalog();
    const ctx = createMockContext({ errors: searchKevTool.errors });
    const input = searchKevTool.input.parse({
      vendorProject: 'acme',
      limit: 1,
      sortBy: 'dateAdded',
      order: 'asc',
    });
    const page1 = await searchKevTool.handler(input, ctx);
    expect(page1.results).toHaveLength(1);
    expect(page1.hasMore).toBe(true);
    expect(page1.cursor).toBeDefined();

    const enrichment1 = getEnrichment(ctx);
    expect(enrichment1.totalCount).toBe(2);
    expect(enrichment1.truncated).toBe(true);
    expect(enrichment1.shown).toBe(1);
    expect(enrichment1.cap).toBe(1);

    const ctx2 = createMockContext({ errors: searchKevTool.errors });
    const page2Input = searchKevTool.input.parse({
      vendorProject: 'acme',
      limit: 1,
      sortBy: 'dateAdded',
      order: 'asc',
      cursor: page1.cursor,
    });
    const page2 = await searchKevTool.handler(page2Input, ctx2);
    expect(page2.results).toHaveLength(1);
    expect(page2.hasMore).toBe(false);
    expect(page2.cursor).toBeUndefined();
  });

  it('content[] and structuredContent carry the same fields', async () => {
    await loadCatalog();
    const ctx = createMockContext({ errors: searchKevTool.errors });
    const input = searchKevTool.input.parse({ vendorProject: 'acme', limit: 25 });
    const result = await searchKevTool.handler(input, ctx);
    const text = firstText(searchKevTool.format?.(result));
    for (const record of result.results) {
      expect(text).toContain(record.cveId);
      expect(text).toContain(record.vulnerabilityName as string);
    }
  });

  it('echoes appliedFilters, catalog, and asOf on every call', async () => {
    await loadCatalog();
    const ctx = createMockContext({ errors: searchKevTool.errors });
    const input = searchKevTool.input.parse({ cwe: 'CWE-20' });
    await searchKevTool.handler(input, ctx);
    const enrichment = getEnrichment(ctx);
    expect(enrichment.appliedFilters).toMatchObject({
      cwe: 'CWE-20',
      sortBy: 'dateAdded',
      order: 'desc',
    });
    expect(enrichment.catalog).toMatchObject({ catalogVersion: '2026.09.18' });
    expect(enrichment.asOf).toBe('2026-09-10');
  });

  it('emits snapshotCaveat when dateAddedFrom is set', async () => {
    await loadCatalog();
    const ctx = createMockContext({ errors: searchKevTool.errors });
    const input = searchKevTool.input.parse({ dateAddedFrom: '2026-01-01' });
    await searchKevTool.handler(input, ctx);
    const enrichment = getEnrichment(ctx);
    expect(enrichment.snapshotCaveat).toContain('no per-record modified timestamp');
  });

  it('does not emit snapshotCaveat when dateAddedFrom is unset', async () => {
    await loadCatalog();
    const ctx = createMockContext({ errors: searchKevTool.errors });
    const input = searchKevTool.input.parse({});
    await searchKevTool.handler(input, ctx);
    expect(getEnrichment(ctx).snapshotCaveat).toBeUndefined();
  });

  it('throws invalid_date_range when dateAddedFrom is later than dateAddedTo', async () => {
    await loadCatalog();
    const ctx = createMockContext({ errors: searchKevTool.errors });
    const input = searchKevTool.input.parse({
      dateAddedFrom: '2026-09-10',
      dateAddedTo: '2026-09-01',
    });
    await expect(searchKevTool.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_date_range' },
    });
  });

  it('throws invalid_date_range when dueAfter is later than dueBefore', async () => {
    await loadCatalog();
    const ctx = createMockContext({ errors: searchKevTool.errors });
    const input = searchKevTool.input.parse({ dueAfter: '2026-09-10', dueBefore: '2026-09-01' });
    await expect(searchKevTool.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_date_range' },
    });
  });

  it('throws catalog_unavailable when no snapshot is held and the fetch fails', async () => {
    const http = createFetchMock([
      {
        match: KEV_FEED_URL,
        respond: () => {
          throw new TypeError('network failure');
        },
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({});
      await expect(searchKevTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'catalog_unavailable' },
      });
    } finally {
      http.restore();
    }
  }, 20000);

  describe('zero-hit notice fragments', () => {
    it('vendorProject/product set: routes to kev_fields and nameContains', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ vendorProject: 'nonexistent-vendor' });
      await searchKevTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain('kev_fields');
    });

    it('cwe set: explains the 175-entry empty-cwes exclusion', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ cwe: 'CWE-9999' });
      await searchKevTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain('175 of 1,716 entries');
    });

    it('directive BOD 26-04 with a pre-2026 window: explains the era boundary', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({
        directive: 'BOD 26-04',
        dateAddedTo: '2020-01-01',
      });
      await searchKevTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain('BOD 26-04 entries begin in 2026');
    });

    it('overdue true with a future dueAfter: flags the contradiction', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ overdue: true, dueAfter: '2099-01-01' });
      await searchKevTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain('contradictory');
    });

    it('no filter explains it: falls back to the generic miss message', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ cveIdPrefix: 'CVE-2099' });
      await searchKevTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain('Relax the narrowest filter');
    });
  });

  describe('upstream records that do not fit the advertised shape', () => {
    it('still returns a page the output schema accepts', async () => {
      await loadCatalog([
        {
          cveID: 'CVE-2026-00009',
          vendorProject: 'Acme Corp',
          product: 'Malformed',
          vulnerabilityName: 'Malformed upstream record',
          dateAdded: '2026-09-02',
          shortDescription: 'Carries a CWE value outside the published pattern.',
          requiredAction: 'Apply updates per vendor instructions.',
          dueDate: '2026-09-23',
          knownRansomwareCampaignUse: 'Unknown',
          forensicTriage: 'No',
          notes: 'https://nvd.nist.gov/vuln/detail/CVE-2026-00009',
          cwes: ['CWE-20', 'Improper Input Validation'],
        },
        { cveID: 'CVE-2026-9', dateAdded: '2026-09-02', dueDate: '2026-09-23' },
      ]);

      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ vendorProject: 'acme' });
      const result = await searchKevTool.handler(input, ctx);

      expect(() => searchKevTool.output.parse(result)).not.toThrow();
      expect(result.results.map((entry) => entry.cveId)).not.toContain('CVE-2026-9');
    });

    it('rejects a nameContains value past the search-text ceiling', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ nameContains: 'widget '.repeat(200) });
      await expect(searchKevTool.handler(input, ctx)).rejects.toThrow(/characters/);
    });
  });
});
