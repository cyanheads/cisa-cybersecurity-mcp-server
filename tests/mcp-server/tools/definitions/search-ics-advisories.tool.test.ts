/**
 * @fileoverview Tests for `cisa_search_ics_advisories` — mirror_not_ready,
 * invalid_cvss_range, invalid_date_range, relevance_sort_without_query,
 * empty_search_text, catalog_unavailable, every zero-hit fragment, the
 * sector/CVSS coverage notices, the cwe filter and its stale-index disclosure,
 * and KEV membership (inKev, kevCves, the not-evaluated notice), against a
 * mirror seeded through the real ingest path and a KEV catalog loaded from the
 * fixture feed.
 * @module tests/mcp-server/tools/definitions/search-ics-advisories.tool.test
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import {
  createFetchMock,
  createMockContext,
  getEnrichment,
  runToolContract,
} from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { searchIcsAdvisoriesTool } from '@/mcp-server/tools/definitions/search-ics-advisories.tool.js';
import {
  getCsafMirror,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL } from '@/services/csaf-mirror/ingest.js';
import {
  getKevCatalog,
  initKevCatalog,
  KEV_FEED_URL,
  resetKevCatalog,
} from '@/services/kev-catalog/kev-catalog-service.js';
import {
  buildOversizedAdvisory,
  FULL_ADVISORY,
  REPUBLISHED_ADVISORY,
  SPARSE_ADVISORY,
  sparseAdvisoryAs,
} from '../../../fixtures/csaf-documents.js';
import { buildKevFeedBody, KEV_RECORDS } from '../../../fixtures/kev-feed.js';
import { buildTarGzResponse } from '../../../fixtures/tar.js';
import { emittedOutputSchema, strictClientValidator } from '../../../helpers/emitted-schema.js';
import { contentText, firstText } from '../../../helpers/format-text.js';

const BASE_ENTRIES = [
  {
    name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json',
    data: JSON.stringify(FULL_ADVISORY),
  },
  {
    name: 'CSAF-develop/csaf_files/OT/white/2014/icsa-14-035-01.json',
    data: JSON.stringify(SPARSE_ADVISORY),
  },
  {
    name: 'CSAF-develop/csaf_files/OT/white/2025/icsa-25-100-02.json',
    data: JSON.stringify(REPUBLISHED_ADVISORY),
  },
];

/* The oversized advisory covers CVE-2026-10000 … CVE-2026-10039; 10035 sorts past
 * the twenty-CVE preview every search result lists. */
const BIG_ENTRY = {
  name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-001-01.json',
  data: JSON.stringify(buildOversizedAdvisory('ICSA-26-001-01')),
};

async function seedMirror(entries = BASE_ENTRIES) {
  const http = createFetchMock([
    { match: CSAF_ARCHIVE_URL, respond: () => buildTarGzResponse(entries) },
  ]);
  http.install();
  try {
    await getCsafMirror().mirrorInstance.runSync({
      mode: 'init',
      signal: AbortSignal.timeout(30_000),
    });
  } finally {
    http.restore();
  }
}

/** A KEV fixture entry for a CVE the advisory fixtures cover. */
const kevEntry = (cveID: string) => ({ ...KEV_RECORDS[0], cveID });

/** Load the KEV snapshot from the fixture feed plus entries for advisory CVEs. */
async function loadKev(cveIds: string[] = ['CVE-2026-12345', 'CVE-2026-10035']) {
  const http = createFetchMock([
    {
      match: KEV_FEED_URL,
      respond: new Response(buildKevFeedBody(cveIds.map(kevEntry)), {
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

type Structured = {
  appliedFilters: Record<string, string>;
  notice?: string;
  results: Array<{ advisoryId: string; cves: string[]; kevCves?: string[] }>;
  totalCount: number;
};

describe('cisa_search_ics_advisories', () => {
  let dir: string;

  beforeEach(() => {
    resetCsafMirror();
    resetKevCatalog();
    dir = mkdtempSync(join(tmpdir(), 'search-ics-'));
    initCsafMirror({ mirrorPath: join(dir, 'csaf.sqlite3'), timeoutMs: 5000 });
    initKevCatalog({ refreshCron: '*/30 * * * *', timeoutMs: 5000 });
  });

  afterEach(() => {
    resetCsafMirror();
    resetKevCatalog();
    rmSync(dir, { recursive: true, force: true });
  });

  it('throws mirror_not_ready before the first sync completes', async () => {
    const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
    const input = searchIcsAdvisoriesTool.input.parse({});
    await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'mirror_not_ready' },
    });
  });

  describe('once seeded', () => {
    beforeEach(async () => {
      await seedMirror();
    }, 30000);

    it('full-text search finds the matching advisory and content[]/structuredContent match', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({
        q: 'Remote Code Execution',
        sortBy: 'relevance',
      });
      const result = await searchIcsAdvisoriesTool.handler(input, ctx);
      expect(result.results).toHaveLength(1);
      const text = firstText(searchIcsAdvisoriesTool.format?.(result));
      const advisory = result.results[0];
      expect(text).toContain(advisory?.advisoryId as string);
      expect(text).toContain(advisory?.title as string);
      expect(text).toContain(advisory?.attribution as string);
      expect(text).toContain(advisory?.url as string);
      expect(text).toContain(advisory?.csafUrl as string);
    });

    it('caps results at limit and discloses truncated/shown/cap', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ limit: 1, sortBy: 'revised' });
      const result = await searchIcsAdvisoriesTool.handler(input, ctx);
      expect(result.results).toHaveLength(1);
      expect(result.hasMore).toBe(true);
      const enrichment = getEnrichment(ctx);
      expect(enrichment.totalCount).toBe(3);
      expect(enrichment.truncated).toBe(true);
      expect(enrichment.shown).toBe(1);
      expect(enrichment.cap).toBe(1);
    });

    it('emits sectorCoverage when a sector filter is applied', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ sector: 'Energy' });
      await searchIcsAdvisoriesTool.handler(input, ctx);
      expect(getEnrichment(ctx).sectorCoverage).toContain('carry no sector note');
    });

    it('emits cvssCoverage when a score filter is applied', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ severity: 'CRITICAL' });
      await searchIcsAdvisoriesTool.handler(input, ctx);
      expect(getEnrichment(ctx).cvssCoverage).toContain('score only in CVSS v2');
    });

    it('throws invalid_cvss_range when cvssMin exceeds cvssMax', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ cvssMin: 9, cvssMax: 1 });
      await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'invalid_cvss_range' },
      });
    });

    it('throws invalid_date_range for publishedFrom after publishedTo', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({
        publishedFrom: '2026-09-10',
        publishedTo: '2026-01-01',
      });
      await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'invalid_date_range' },
      });
    });

    it('throws invalid_date_range for revisedFrom after revisedTo', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({
        revisedFrom: '2026-09-10',
        revisedTo: '2026-01-01',
      });
      await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'invalid_date_range' },
      });
    });

    it('throws relevance_sort_without_query when sortBy is relevance and q is absent', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ sortBy: 'relevance' });
      await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'relevance_sort_without_query' },
      });
    });

    it('a cursor walked past the end of the matches returns an empty page with hasMore: false', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const page1 = await searchIcsAdvisoriesTool.handler(
        searchIcsAdvisoriesTool.input.parse({ limit: 2, sortBy: 'revised' }),
        ctx,
      );
      expect(page1.hasMore).toBe(true);
      expect(page1.cursor).toBeDefined();

      const ctx2 = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const page2 = await searchIcsAdvisoriesTool.handler(
        searchIcsAdvisoriesTool.input.parse({ limit: 2, sortBy: 'revised', cursor: page1.cursor }),
        ctx2,
      );
      expect(page2.results).toHaveLength(1); /* 3 total, 2 shown on page 1, 1 remains */
      expect(page2.hasMore).toBe(false);
      expect(page2.cursor).toBeUndefined();
    });

    it('through the contract, both surfaces carry the same result fields and the filter echo', async () => {
      const result = await runToolContract(searchIcsAdvisoriesTool, {
        vendor: 'acme',
        limit: 1,
      });
      expect(result.isError).toBeFalsy();
      const structured = result.structuredContent as {
        appliedFilters: Record<string, string>;
        results: Array<Record<string, unknown>>;
        totalCount: number;
      };
      expect(structured.totalCount).toBe(1);
      expect(structured.appliedFilters).toEqual({
        vendor: 'acme',
        sortBy: 'revised',
        order: 'desc',
        limit: '1',
        offset: '0',
      });
      const advisory = structured.results[0] ?? {};
      expect(Object.keys(advisory).sort()).toEqual(
        [
          'advisoryId',
          'attribution',
          'csafUrl',
          'cveCount',
          'cves',
          'maxCvss',
          'productCount',
          'published',
          'publisherCategory',
          'revised',
          'revision',
          'sectors',
          'sectorsRaw',
          'series',
          'title',
          'url',
          'vendorCount',
          'vendors',
        ].sort(),
      );
      const text = contentText(result);
      expect(text).toContain('### ICSA-26-260-07 — Acme Widgets PLC Remote Code Execution');
      expect(text).toContain('**CVEs (1):** CVE-2026-12345');
      expect(text).toContain('**Applied filters:** vendor=acme');
    });

    it('rejects a limit above the 50-item schema cap', () => {
      expect(() => searchIcsAdvisoriesTool.input.parse({ limit: 51 })).toThrow();
    });

    it('rejects a malformed cve filter', () => {
      expect(() => searchIcsAdvisoriesTool.input.parse({ cve: 'not-a-cve' })).toThrow();
    });

    it('rejects a severity value outside the declared band enum', () => {
      expect(() => searchIcsAdvisoriesTool.input.parse({ severity: 'ULTRA' })).toThrow();
    });

    describe('cve and cwe case and whitespace', () => {
      const run = (args: Record<string, string>) =>
        runToolContract(
          searchIcsAdvisoriesTool,
          args as z.input<typeof searchIcsAdvisoriesTool.input>,
        );

      it.each([
        ['cve', 'CVE-2026-12345', ['ICSA-26-260-07']],
        ['cve', 'CVE-2014-0002', ['ICSA-14-035-01']],
        ['cwe', 'CWE-20', ['ICSA-26-260-07']],
      ])('%s %s in canonical form matches its advisories', async (key, value, expected) => {
        const structured = (await run({ [key]: value })).structuredContent as Structured;
        expect(structured.results.map((item) => item.advisoryId)).toEqual(expected);
        expect(structured.appliedFilters[key]).toBe(value);
      });

      it.each([
        ['cve', ' cve-2026-12345 ', 'CVE-2026-12345'],
        ['cve', 'Cve-2014-0002\t', 'CVE-2014-0002'],
        ['cwe', 'cwe-20\n', 'CWE-20'],
        ['cwe', ' Cwe-20 ', 'CWE-20'],
      ])(
        '%s %j returns what %s returns and echoes the canonical form on both surfaces',
        async (key, variant, canonical) => {
          const expected = (await run({ [key]: canonical })).structuredContent as Structured;
          const result = await run({ [key]: variant });
          expect(result.isError).toBeFalsy();
          const structured = result.structuredContent as Structured;
          expect(structured.totalCount).toBeGreaterThan(0);
          expect(structured.results).toEqual(expected.results);
          expect(structured.appliedFilters[key]).toBe(canonical);
          expect(contentText(result)).toContain(`${key}=${canonical}`);
        },
      );

      it.each([
        ['cve', 'CVE-26'],
        ['cve', 'cve_2026_12345'],
        ['cve', '  '],
        ['cwe', 'cwe_79'],
        ['cwe', 'CWE-'],
        ['cwe', '\t'],
      ])('%s %j still fails the pattern as InvalidParams', async (key, value) => {
        const result = await run({ [key]: value });
        expect(result.isError).toBe(true);
        const structured = result.structuredContent as { error: { code: number } };
        expect(structured.error.code).toBe(JsonRpcErrorCode.InvalidParams);
        expect(contentText(result)).toContain(key);
      });
    });

    describe('zero-hit notice fragments', () => {
      it('vendor set: notes vendor names are unnormalized', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ vendor: 'NoSuchVendorXYZ' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('not normalized');
      });

      it('sector set: notes the 2017 coverage boundary', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ sector: 'Dams' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('Sector coverage begins in 2017');
      });

      it('series ICSMA: notes the 188-of-3,926 scope', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ series: 'ICSMA' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('ICSMA covers medical devices');
      });

      it('cve set: routes to cisa_check_cve_status', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ cve: 'CVE-2099-00001' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('cisa_check_cve_status');
      });

      it('no filter explains it: falls back to the generic miss message', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ q: 'nonexistentquerytoken' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('Relax the narrowest filter');
      });

      it('cwe set: explains exact CWE matching and routes to cisa_search_kev', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ cwe: 'CWE-99999' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        const notice = getEnrichment(ctx).notice as string;
        expect(notice).toContain('No ICS advisory lists that CWE');
        expect(notice).toContain('cisa_search_kev');
        expect(notice).not.toContain('may be incomplete');
      });

      it('inKev true: explains how sharply inKev narrows', async () => {
        await loadKev([]);
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ inKev: true });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('drop inKev');
      });
    });

    describe('q with no searchable token', () => {
      it.each([
        ['whitespace', '   '],
        ['bare quotes', '""'],
        ['punctuation', '-- !!'],
      ])(
        '%s fails as empty_search_text with its recovery hint on both surfaces',
        async (_label, q) => {
          const result = await runToolContract(searchIcsAdvisoriesTool, { q, limit: 1 });
          expect(result.isError).toBe(true);
          const text = contentText(result);
          expect(text).toContain('q contains no searchable word');
          expect(text).toContain('Put at least one word or number in q');
          expect(JSON.stringify(result.structuredContent)).toContain('empty_search_text');
        },
      );

      it('also fails under sortBy relevance instead of ranking the whole corpus', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ q: '""', sortBy: 'relevance' });
        await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
          data: { reason: 'empty_search_text' },
        });
      });
    });

    describe('cwe filter', () => {
      it('matches exact CWE membership and echoes cwe in appliedFilters on both surfaces', async () => {
        const result = await runToolContract(searchIcsAdvisoriesTool, { cwe: 'CWE-20' });
        const structured = result.structuredContent as Structured;
        expect(structured.results.map((item) => item.advisoryId)).toEqual(['ICSA-26-260-07']);
        expect(structured.appliedFilters.cwe).toBe('CWE-20');
        expect(structured.notice ?? '').not.toContain('may be incomplete');
        expect(contentText(result)).toContain('cwe=CWE-20');
      });

      it('AND-combines with the other filters', async () => {
        const hit = await runToolContract(searchIcsAdvisoriesTool, {
          cwe: 'CWE-20',
          severity: 'CRITICAL',
        });
        expect((hit.structuredContent as Structured).totalCount).toBe(1);
        const miss = await runToolContract(searchIcsAdvisoriesTool, {
          cwe: 'CWE-20',
          publisher: 'other',
        });
        expect((miss.structuredContent as Structured).totalCount).toBe(0);
      });

      it('rejects a malformed cwe at the schema', () => {
        expect(() => searchIcsAdvisoriesTool.input.parse({ cwe: '787' })).toThrow();
      });

      describe('on an index an older ingest built', () => {
        beforeEach(async () => {
          const handle = await getCsafMirror().mirrorInstance.raw();
          handle.exec("DELETE FROM mirror_meta WHERE key = 'ingest_content_version'");
        });

        it('a zero-hit cwe search is disclosed as possibly incomplete, not answered confidently', async () => {
          const handle = await getCsafMirror().mirrorInstance.raw();
          handle.exec('DELETE FROM advisory_cwes');
          const result = await runToolContract(searchIcsAdvisoriesTool, { cwe: 'CWE-20' });
          const structured = result.structuredContent as Structured;
          expect(structured.totalCount).toBe(0);
          expect(structured.notice).toContain('may be incomplete');
          expect(structured.notice).not.toContain('No ICS advisory lists that CWE');
          expect(structured.notice).not.toContain('No advisory matches');
          expect(contentText(result)).toContain('may be incomplete');
        });

        it('a cwe search with hits carries the same disclosure', async () => {
          const result = await runToolContract(searchIcsAdvisoriesTool, { cwe: 'CWE-20' });
          const structured = result.structuredContent as Structured;
          expect(structured.totalCount).toBe(1);
          expect(structured.notice).toContain('may be incomplete');
        });

        it('a search without cwe carries no disclosure', async () => {
          const result = await runToolContract(searchIcsAdvisoriesTool, { vendor: 'acme' });
          expect((result.structuredContent as Structured).notice ?? '').not.toContain(
            'may be incomplete',
          );
        });
      });
    });
  });

  describe('advisory IDs carrying a revision suffix', () => {
    beforeEach(async () => {
      await seedMirror([
        ...BASE_ENTRIES,
        {
          name: 'CSAF-develop/csaf_files/OT/white/2010/icsa-10-316-01a.json',
          data: JSON.stringify(sparseAdvisoryAs('ICSA-10-316-01A', '2010-11-12T00:00:00.000000Z')),
        },
        {
          name: 'CSAF-develop/csaf_files/OT/white/2010/icsa-10-301-01.json',
          data: JSON.stringify(sparseAdvisoryAs('ICSA-10-301-01', '2010-10-28T00:00:00.000000Z')),
        },
        {
          name: 'CSAF-develop/csaf_files/OT/white/2016/icsa-16-231-01-0.json',
          data: JSON.stringify(sparseAdvisoryAs('ICSA-16-231-01-0', '2016-08-18T00:00:00.000000Z')),
        },
      ]);
    }, 30000);

    it('a page holding an uppercase-suffix ID validates against the emitted, flag-free output schema', async () => {
      const result = await runToolContract(searchIcsAdvisoriesTool, {
        publishedTo: '2016-12-31',
        sortBy: 'published',
        order: 'asc',
        limit: 5,
      });
      const structured = result.structuredContent as Structured;
      expect(structured.results.map((item) => item.advisoryId)).toEqual([
        'ICSA-10-301-01',
        'ICSA-10-316-01A',
        'ICSA-14-035-01',
        'ICSA-16-231-01-0',
      ]);
      const verdict = strictClientValidator(searchIcsAdvisoriesTool).safeParse(structured);
      expect(verdict.error?.issues ?? []).toEqual([]);
    });

    it('advertises the advisoryId pattern in its canonical uppercase form', () => {
      const emitted = JSON.stringify(emittedOutputSchema(searchIcsAdvisoriesTool));
      expect(emitted).toContain(
        '"pattern":"^ICS(A|MA)-\\\\d{2}-\\\\d{3}-\\\\d{2}(?:[A-Z]|-\\\\d+)?$"',
      );
    });
  });

  describe('KEV membership', () => {
    beforeEach(async () => {
      await seedMirror([...BASE_ENTRIES, BIG_ENTRY]);
    }, 30000);

    describe('with the KEV snapshot loaded', () => {
      beforeEach(async () => {
        await loadKev();
      });

      it('inKev: true returns only KEV-covering advisories, with kevCves and the catalog version on both surfaces', async () => {
        const result = await runToolContract(searchIcsAdvisoriesTool, { inKev: true });
        expect(result.isError).toBeFalsy();
        const structured = result.structuredContent as Structured;
        expect(structured.totalCount).toBe(2);
        expect(structured.results.map((item) => [item.advisoryId, item.kevCves])).toEqual([
          ['ICSA-26-260-07', ['CVE-2026-12345']],
          ['ICSA-26-001-01', ['CVE-2026-10035']],
        ]);
        expect(structured.appliedFilters).toMatchObject({
          inKev: 'true',
          kevCatalogVersion: '2026.09.18',
        });
        const text = contentText(result);
        expect(text).toContain('**In KEV (1):** CVE-2026-12345');
        expect(text).toContain('**In KEV (1):** CVE-2026-10035');
        expect(text).toContain('kevCatalogVersion=2026.09.18');
      });

      it('kevCves reports a KEV CVE that sorts past the twenty-CVE preview', async () => {
        const result = await runToolContract(searchIcsAdvisoriesTool, { vendor: 'BigVendor' });
        const [big] = (result.structuredContent as Structured).results;
        expect(big?.cves).toHaveLength(20);
        expect(big?.cves).not.toContain('CVE-2026-10035');
        expect(big?.kevCves).toEqual(['CVE-2026-10035']);
        expect(contentText(result)).toContain('**In KEV (1):** CVE-2026-10035');
      });

      it('inKev: false returns the advisories covering no KEV CVE, each with an empty kevCves', async () => {
        const result = await runToolContract(searchIcsAdvisoriesTool, { inKev: false });
        const structured = result.structuredContent as Structured;
        expect(structured.results.map((item) => [item.advisoryId, item.kevCves])).toEqual([
          ['ICSA-25-100-02', []],
          ['ICSA-14-035-01', []],
        ]);
        expect(contentText(result)).toContain('**In KEV (0):** none of its CVEs');
      });

      it('a search without inKev still carries kevCves, no KEV notice, and no catalog version echo', async () => {
        const result = await runToolContract(searchIcsAdvisoriesTool, {});
        const structured = result.structuredContent as Structured;
        expect(structured.totalCount).toBe(4);
        for (const item of structured.results) expect(item.kevCves).toBeDefined();
        expect(structured.notice).toBeUndefined();
        expect(structured.appliedFilters).not.toHaveProperty('kevCatalogVersion');
      });

      it('inKev pages through the cursor with a stable total', async () => {
        const first = await runToolContract(searchIcsAdvisoriesTool, { inKev: true, limit: 1 });
        const page1 = first.structuredContent as Structured & { cursor?: string };
        expect(page1.totalCount).toBe(2);
        expect(page1.cursor).toBeDefined();
        const second = await runToolContract(searchIcsAdvisoriesTool, {
          inKev: true,
          limit: 1,
          cursor: page1.cursor,
        });
        const page2 = second.structuredContent as Structured & { hasMore: boolean };
        expect(page2.totalCount).toBe(2);
        expect(page2.hasMore).toBe(false);
        expect([...page1.results, ...page2.results].map((item) => item.advisoryId)).toEqual([
          'ICSA-26-260-07',
          'ICSA-26-001-01',
        ]);
      });
    });

    describe('with no KEV snapshot held', () => {
      it('a search without inKev succeeds, omits kevCves, says so, and makes no KEV request', async () => {
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
          const result = await runToolContract(searchIcsAdvisoriesTool, { vendor: 'acme' });
          expect(result.isError).toBeFalsy();
          const structured = result.structuredContent as Structured;
          expect(structured.results).toHaveLength(1);
          expect(structured.results[0]).not.toHaveProperty('kevCves');
          expect(structured.notice).toContain('KEV membership was not evaluated');
          const text = contentText(result);
          expect(text).not.toContain('**In KEV');
          expect(text).toContain('KEV membership was not evaluated');
          expect(http.calls).toHaveLength(0);
        } finally {
          http.restore();
        }
      });

      it('a capped page keeps both the cap notice and the KEV notice', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ limit: 1 });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        const enrichment = getEnrichment(ctx);
        expect(enrichment.truncated).toBe(true);
        expect(enrichment.notice).toContain('Results capped at 1; showing 1.');
        expect(enrichment.notice).toContain('KEV membership was not evaluated');
      });

      it('a zero-hit search reports only the zero-hit notice', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ vendor: 'NoSuchVendorXYZ' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        const notice = getEnrichment(ctx).notice as string;
        expect(notice).toContain('not normalized');
        expect(notice).not.toContain('KEV membership');
      });

      it('inKev with the KEV fetch failing throws the retryable catalog_unavailable', async () => {
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
          const result = await runToolContract(searchIcsAdvisoriesTool, { inKev: true });
          expect(result.isError).toBe(true);
          const text = contentText(result);
          expect(text).toContain('drop inKev to search without it');
          expect(JSON.stringify(result.structuredContent)).toContain('catalog_unavailable');
        } finally {
          http.restore();
        }
      }, 20000);
    });
  });
});
