/**
 * @fileoverview Tests for `cisa_search_kev` — filters, pagination, sort,
 * invalid_date_range, and every zero-hit notice fragment.
 * @module tests/mcp-server/tools/definitions/search-kev.tool.test
 */

import { z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import {
  createFetchMock,
  createMockContext,
  getEnrichment,
  runToolContract,
} from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { searchKevTool } from '@/mcp-server/tools/definitions/search-kev.tool.js';
import {
  getKevCatalog,
  initKevCatalog,
  KEV_FEED_URL,
  resetKevCatalog,
} from '@/services/kev-catalog/kev-catalog-service.js';
import { buildKevFeedBody } from '../../../fixtures/kev-feed.js';
import { DRIFTING_CATALOG_COUNT } from '../../../helpers/catalog-counts.js';
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

    it('cwe matching nothing: explains the empty-cwes exclusion with figures from the loaded snapshot', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ cwe: 'CWE-9999' });
      await searchKevTool.handler(input, ctx);
      /* The fixture catalog holds five entries, one of them with an empty cwes array. */
      expect(getEnrichment(ctx).notice).toContain(
        'No KEV entry carries CWE-9999. 1 of 5 entries carry an empty cwes array',
      );
    });

    it('cwe matching on its own is not blamed when another filter narrows to zero', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ cwe: 'CWE-20', cveIdPrefix: 'CVE-2099' });
      await searchKevTool.handler(input, ctx);
      const notice = getEnrichment(ctx).notice as string;
      expect(notice).toContain('cveIdPrefix=CVE-2099 matches no entry on its own');
      expect(notice).not.toContain('No KEV entry carries');
    });

    it('vendorProject matching on its own is not blamed; the filters whose removal restores results are named with counts', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      /* Acme alone: 2. Gadget alone: 1. Forensic triage alone: 1. Together: 0. */
      const input = searchKevTool.input.parse({
        vendorProject: 'Acme',
        product: 'Gadget',
        forensicTriage: true,
      });
      await searchKevTool.handler(input, ctx);
      const notice = getEnrichment(ctx).notice as string;
      expect(notice).not.toContain('free-text labels');
      expect(notice).toContain('dropping product restores 1 entry');
      expect(notice).toContain('dropping forensicTriage restores 1 entry');
      expect(notice).not.toContain('dropping vendorProject');
    });

    it('overdue narrowing a vendor to zero is named as the filter to drop', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ vendorProject: 'OldVendor', overdue: false });
      await searchKevTool.handler(input, ctx);
      const notice = getEnrichment(ctx).notice as string;
      expect(notice).toContain('dropping overdue restores 1 entry');
      expect(notice).not.toContain('free-text labels');
    });

    it('says no single filter explains the miss when no one removal restores a result', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      /* Each matches alone; every pair is still disjoint. */
      const input = searchKevTool.input.parse({
        vendorProject: 'OldVendor',
        cveIdPrefix: 'CVE-2026',
        directive: 'none',
      });
      await searchKevTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain('no single filter explains the miss');
    });

    it('directive BOD 26-04 with an earlier window: names the earliest BOD 26-04 addition in the snapshot', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({
        directive: 'BOD 26-04',
        dateAddedTo: '2020-01-01',
      });
      await searchKevTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain(
        'Entries citing BOD 26-04 were added from 2026-01-01 through 2026-09-05',
      );
    });

    it('directive window fragment follows the snapshot, not a fixed 2026 threshold', async () => {
      await loadCatalog([
        {
          cveID: 'CVE-2025-00006',
          vendorProject: 'Early Adopter',
          product: 'Preview',
          vulnerabilityName: 'Preview Build Flaw',
          dateAdded: '2025-12-15',
          shortDescription: 'Preview contains a flaw.',
          requiredAction: 'Apply mitigations per BOD 26-04.',
          dueDate: '2025-12-18',
          knownRansomwareCampaignUse: 'Unknown',
          forensicTriage: 'No',
          notes: 'https://nvd.nist.gov/vuln/detail/CVE-2025-00006',
          cwes: ['CWE-20'],
        },
      ]);
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({
        directive: 'BOD 26-04',
        dateAddedTo: '2025-12-01',
      });
      await searchKevTool.handler(input, ctx);
      const notice = getEnrichment(ctx).notice as string;
      expect(notice).toContain('added from 2025-12-15');
      expect(notice).not.toContain('begin in 2026');
    });

    it('overdue true with a dueAfter on or after asOf: flags the contradiction against the echoed asOf', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      /* asOf is 2026-09-10 (injected clock); the wall clock is later. CVE-2026-00002 is due 2026-09-19. */
      const input = searchKevTool.input.parse({ overdue: true, dueAfter: '2026-09-15' });
      await searchKevTool.handler(input, ctx);
      const enrichment = getEnrichment(ctx);
      expect(enrichment.asOf).toBe('2026-09-10');
      expect(enrichment.notice).toContain('contradictory');
      expect(enrichment.notice).toContain('2026-09-10');
    });

    it('overdue true with a far-future dueAfter: names dueAfter and flags the contradiction', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ overdue: true, dueAfter: '2099-01-01' });
      await searchKevTool.handler(input, ctx);
      const notice = getEnrichment(ctx).notice as string;
      expect(notice).toContain('contradictory');
      expect(notice).toContain('dueAfter=2099-01-01 matches no entry on its own');
    });

    it('a single filter that matches nothing is named', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ cveIdPrefix: 'CVE-2099' });
      await searchKevTool.handler(input, ctx);
      expect(getEnrichment(ctx).notice).toContain(
        'cveIdPrefix=CVE-2099 matches no entry on its own',
      );
    });

    it('beside other filters, says how many entries dropping the filter that matches nothing restores', async () => {
      await loadCatalog();
      /* cwe CWE-20 alone matches CVE-2026-00001 and CVE-2026-00005. */
      const result = await runToolContract(searchKevTool, {
        cwe: 'CWE-20',
        cveIdPrefix: 'CVE-2099',
      });
      const notice = (result.structuredContent as { notice: string }).notice;
      expect(notice).toContain(
        'cveIdPrefix=CVE-2099 matches no entry on its own — relax or drop it. Dropping cveIdPrefix restores 2 entries.',
      );
      expect(contentText(result)).toContain(notice);
    });

    it('says dropping the filter that matches nothing restores nothing when the other filters also miss together', async () => {
      await loadCatalog();
      /* OldVendor alone: 1, Gadget alone: 1, together: 0 — dropping cveIdPrefix restores nothing. */
      const result = await runToolContract(searchKevTool, {
        cveIdPrefix: 'CVE-2099',
        vendorProject: 'OldVendor',
        product: 'Gadget',
      });
      const notice = (result.structuredContent as { notice: string }).notice;
      expect(notice).toContain(
        'Dropping cveIdPrefix alone restores nothing: the other filters match no entry together either.',
      );
      expect(contentText(result)).toContain(notice);
    });

    it('names two unmatched label filters in the plural', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ vendorProject: 'zzzz', product: 'qqqq' });
      await searchKevTool.handler(input, ctx);
      const notice = getEnrichment(ctx).notice as string;
      expect(notice).toContain(
        'vendorProject=zzzz and product=qqqq each match no entry on their own.',
      );
      expect(notice).toContain('or drop the filters and match on nameContains instead.');
      expect(notice).not.toContain('Dropping');
    });

    it('computes the per-filter counts only on a zero-hit result', async () => {
      await loadCatalog();
      const spy = vi.spyOn(getKevCatalog(), 'filterCounts');
      await searchKevTool.handler(
        searchKevTool.input.parse({ vendorProject: 'acme' }),
        createMockContext({ errors: searchKevTool.errors }),
      );
      expect(spy).not.toHaveBeenCalled();
      await searchKevTool.handler(
        searchKevTool.input.parse({ vendorProject: 'acme', cveIdPrefix: 'CVE-2019' }),
        createMockContext({ errors: searchKevTool.errors }),
      );
      expect(spy).toHaveBeenCalledTimes(1);
    });

    it('reaches both surfaces through the assembled result', async () => {
      await loadCatalog();
      const result = await runToolContract(searchKevTool, {
        cwe: 'CWE-20',
        cveIdPrefix: 'CVE-2099',
      });
      const structured = result.structuredContent as { totalCount: number; notice: string };
      expect(structured.totalCount).toBe(0);
      expect(structured.notice).toContain('cveIdPrefix=CVE-2099 matches no entry on its own');
      expect(contentText(result)).toContain(structured.notice);
    });
  });

  describe('non-empty results', () => {
    it('carry no zero-hit notice, and the truncation notice is unchanged', async () => {
      await loadCatalog();
      const whole = await runToolContract(searchKevTool, { vendorProject: 'acme' });
      expect((whole.structuredContent as { notice?: string }).notice).toBeUndefined();

      const paged = await runToolContract(searchKevTool, { vendorProject: 'acme', limit: 1 });
      expect((paged.structuredContent as { notice?: string }).notice).toMatchInlineSnapshot(
        `"Results capped at 1; showing 1. Raise the cap or narrow with filters."`,
      );
    });
  });

  describe('cwe and cveIdPrefix case and whitespace', () => {
    type Structured = { appliedFilters: Record<string, string>; results: Array<{ cveId: string }> };
    const run = (args: Record<string, string>) =>
      runToolContract(searchKevTool, args as z.input<typeof searchKevTool.input>);

    it.each([
      ['cwe', 'CWE-79', ['CVE-2019-00004']],
      ['cwe', 'CWE-20', ['CVE-2026-00001', 'CVE-2026-00005']],
      ['cveIdPrefix', 'CVE-2026', ['CVE-2026-00002', 'CVE-2026-00001', 'CVE-2026-00005']],
    ])('%s %s in canonical form matches its entries', async (key, value, expected) => {
      await loadCatalog();
      const result = await run({ [key]: value });
      const structured = result.structuredContent as Structured;
      expect(structured.results.map((record) => record.cveId)).toEqual(expected);
      expect(structured.appliedFilters[key]).toBe(value);
    });

    it.each([
      ['cwe', ' cwe-79 ', 'CWE-79'],
      ['cwe', 'cwe-20\n', 'CWE-20'],
      ['cveIdPrefix', 'cve-2026\t', 'CVE-2026'],
      ['cveIdPrefix', ' Cve-2019 ', 'CVE-2019'],
    ])(
      '%s %j returns what %s returns and echoes the canonical form on both surfaces',
      async (key, variant, canonical) => {
        await loadCatalog();
        const expected = (await run({ [key]: canonical })).structuredContent as Structured;
        const result = await run({ [key]: variant });
        expect(result.isError).toBeFalsy();
        const structured = result.structuredContent as Structured;
        expect(structured.results.length).toBeGreaterThan(0);
        expect(structured.results).toEqual(expected.results);
        expect(structured.appliedFilters[key]).toBe(canonical);
        expect(contentText(result)).toContain(`${key}=${canonical}`);
      },
    );

    it.each([
      ['cwe', 'cwe_79'],
      ['cwe', '79'],
      ['cwe', '   '],
      ['cveIdPrefix', 'CVE-26'],
      ['cveIdPrefix', 'cve-2026-1'],
      ['cveIdPrefix', ' '],
    ])('%s %j still fails the pattern as InvalidParams', async (key, value) => {
      await loadCatalog();
      const result = await run({ [key]: value });
      expect(result.isError).toBe(true);
      const structured = result.structuredContent as { error: { code: number } };
      expect(structured.error.code).toBe(JsonRpcErrorCode.InvalidParams);
      expect(contentText(result)).toContain(key);
    });
  });

  describe('nameContains with a word it cannot match', () => {
    type Structured = {
      cap?: number;
      hasMore: boolean;
      notice?: string;
      results: Array<{ cveId: string }>;
      shown?: number;
      totalCount: number;
      truncated?: boolean;
    };
    const run = (args: z.input<typeof searchKevTool.input>) => runToolContract(searchKevTool, args);
    const DROPPED = (words: string, searched: string) =>
      `nameContains dropped the characters of ${words} outside the letters a-z and the digits 0-9 — matching folds case and accents and keeps only those, so the dropped characters can never match. Searched for: ${searched}.`;

    it('names a Latin letter with no a-z fold (ß) without calling it outside the Latin alphabet', async () => {
      await loadCatalog();
      const structured = (await run({ nameContains: 'Straße widget' }))
        .structuredContent as Structured;
      expect(structured.notice).toContain(DROPPED('"Straße"', 'stra e widget'));
      expect(structured.notice).not.toContain('Latin');
    });

    it('searches the surviving token, returns what that token alone returns, and names what was dropped and searched on both surfaces', async () => {
      await loadCatalog();
      const plain = (await run({ nameContains: 'widget' })).structuredContent as Structured;
      const result = await run({ nameContains: '漏洞 widget' });
      const structured = result.structuredContent as Structured;
      expect(structured.results).toEqual(plain.results);
      expect(structured.results.map((record) => record.cveId)).toEqual(['CVE-2026-00001']);
      expect(structured.totalCount).toBe(1);
      expect(structured.notice).toBe(DROPPED('"漏洞"', 'widget'));
      expect(contentText(result)).toContain(DROPPED('"漏洞"', 'widget'));
    });

    it('names every dropped word, including one only partly outside the Latin alphabet', async () => {
      await loadCatalog();
      const structured = (await run({ nameContains: 'ΑΘΗΝΑ acme ١٢٣' }))
        .structuredContent as Structured;
      expect(structured.totalCount).toBe(2);
      expect(structured.notice).toBe(DROPPED('"ΑΘΗΝΑ", "١٢٣"', 'acme'));
    });

    it.each([
      ['Latin only', 'widget pro'],
      ['accented Latin, which folds', 'Wídget Pró'],
      ['punctuation, which is not a letter or digit', 'widget -- pro!'],
    ])('%s raises no notice', async (_label, nameContains) => {
      await loadCatalog();
      const structured = (await run({ nameContains })).structuredContent as Structured;
      expect(structured.results.map((record) => record.cveId)).toEqual(['CVE-2026-00001']);
      expect(structured.notice).toBeUndefined();
    });

    it('on a zero-hit search, keeps the zero-hit explanation beside the dropped-word notice', async () => {
      await loadCatalog();
      const result = await run({ nameContains: '漏洞 nonexistentword' });
      const structured = result.structuredContent as Structured;
      expect(structured.totalCount).toBe(0);
      expect(structured.notice).toContain(DROPPED('"漏洞"', 'nonexistentword'));
      expect(structured.notice).toContain(
        'nameContains=漏洞 nonexistentword matches no entry on its own',
      );
      expect(contentText(result)).toContain(structured.notice as string);
    });

    it('on a capped page, keeps the truncation disclosure beside the dropped-word notice', async () => {
      await loadCatalog();
      /* "remote" names two fixture entries; the cap is one. */
      const result = await run({ nameContains: 'remote 漏洞', limit: 1 });
      const structured = result.structuredContent as Structured;
      expect(structured).toMatchObject({ truncated: true, shown: 1, cap: 1, totalCount: 2 });
      expect(structured.notice).toBe(
        `Results capped at 1; showing 1. Raise the cap or narrow with filters. ${DROPPED('"漏洞"', 'remote')}`,
      );
      expect(contentText(result)).toContain(structured.notice as string);
    });

    it('on the last page past the cap, still names what was dropped', async () => {
      await loadCatalog();
      const first = (await run({ nameContains: 'remote 漏洞', limit: 1 }))
        .structuredContent as Structured & { cursor?: string };
      const last = (await run({ nameContains: 'remote 漏洞', limit: 1, cursor: first.cursor }))
        .structuredContent as Structured;
      expect(last.hasMore).toBe(false);
      expect(last.truncated).toBeUndefined();
      expect(last.results).toHaveLength(1);
      expect(last.notice).toBe(DROPPED('"漏洞"', 'remote'));
    });
  });

  describe('nameContains with no searchable token', () => {
    it.each([
      ['punctuation', '--'],
      ['whitespace', '  '],
      ['dashes', '——'],
      ['symbols', '$$'],
      ['CJK', '漏洞'],
    ])(
      '%s fails as empty_search_text with its recovery hint on both surfaces',
      async (_label, nameContains) => {
        await loadCatalog();
        const result = await runToolContract(searchKevTool, { nameContains });
        expect(result.isError).toBe(true);
        const text = contentText(result);
        expect(text).toContain('nameContains holds no searchable token');
        expect(text).toContain(
          'Put at least one word or number in nameContains that uses the letters a-z, accented or not, or the digits 0-9',
        );
        expect(text).not.toContain('Latin');
        const structured = result.structuredContent as {
          error: { code: number; data: { reason: string } };
        };
        expect(structured.error.code).toBe(JsonRpcErrorCode.ValidationError);
        expect(structured.error.data.reason).toBe('empty_search_text');
      },
    );

    it('checks the length ceiling first', async () => {
      await loadCatalog();
      const ctx = createMockContext({ errors: searchKevTool.errors });
      const input = searchKevTool.input.parse({ nameContains: '-'.repeat(600) });
      await expect(searchKevTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'search_text_too_long' },
      });
    });

    it.each([
      ['a number', '44228', 'CVE-2021-44228'],
      ['an accented word', 'Café', 'CVE-2024-00008'],
      ['a word followed by punctuation', 'siemens --', 'CVE-2024-00007'],
    ])('%s still searches', async (_label, nameContains, expected) => {
      await loadCatalog([
        {
          cveID: 'CVE-2021-44228',
          vendorProject: 'Apache',
          product: 'Log4j2',
          vulnerabilityName: 'Apache Log4j2 Remote Code Execution',
          dateAdded: '2021-12-10',
          shortDescription: 'Log4j2 JNDI features (CVE-2021-44228) allow remote code execution.',
          requiredAction: 'Apply updates per vendor instructions.',
          dueDate: '2021-12-24',
          knownRansomwareCampaignUse: 'Known',
          forensicTriage: 'No',
          notes: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
          cwes: ['CWE-20'],
        },
        {
          cveID: 'CVE-2024-00007',
          vendorProject: 'Siemens',
          product: 'SIMATIC',
          vulnerabilityName: 'Siemens SIMATIC Improper Authentication',
          dateAdded: '2024-03-01',
          shortDescription: 'SIMATIC contains an improper authentication vulnerability.',
          requiredAction: 'Apply updates per vendor instructions.',
          dueDate: '2024-03-22',
          knownRansomwareCampaignUse: 'Unknown',
          forensicTriage: 'No',
          notes: 'https://nvd.nist.gov/vuln/detail/CVE-2024-00007',
          cwes: ['CWE-287'],
        },
        {
          cveID: 'CVE-2024-00008',
          vendorProject: 'Cafe Systems',
          product: 'Menu Board',
          vulnerabilityName: 'Cafe Menu Board Path Traversal',
          dateAdded: '2024-04-01',
          shortDescription: 'Cafe Menu Board contains a path traversal vulnerability.',
          requiredAction: 'Apply updates per vendor instructions.',
          dueDate: '2024-04-22',
          knownRansomwareCampaignUse: 'Unknown',
          forensicTriage: 'No',
          notes: 'https://nvd.nist.gov/vuln/detail/CVE-2024-00008',
          cwes: ['CWE-22'],
        },
      ]);
      const result = await runToolContract(searchKevTool, { nameContains });
      expect(result.isError).toBeFalsy();
      const structured = result.structuredContent as { results: Array<{ cveId: string }> };
      expect(structured.results.map((record) => record.cveId)).toEqual([expected]);
    });
  });

  it('states no KEV catalog count that drifts with each release', () => {
    const definition = JSON.stringify({
      description: searchKevTool.description,
      input: z.toJSONSchema(searchKevTool.input),
    });
    expect(definition).toContain('forensic-triage tier');
    expect(definition).not.toMatch(DRIFTING_CATALOG_COUNT);
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
