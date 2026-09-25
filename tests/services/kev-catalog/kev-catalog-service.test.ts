/**
 * @fileoverview Tests for the KEV catalog service — loading, the injected
 * clock, conditional refresh (304 leaving the snapshot intact), HTML-body
 * classification as ServiceUnavailable (never SerializationError), the
 * catalog_unavailable failure when no snapshot is held, and search filtering.
 * @module tests/services/kev-catalog/kev-catalog-service.test
 */

import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  getKevCatalog,
  initKevCatalog,
  KEV_FEED_URL,
  queryTokens,
  resetKevCatalog,
} from '@/services/kev-catalog/kev-catalog-service.js';
import type { KevSnapshot } from '@/services/kev-catalog/types.js';
import { buildKevFeedBody } from '../../fixtures/kev-feed.js';

const FIXED_NOW = () => new Date('2026-09-10T00:00:00Z');

describe('KevCatalogService', () => {
  beforeEach(() => {
    resetKevCatalog();
    initKevCatalog({ refreshCron: '*/30 * * * *', timeoutMs: 5000, now: FIXED_NOW });
  });

  afterEach(() => {
    resetKevCatalog();
  });

  it('asOf() reads the injected clock, not the real one', () => {
    expect(getKevCatalog().asOf()).toBe('2026-09-10');
  });

  it('loads the snapshot on first call and indexes every record', async () => {
    const http = createFetchMock([
      {
        match: KEV_FEED_URL,
        respond: new Response(buildKevFeedBody(), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'last-modified': 'Fri, 18 Sep 2026 00:00:00 GMT',
          },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      const snapshot = await getKevCatalog().snapshot(ctx);
      expect(snapshot.count).toBe(5);
      expect(snapshot.catalogVersion).toBe('2026.09.18');
      expect(snapshot.byId.get('CVE-2026-00001')).toBeDefined();
      expect(http.calls).toHaveLength(1);

      /* A second call reuses the cached snapshot — no second fetch. */
      await getKevCatalog().snapshot(ctx);
      expect(http.calls).toHaveLength(1);
    } finally {
      http.restore();
    }
  });

  it('concurrent callers share one in-flight load rather than racing a second fetch', async () => {
    let fetchCount = 0;
    const http = createFetchMock([
      {
        match: KEV_FEED_URL,
        respond: () => {
          fetchCount += 1;
          return new Response(buildKevFeedBody(), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        },
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      const catalog = getKevCatalog();
      const [a, b] = await Promise.all([catalog.snapshot(ctx), catalog.snapshot(ctx)]);
      expect(a).toBe(b);
      expect(fetchCount).toBe(1);
    } finally {
      http.restore();
    }
  });

  it('a 304 response leaves the snapshot in place and only advances lastCheckedAt', async () => {
    const ctx = createMockContext();
    const catalog = getKevCatalog();

    const httpFirst = createFetchMock([
      {
        match: KEV_FEED_URL,
        respond: new Response(buildKevFeedBody(), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'last-modified': 'Fri, 18 Sep 2026 00:00:00 GMT',
          },
        }),
      },
    ]);
    httpFirst.install();
    let snapshotBefore: KevSnapshot | undefined;
    try {
      snapshotBefore = await catalog.snapshot(ctx);
    } finally {
      httpFirst.restore();
    }

    const httpSecond = createFetchMock([
      { match: KEV_FEED_URL, respond: new Response(null, { status: 304 }) },
    ]);
    httpSecond.install();
    try {
      await catalog.refresh(ctx);
    } finally {
      httpSecond.restore();
    }

    const state = catalog.state();
    expect(state.count).toBe(5);
    expect(state.catalogVersion).toBe('2026.09.18');
    expect(state.lastCheckedAt).not.toBeNull();
    /* Same snapshot object — the 304 branch never rebuilt it. */
    expect(catalog.currentSnapshot()).toBe(snapshotBefore);
  });

  it('classifies an HTML error body as ServiceUnavailable, never SerializationError', async () => {
    const html = `<!doctype html><html><body>${'x'.repeat(500)}</body></html>`;
    const http = createFetchMock([
      {
        match: KEV_FEED_URL,
        respond: new Response(html, { status: 200, headers: { 'content-type': 'text/html' } }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      const error = await getKevCatalog()
        .snapshot(ctx)
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(McpError);
      const mcpError = error as McpError;
      expect(mcpError.code).not.toBe('SerializationError');
      expect(mcpError.data).toMatchObject({ reason: 'catalog_unavailable' });
    } finally {
      http.restore();
    }
  }, 20000);

  it('throws the retryable catalog_unavailable failure when no snapshot is held and the fetch fails', async () => {
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
      const ctx = createMockContext();
      await expect(getKevCatalog().snapshot(ctx)).rejects.toMatchObject({
        data: { reason: 'catalog_unavailable', retryable: true },
      });
    } finally {
      http.restore();
    }
  }, 20000);

  it('a failed refresh with a snapshot already held logs a warning and keeps serving the old snapshot', async () => {
    const ctx = createMockContext();
    const catalog = getKevCatalog();

    const httpFirst = createFetchMock([
      {
        match: KEV_FEED_URL,
        respond: new Response(buildKevFeedBody(), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      },
    ]);
    httpFirst.install();
    let before: KevSnapshot | undefined;
    try {
      before = await catalog.snapshot(ctx);
    } finally {
      httpFirst.restore();
    }

    const httpFail = createFetchMock([
      {
        match: KEV_FEED_URL,
        respond: () => {
          throw new TypeError('network failure');
        },
      },
    ]);
    httpFail.install();
    try {
      await expect(catalog.refresh(ctx)).resolves.toBeUndefined();
    } finally {
      httpFail.restore();
    }

    expect(catalog.currentSnapshot()).toBe(before);
  }, 20000);

  describe('search', () => {
    async function loadedCatalog() {
      const http = createFetchMock([
        {
          match: KEV_FEED_URL,
          respond: new Response(buildKevFeedBody(), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        },
      ]);
      http.install();
      try {
        const ctx = createMockContext();
        await getKevCatalog().snapshot(ctx);
        return ctx;
      } finally {
        http.restore();
      }
    }

    it('AND-combines vendorProject and product substring filters', async () => {
      const ctx = await loadedCatalog();
      const results = await getKevCatalog().search(
        { vendorProject: 'acme', product: 'widget' },
        'dateAdded',
        'desc',
        ctx,
      );
      expect(results.map((r) => r.cveId)).toEqual(['CVE-2026-00001']);
    });

    it('filters by exact CWE membership', async () => {
      const ctx = await loadedCatalog();
      const results = await getKevCatalog().search({ cwe: 'CWE-89' }, 'dateAdded', 'desc', ctx);
      expect(results.map((r) => r.cveId)).toEqual(['CVE-2021-00003']);
    });

    it('filters by cveIdPrefix (year scope)', async () => {
      const ctx = await loadedCatalog();
      const results = await getKevCatalog().search(
        { cveIdPrefix: 'CVE-2026' },
        'dateAdded',
        'asc',
        ctx,
      );
      expect(results.map((r) => r.cveId)).toEqual([
        'CVE-2026-00005',
        'CVE-2026-00001',
        'CVE-2026-00002',
      ]);
    });

    it('filters by ransomware linkage', async () => {
      const ctx = await loadedCatalog();
      const results = await getKevCatalog().search({ ransomware: true }, 'dateAdded', 'asc', ctx);
      expect(results.map((r) => r.cveId).sort()).toEqual(['CVE-2026-00001', 'CVE-2026-00005']);
    });

    it('filters by the forensic-triage tier', async () => {
      const ctx = await loadedCatalog();
      const results = await getKevCatalog().search(
        { forensicTriage: true },
        'dateAdded',
        'asc',
        ctx,
      );
      expect(results.map((r) => r.cveId)).toEqual(['CVE-2026-00001']);
    });

    it('filters by directive "none" — entries citing neither BOD', async () => {
      const ctx = await loadedCatalog();
      const results = await getKevCatalog().search({ directive: 'none' }, 'dateAdded', 'asc', ctx);
      expect(results.map((r) => r.cveId)).toEqual(['CVE-2019-00004']);
    });

    it('filters by directive BOD 22-01', async () => {
      const ctx = await loadedCatalog();
      const results = await getKevCatalog().search(
        { directive: 'BOD 22-01' },
        'dateAdded',
        'asc',
        ctx,
      );
      expect(results.map((r) => r.cveId)).toEqual(['CVE-2021-00003']);
    });

    it('overdue filter resolves against asOf, not the real clock', async () => {
      const ctx = await loadedCatalog();
      /* asOf is 2026-09-10 (injected clock): CVE-2026-00005 (due 2026-01-04) and
       * the pre-2026 entries are overdue; CVE-2026-00002 (due 2026-09-19) is not. */
      const results = await getKevCatalog().search({ overdue: true }, 'dateAdded', 'asc', ctx);
      const ids = results.map((r) => r.cveId);
      expect(ids).toContain('CVE-2026-00005');
      expect(ids).not.toContain('CVE-2026-00002');
    });

    it('date-added range filters are inclusive on both bounds', async () => {
      const ctx = await loadedCatalog();
      const results = await getKevCatalog().search(
        { dateAddedFrom: '2026-09-01', dateAddedTo: '2026-09-01' },
        'dateAdded',
        'asc',
        ctx,
      );
      expect(results.map((r) => r.cveId)).toEqual(['CVE-2026-00001']);
    });

    it('nameContains requires every token to match (strict, no fuzzy fallback)', async () => {
      const ctx = await loadedCatalog();
      const hit = await getKevCatalog().search(
        { nameContains: 'widget pro' },
        'dateAdded',
        'asc',
        ctx,
      );
      expect(hit.map((r) => r.cveId)).toEqual(['CVE-2026-00001']);

      const miss = await getKevCatalog().search(
        { nameContains: 'widget nonexistent' },
        'dateAdded',
        'asc',
        ctx,
      );
      expect(miss).toEqual([]);
    });

    it('sorts by dueDate ascending and descending', async () => {
      const ctx = await loadedCatalog();
      const asc = await getKevCatalog().search({}, 'dueDate', 'asc', ctx);
      const desc = await getKevCatalog().search({}, 'dueDate', 'desc', ctx);
      expect(asc.map((r) => r.cveId)).toEqual([...desc.map((r) => r.cveId)].reverse());
      const first = asc[0]?.dueDate;
      const last = asc.at(-1)?.dueDate;
      expect(first !== undefined && last !== undefined && first <= last).toBe(true);
    });

    it('returns an empty array when nothing matches', async () => {
      const ctx = await loadedCatalog();
      const results = await getKevCatalog().search(
        { vendorProject: 'nonexistent-vendor' },
        'dateAdded',
        'desc',
        ctx,
      );
      expect(results).toEqual([]);
    });

    it.each([
      ['punctuation', '--'],
      ['whitespace', '  '],
      ['CJK', '漏洞'],
    ])('throws empty_search_text when nameContains is %s', async (_label, nameContains) => {
      const ctx = await loadedCatalog();
      await expect(
        getKevCatalog().search({ nameContains }, 'dateAdded', 'desc', ctx),
      ).rejects.toMatchObject({
        code: JsonRpcErrorCode.ValidationError,
        data: {
          reason: 'empty_search_text',
          field: 'nameContains',
          recovery: { hint: expect.any(String) },
        },
      });
    });

    it('a word in another script beside a surviving token searches the survivor alone', async () => {
      const ctx = await loadedCatalog();
      const mixed = await getKevCatalog().search(
        { nameContains: '漏洞 widget ΠΡΟ' },
        'dateAdded',
        'asc',
        ctx,
      );
      const plain = await getKevCatalog().search(
        { nameContains: 'widget' },
        'dateAdded',
        'asc',
        ctx,
      );
      expect(mixed.map((r) => r.cveId)).toEqual(plain.map((r) => r.cveId));
      expect(mixed.map((r) => r.cveId)).toEqual(['CVE-2026-00001']);
    });
  });

  describe('queryTokens', () => {
    it.each([
      ['a word in another script', '漏洞 siemens', ['siemens'], ['漏洞']],
      ['two dropped words', 'ΑΘΗΝΑ acme 漏洞', ['acme'], ['ΑΘΗΝΑ', '漏洞']],
      ['a script run fused to a Latin word', '漏洞siemens', ['siemens'], ['漏洞siemens']],
      ['a letter with no Latin fold', 'straße', ['stra', 'e'], ['straße']],
      ['digits outside 0-9', 'acme ١٢٣', ['acme'], ['١٢٣']],
      ['accents, which fold', 'Café crème', ['cafe', 'creme'], []],
      ['punctuation, which is not a letter or digit', 'log4j—exploit --', ['log4j', 'exploit'], []],
      ['Latin only', 'Widget Pro', ['widget', 'pro'], []],
    ])('%s: %j searches %j and reports %j dropped', (_label, query, tokens, dropped) => {
      expect(queryTokens(query)).toEqual({ tokens, dropped });
    });

    it('still throws empty_search_text when every word is dropped', () => {
      expect(() => queryTokens('漏洞 ΑΘΗΝΑ')).toThrow(
        expect.objectContaining({ data: expect.objectContaining({ reason: 'empty_search_text' }) }),
      );
    });
  });

  describe('filterCounts', () => {
    async function loadedCatalog() {
      const http = createFetchMock([
        {
          match: KEV_FEED_URL,
          respond: new Response(buildKevFeedBody(), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        },
      ]);
      http.install();
      try {
        const ctx = createMockContext();
        await getKevCatalog().snapshot(ctx);
        return ctx;
      } finally {
        http.restore();
      }
    }

    it('counts each applied filter alone and what dropping it restores, in filter order', async () => {
      const ctx = await loadedCatalog();
      const counts = await getKevCatalog().filterCounts(
        { vendorProject: 'Acme', product: 'Gadget', forensicTriage: true },
        ctx,
      );
      expect(counts).toEqual([
        { filter: 'vendorProject', alone: 2, restoredByDropping: 0 },
        { filter: 'product', alone: 1, restoredByDropping: 1 },
        { filter: 'forensicTriage', alone: 1, restoredByDropping: 1 },
      ]);
    });

    it('reports no restorer when every pair of filters is disjoint', async () => {
      const ctx = await loadedCatalog();
      const counts = await getKevCatalog().filterCounts(
        { vendorProject: 'OldVendor', cveIdPrefix: 'CVE-2026', directive: 'none' },
        ctx,
      );
      expect(counts).toEqual([
        { filter: 'vendorProject', alone: 1, restoredByDropping: 0 },
        { filter: 'cveIdPrefix', alone: 3, restoredByDropping: 0 },
        { filter: 'directive', alone: 1, restoredByDropping: 0 },
      ]);
    });

    it('resolves overdue against asOf and counts a filter that matches nothing as zero', async () => {
      const ctx = await loadedCatalog();
      /* asOf 2026-09-10: only CVE-2026-00002 (due 2026-09-19) is not overdue, and it
       * passes every filter but cveIdPrefix — so dropping cveIdPrefix restores it. */
      const counts = await getKevCatalog().filterCounts(
        { overdue: false, cveIdPrefix: 'CVE-2099', ransomware: false, forensicTriage: false },
        ctx,
      );
      expect(counts).toEqual([
        { filter: 'cveIdPrefix', alone: 0, restoredByDropping: 1 },
        { filter: 'overdue', alone: 1, restoredByDropping: 0 },
        { filter: 'ransomware', alone: 3, restoredByDropping: 0 },
        { filter: 'forensicTriage', alone: 4, restoredByDropping: 0 },
      ]);
    });

    it('returns no counts when no filter is applied', async () => {
      const ctx = await loadedCatalog();
      expect(await getKevCatalog().filterCounts({ vendorProject: '' }, ctx)).toEqual([]);
    });
  });
});
