/**
 * @fileoverview Tests for `cisa_get_alerts` — feed_unavailable, the since
 * filter excluding the whole window, truncation, the advisoryId chain, and
 * the two-digit-year pubDate / trailing-whitespace title passthrough from the
 * feed normalizer.
 * @module tests/mcp-server/tools/definitions/get-alerts.tool.test
 */

import {
  createFetchMock,
  createMockContext,
  getEnrichment,
  runToolContract,
} from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetServerConfig } from '@/config/server-config.js';
import { getAlertsTool } from '@/mcp-server/tools/definitions/get-alerts.tool.js';
import {
  FEED_URLS,
  getCisaFeeds,
  initCisaFeeds,
  resetCisaFeeds,
} from '@/services/cisa-feeds/cisa-feeds-service.js';
import { buildAdvisoriesFeed, buildRollingFeed } from '../../../fixtures/rss-feeds.js';
import { strictClientValidator } from '../../../helpers/emitted-schema.js';
import { firstText } from '../../../helpers/format-text.js';

describe('cisa_get_alerts', () => {
  it('walks every page of a warm window once and preserves the default 30-item read', async () => {
    const http = createFetchMock([
      { match: FEED_URLS.advisories, respond: () => new Response(buildRollingFeed()) },
    ]);
    http.install();
    try {
      const full = await runToolContract(getAlertsTool, { limit: 31 });
      expect(full.structuredContent).toMatchObject({ hasMore: false, window: { itemCount: 30 } });
      expect(full.structuredContent).not.toHaveProperty('notice');
      const ids: string[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 15; page++) {
        const result = await runToolContract(getAlertsTool, {
          limit: 2,
          ...(cursor ? { cursor } : {}),
        });
        const structured = result.structuredContent as {
          items: Array<{ guid: string }>;
          cursor?: string;
          hasMore: boolean;
          fetchedAt: string;
        };
        ids.push(...structured.items.map((item) => item.guid));
        expect(structured.hasMore).toBe(page < 14);
        expect(structured.fetchedAt).toBe(
          (full.structuredContent as { fetchedAt: string }).fetchedAt,
        );
        if (structured.cursor) expect(JSON.stringify(result.content)).toContain(structured.cursor);
        cursor = structured.cursor;
      }
      expect(ids).toEqual(Array.from({ length: 30 }, (_, index) => `/node/${30 - index}`));
      expect(cursor).toBeUndefined();
      expect(http.calls).toHaveLength(1);
    } finally {
      http.restore();
    }
  });

  it('resumes after a stable anchor when upstream prepends and applies since afterward', async () => {
    initCisaFeeds({ cacheTtlSeconds: 0, timeoutMs: 5000 });
    let ids = [30, 29, 28, 27];
    const http = createFetchMock([
      { match: FEED_URLS.advisories, respond: () => new Response(buildRollingFeed(ids)) },
    ]);
    http.install();
    try {
      const first = await runToolContract(getAlertsTool, { limit: 2 });
      const { cursor } = first.structuredContent as { cursor: string };
      ids = [31, 30, 29, 28, 27];
      const next = await runToolContract(getAlertsTool, { cursor, limit: 2, since: '2026-09-28' });
      expect(next.structuredContent).toMatchObject({
        items: [{ guid: '/node/28' }],
        hasMore: false,
      });
      expect(JSON.stringify(next.content)).toContain('/node/28');
      expect(JSON.stringify(next.content)).not.toContain('Alert 29');
    } finally {
      http.restore();
    }
  });

  it.each([
    ['removed', [30, 28]],
    ['fabricated', [30, 29, 28]],
    ['empty', []],
  ] as const)('discloses an unavailable %s anchor without inferring why', async (kind, ids) => {
    const cursor = Buffer.from(
      JSON.stringify({
        feed: 'advisories',
        guid: kind === 'fabricated' ? '/node/999' : '/node/29',
      }),
    ).toString('base64url');
    const http = createFetchMock([
      { match: FEED_URLS.advisories, respond: () => new Response(buildRollingFeed([...ids])) },
    ]);
    http.install();
    try {
      const result = await runToolContract(getAlertsTool, { cursor });
      expect(result.structuredContent).toMatchObject({ items: [], hasMore: false });
      expect(result.structuredContent).not.toHaveProperty('cursor');
      for (const surface of [
        JSON.stringify(result.structuredContent),
        JSON.stringify(result.content),
      ]) {
        expect(surface).toContain('anchor is unavailable');
        expect(surface).toContain('Restart without a cursor');
        expect(surface).not.toContain('evicted');
        expect(surface).not.toContain('rolled past');
      }
    } finally {
      http.restore();
    }
  });

  it.each([
    'not-json',
    Buffer.from(JSON.stringify({ feed: 'ics', guid: '/node/1' })).toString('base64url'),
  ])('rejects invalid or mismatched cursors before fetching: %s', async (cursor) => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    const result = await runToolContract(getAlertsTool, { feed: 'alerts', cursor });
    expect(result.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cursor', retryable: false } },
    });
    for (const surface of [
      JSON.stringify(result.structuredContent),
      JSON.stringify(result.content),
    ])
      expect(surface).toContain('same feed');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('keeps stale freshness and anchor guidance together, then can continue in the cached window', async () => {
    initCisaFeeds({ cacheTtlSeconds: 0, timeoutMs: 5000 });
    let fail = false;
    const http = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: () =>
          fail ? new Response('', { status: 400 }) : new Response(buildRollingFeed()),
      },
    ]);
    http.install();
    try {
      const first = await runToolContract(getAlertsTool, { limit: 2 });
      const initial = first.structuredContent as { cursor: string; fetchedAt: string };
      fail = true;
      const continued = await runToolContract(getAlertsTool, { limit: 2, cursor: initial.cursor });
      expect(continued.structuredContent).toMatchObject({
        stale: true,
        fetchedAt: initial.fetchedAt,
        items: [{ guid: '/node/28' }, { guid: '/node/27' }],
        hasMore: true,
      });
      const cursor = Buffer.from(
        JSON.stringify({ feed: 'advisories', guid: '/node/missing' }),
      ).toString('base64url');
      const unavailable = await runToolContract(getAlertsTool, { cursor });
      for (const surface of [
        JSON.stringify(unavailable.structuredContent),
        JSON.stringify(unavailable.content),
      ]) {
        expect(surface).toContain('anchor is unavailable in this cached window');
        expect(surface).toContain('Retry in a few minutes');
        expect(surface).toContain('may omit newer publications');
        expect(surface).toContain('2026-09-01');
      }
    } finally {
      http.restore();
    }
  });

  it('rejects an oversized limit in strict mode before fetching, with recovery on both surfaces', async () => {
    vi.stubEnv('CISA_CLAMP_OVERSIZED_INPUTS', 'false');
    resetServerConfig();
    const fetch = vi.spyOn(globalThis, 'fetch');
    try {
      const result = await runToolContract(getAlertsTool, { limit: 31 });
      expect(result.structuredContent).toMatchObject({
        error: { data: { reason: 'read_limit_exceeded', retryable: false } },
      });
      for (const surface of [
        JSON.stringify(result.structuredContent),
        JSON.stringify(result.content),
      ])
        expect(surface).toContain('30');
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllEnvs();
      resetServerConfig();
    }
  });
  it('preserves the default whole available window and normalized GUID order', async () => {
    const http = createFetchMock([
      { match: FEED_URLS.advisories, respond: () => new Response(buildAdvisoriesFeed()) },
    ]);
    http.install();
    try {
      const result = await getAlertsTool.handler(
        getAlertsTool.input.parse({}),
        createMockContext({ errors: getAlertsTool.errors }),
      );
      expect(result.items.map((item) => item.guid)).toEqual(['/node/25513', '/node/25500']);
      expect(result.window.itemCount).toBe(2);
    } finally {
      http.restore();
    }
  });

  it('continues after the GUID anchor on both surfaces', async () => {
    const http = createFetchMock([
      { match: FEED_URLS.advisories, respond: () => new Response(buildAdvisoriesFeed()) },
    ]);
    http.install();
    try {
      const first = await runToolContract(getAlertsTool, { limit: 1 });
      const page = first.structuredContent as { hasMore: boolean; cursor: string };
      expect(page.hasMore).toBe(true);
      expect(page.cursor).toEqual(expect.any(String));
      const next = await runToolContract(getAlertsTool, { limit: 1, cursor: page.cursor });
      expect(next.structuredContent).toMatchObject({
        hasMore: false,
        items: [{ guid: '/node/25500' }],
      });
      expect(JSON.stringify(next.content)).toContain('/node/25500');
      expect(JSON.stringify(next.content)).toContain('More available:');
    } finally {
      http.restore();
    }
  });
  beforeEach(() => {
    resetCisaFeeds();
    initCisaFeeds({ cacheTtlSeconds: 900, timeoutMs: 5000 });
  });

  afterEach(() => {
    resetCisaFeeds();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('discloses stale empty results safely on both surfaces, preserves earlier responses and recovers', async () => {
    initCisaFeeds({ cacheTtlSeconds: 0, timeoutMs: 5000 });
    let fail = false;
    const http = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: () =>
          fail
            ? new Response('private diagnostic body', { status: 400 })
            : new Response(buildAdvisoriesFeed()),
      },
    ]);
    http.install();
    try {
      const fresh = await runToolContract(getAlertsTool, {});
      const before = JSON.stringify(fresh);
      expect(fresh.structuredContent).toMatchObject({
        stale: false,
        fetchedAt: expect.any(String),
      });
      fail = true;
      const stale = await runToolContract(getAlertsTool, { since: '2099-01-01' });
      expect(stale.structuredContent).toMatchObject({
        stale: true,
        fetchedAt: (fresh.structuredContent as { fetchedAt: string }).fetchedAt,
        items: [],
      });
      for (const surface of [
        JSON.stringify(stale.structuredContent),
        JSON.stringify(stale.content),
      ]) {
        expect(surface).toContain('retry in a few minutes');
        expect(surface).toContain('does not establish current publication absence');
        expect(surface).not.toContain('private diagnostic body');
      }
      expect(JSON.stringify(fresh)).toBe(before);
      fail = false;
      const recovered = await runToolContract(getAlertsTool, { limit: 1 });
      expect(recovered.structuredContent).toMatchObject({
        stale: false,
        truncated: true,
        shown: 1,
        cap: 1,
      });
      expect(JSON.stringify(stale.structuredContent)).toContain('"stale":true');
    } finally {
      http.restore();
    }
  });

  it('returns cancellation instead of stale success when the caller aborts during refresh', async () => {
    vi.useFakeTimers();
    initCisaFeeds({ cacheTtlSeconds: 0, timeoutMs: 5000 });
    const controller = new AbortController();
    let cancel = false;
    const http = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: () => {
          if (cancel) {
            controller.abort(new DOMException('This operation was aborted', 'AbortError'));
            throw controller.signal.reason;
          }
          return new Response(buildAdvisoriesFeed());
        },
      },
    ]);
    http.install();
    try {
      await runToolContract(getAlertsTool, {});
      cancel = true;
      const result = await runToolContract(
        getAlertsTool,
        {},
        { context: { signal: controller.signal } },
      );
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({ error: { code: -32011 } });
      expect(JSON.stringify(result.content)).toContain('This operation was aborted');
      expect(http.calls).toHaveLength(2);
      await vi.advanceTimersByTimeAsync(60_000);
      expect(http.calls).toHaveLength(2);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      http.restore();
    }
  });

  it('shares a 45-second deadline across attempts and backoff before stale fallback', async () => {
    vi.useFakeTimers();
    initCisaFeeds({ cacheTtlSeconds: 0, timeoutMs: 30_000 });
    let attempts = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      attempts++;
      if (attempts === 1) return new Response(buildAdvisoriesFeed());
      if (attempts === 2)
        return new Response('', { status: 503, headers: { 'retry-after': '30' } });
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
      });
    });
    await runToolContract(getAlertsTool, {});
    const started = Date.now();
    const pending = runToolContract(getAlertsTool, {}).then((result) => ({
      result,
      settledAt: Date.now(),
    }));
    await vi.advanceTimersByTimeAsync(45_000);
    const { result, settledAt } = await pending;
    expect(settledAt - started).toBe(45_000);
    expect(result.structuredContent).toMatchObject({ stale: true });
    expect(attempts).toBe(3);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(attempts).toBe(3);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('returns items with normalized pubDate, trimmed title, and the advisoryId chain', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: new Response(buildAdvisoriesFeed(), {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getAlertsTool.errors });
      const input = getAlertsTool.input.parse({ feed: 'advisories' });
      const result = await getAlertsTool.handler(input, ctx);
      expect(result.items).toHaveLength(2);
      expect(result.items[0]?.title).toBe('Acme Widget Advisory');
      expect(result.items[0]?.pubDate).toBe('2026-09-18T12:00:00.000Z');
      expect(result.items[0]?.advisoryId).toBe('ICSA-26-260-07');
      expect(result.items[1]?.advisoryId).toBeUndefined();

      const text = firstText(getAlertsTool.format?.(result));
      expect(text).toContain(result.items[0]?.title as string);
      expect(text).toContain(result.items[0]?.advisoryId as string);
      expect(text).toContain(result.window.oldest as string);
      expect(text).toContain(String(result.window.upstreamWindowSize));

      const enrichment = getEnrichment(ctx);
      expect(enrichment.windowCaveat).toContain('rolling window of the 30 most recent items');
    } finally {
      http.restore();
    }
  });

  it('an ICS item whose slug carries a revision suffix validates against the emitted, flag-free output schema', async () => {
    const feed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>CISA ICS Advisories</title>
<item>
  <title>Revised ICS Advisory</title>
  <link>https://www.cisa.gov/news-events/ics-advisories/icsa-24-100-01a</link>
  <description>Update A.</description>
  <pubDate>Fri, 18 Sep 26 12:00:00 +0000</pubDate>
  <guid>/node/25520</guid>
</item>
</channel></rss>`;
    const http = createFetchMock([
      {
        match: FEED_URLS.ics,
        respond: new Response(feed, { headers: { 'content-type': 'application/xml' } }),
      },
    ]);
    http.install();
    try {
      const result = await runToolContract(getAlertsTool, { feed: 'ics' });
      const structured = result.structuredContent as { items: Array<{ advisoryId?: string }> };
      expect(structured.items[0]?.advisoryId).toBe('ICSA-24-100-01A');
      const verdict = strictClientValidator(getAlertsTool).safeParse(structured);
      expect(verdict.error?.issues ?? []).toEqual([]);
    } finally {
      http.restore();
    }
  });

  it('the since filter excludes items before the date and discloses the exclusion count', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: new Response(buildAdvisoriesFeed(), {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getAlertsTool.errors });
      const input = getAlertsTool.input.parse({ feed: 'advisories', since: '2026-09-18' });
      const result = await getAlertsTool.handler(input, ctx);
      expect(result.items).toHaveLength(1);
      expect(result.items[0]?.title).toBe('Acme Widget Advisory');
      const enrichment = getEnrichment(ctx);
      expect(enrichment.effectiveQuery).toContain('since=2026-09-18');
      expect(enrichment.effectiveQuery).toContain('excluded 1 of 2');
    } finally {
      http.restore();
    }
  });

  it('emits the zero-match notice when since excludes every item', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: new Response(buildAdvisoriesFeed(), {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getAlertsTool.errors });
      const input = getAlertsTool.input.parse({ feed: 'advisories', since: '2099-01-01' });
      const result = await getAlertsTool.handler(input, ctx);
      expect(result.items).toEqual([]);
      const enrichment = getEnrichment(ctx);
      expect(enrichment.notice).toContain('No item in the current 30-item window is on or after');
    } finally {
      http.restore();
    }
  });

  it('truncates to limit and discloses shown/cap', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: new Response(buildAdvisoriesFeed(), {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getAlertsTool.errors });
      const input = getAlertsTool.input.parse({ feed: 'advisories', limit: 1 });
      const result = await getAlertsTool.handler(input, ctx);
      expect(result.items).toHaveLength(1);
      const enrichment = getEnrichment(ctx);
      expect(enrichment.truncated).toBe(true);
      expect(enrichment.shown).toBe(1);
      expect(enrichment.cap).toBe(1);
    } finally {
      http.restore();
    }
  });

  it('throws feed_unavailable when the feed fetch fails and no cache exists', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.alerts,
        respond: () => {
          throw new TypeError('network failure');
        },
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getAlertsTool.errors });
      const input = getAlertsTool.input.parse({ feed: 'alerts' });
      await expect(getAlertsTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'feed_unavailable' },
      });
    } finally {
      http.restore();
    }
  }, 20000);

  it('defaults feed to advisories and limit to the upstream window size', () => {
    const input = getAlertsTool.input.parse({});
    expect(input.feed).toBe('advisories');
    expect(input.limit).toBe(30);
  });

  it('keeps the cold feed_unavailable recovery contract on both surfaces', async () => {
    const http = createFetchMock([
      { match: FEED_URLS.alerts, respond: () => new Response('private failure', { status: 400 }) },
    ]);
    http.install();
    try {
      const result = await runToolContract(getAlertsTool, { feed: 'alerts' });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        error: { data: { reason: 'feed_unavailable', retryable: true } },
      });
      for (const surface of [
        JSON.stringify(result.structuredContent),
        JSON.stringify(result.content),
      ]) {
        expect(surface).toContain('retry in a few minutes');
        expect(surface).not.toContain('private failure');
      }
    } finally {
      http.restore();
    }
  });

  it('accepts limit 31 and rejects above the hard ceiling', () => {
    expect(getAlertsTool.input.parse({ limit: 31 }).limit).toBe(31);
    expect(() => getAlertsTool.input.parse({ limit: 1001 })).toThrow();
  });

  it('reads the currently-cached window state via getCisaFeeds directly', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: new Response(buildAdvisoriesFeed(), {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext({ errors: getAlertsTool.errors });
      await getAlertsTool.handler(getAlertsTool.input.parse({ feed: 'advisories' }), ctx);
      const state = getCisaFeeds().state();
      expect(state.cached.some((c) => c.feed === 'advisories')).toBe(true);
    } finally {
      http.restore();
    }
  });
});
