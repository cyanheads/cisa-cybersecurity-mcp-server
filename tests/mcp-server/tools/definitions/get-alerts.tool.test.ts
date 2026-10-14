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
import { getAlertsTool } from '@/mcp-server/tools/definitions/get-alerts.tool.js';
import {
  FEED_URLS,
  getCisaFeeds,
  initCisaFeeds,
  resetCisaFeeds,
} from '@/services/cisa-feeds/cisa-feeds-service.js';
import { buildAdvisoriesFeed } from '../../../fixtures/rss-feeds.js';
import { strictClientValidator } from '../../../helpers/emitted-schema.js';
import { firstText } from '../../../helpers/format-text.js';

describe('cisa_get_alerts', () => {
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
            controller.abort();
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

  it('rejects a limit above 30 (the upstream ceiling)', () => {
    expect(() => getAlertsTool.input.parse({ limit: 31 })).toThrow();
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
