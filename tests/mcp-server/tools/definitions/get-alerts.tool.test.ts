/**
 * @fileoverview Tests for `cisa_get_alerts` — feed_unavailable, the since
 * filter excluding the whole window, truncation, the advisoryId chain, and
 * the two-digit-year pubDate / trailing-whitespace title passthrough from the
 * feed normalizer.
 * @module tests/mcp-server/tools/definitions/get-alerts.tool.test
 */

import { createFetchMock, createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getAlertsTool } from '@/mcp-server/tools/definitions/get-alerts.tool.js';
import {
  FEED_URLS,
  getCisaFeeds,
  initCisaFeeds,
  resetCisaFeeds,
} from '@/services/cisa-feeds/cisa-feeds-service.js';
import { buildAdvisoriesFeed } from '../../../fixtures/rss-feeds.js';
import { firstText } from '../../../helpers/format-text.js';

describe('cisa_get_alerts', () => {
  beforeEach(() => {
    resetCisaFeeds();
    initCisaFeeds({ cacheTtlSeconds: 900, timeoutMs: 5000 });
  });

  afterEach(() => {
    resetCisaFeeds();
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
