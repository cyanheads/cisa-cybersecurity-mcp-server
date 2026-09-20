/**
 * @fileoverview Tests for the CISA RSS feed service — parsing, the timer
 * cache, HTML-body classification, feed_unavailable on a channel-less body,
 * and the fall-back-to-cache behavior on a failed refresh.
 * @module tests/services/cisa-feeds/cisa-feeds-service.test
 */

import { McpError } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  FEED_URLS,
  getCisaFeeds,
  initCisaFeeds,
  resetCisaFeeds,
  SUMMARY_CAP,
} from '@/services/cisa-feeds/cisa-feeds-service.js';
import {
  buildAdvisoriesFeed,
  buildEmptyChannelFeed,
  buildIcsAdvisoriesFeedWithOversizedItem,
} from '../../fixtures/rss-feeds.js';

describe('CisaFeedsService', () => {
  beforeEach(() => {
    resetCisaFeeds();
    initCisaFeeds({ cacheTtlSeconds: 900, timeoutMs: 5000 });
  });

  afterEach(() => {
    resetCisaFeeds();
  });

  it('parses items, trims titles, and chains an advisory link into advisoryId', async () => {
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
      const ctx = createMockContext();
      const window = await getCisaFeeds().window('advisories', ctx);
      expect(window.items).toHaveLength(2);
      expect(window.items[0]?.title).toBe('Acme Widget Advisory');
      expect(window.items[0]?.advisoryId).toBe('ICSA-26-260-07');
      expect(window.items[0]?.pubDate).toBe('2026-09-18T12:00:00.000Z');
      expect(window.items[0]?.guid).toBe('/node/25513');
      expect(window.items[1]?.advisoryId).toBeUndefined();
      expect(window.feedTitle).toBe('CISA Advisories');
    } finally {
      http.restore();
    }
  });

  it('caches the parsed window and does not refetch within the TTL', async () => {
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
      const ctx = createMockContext();
      await getCisaFeeds().window('advisories', ctx);
      await getCisaFeeds().window('advisories', ctx);
      expect(http.calls).toHaveLength(1);
    } finally {
      http.restore();
    }
  });

  it('caps and discloses truncation of an oversized item description', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.ics,
        respond: new Response(buildIcsAdvisoriesFeedWithOversizedItem(), {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      const window = await getCisaFeeds().window('ics', ctx);
      const item = window.items[0];
      expect(item?.summaryTruncated).toBe(true);
      expect(item?.summary.length).toBe(SUMMARY_CAP);
      expect(item?.summary.endsWith('…')).toBe(true);
    } finally {
      http.restore();
    }
  });

  it('classifies an HTML error body as ServiceUnavailable, never SerializationError', async () => {
    const html = `<!doctype html><html><body>${'x'.repeat(500)}</body></html>`;
    const http = createFetchMock([
      {
        match: FEED_URLS.alerts,
        respond: new Response(html, { headers: { 'content-type': 'text/html' } }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      const error = await getCisaFeeds()
        .window('alerts', ctx)
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).not.toBe('SerializationError');
    } finally {
      http.restore();
    }
  }, 20000);

  it('throws feed_unavailable when the body carries no RSS channel', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.alerts,
        respond: new Response('<?xml version="1.0"?><foo></foo>', {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      await expect(getCisaFeeds().window('alerts', ctx)).rejects.toMatchObject({
        data: { reason: 'feed_unavailable' },
      });
    } finally {
      http.restore();
    }
  }, 20000);

  it('an empty channel (no items) yields an empty window with null oldest/newest', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.alerts,
        respond: new Response(buildEmptyChannelFeed(), {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      const window = await getCisaFeeds().window('alerts', ctx);
      expect(window.items).toEqual([]);
      expect(window.oldest).toBeNull();
      expect(window.newest).toBeNull();
    } finally {
      http.restore();
    }
  });

  it('falls back to the cached window when a refresh fails after the TTL expires', async () => {
    const ctx = createMockContext();
    const httpFirst = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: new Response(buildAdvisoriesFeed(), {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    httpFirst.install();
    try {
      await getCisaFeeds().window('advisories', ctx);
    } finally {
      httpFirst.restore();
    }

    /* Force the cache to look stale by re-initializing with a zero TTL, then
     * fail the next fetch — the service should fall back to serving the last
     * good window rather than throwing, once a cached window exists. */
    resetCisaFeeds();
    initCisaFeeds({ cacheTtlSeconds: 0, timeoutMs: 5000 });
    const httpWarm = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: new Response(buildAdvisoriesFeed(), {
          headers: { 'content-type': 'application/xml' },
        }),
      },
    ]);
    httpWarm.install();
    try {
      await getCisaFeeds().window('advisories', ctx);
    } finally {
      httpWarm.restore();
    }

    const httpFail = createFetchMock([
      {
        match: FEED_URLS.advisories,
        respond: () => {
          throw new TypeError('network failure');
        },
      },
    ]);
    httpFail.install();
    try {
      const window = await getCisaFeeds().window('advisories', ctx);
      expect(window.items).toHaveLength(2);
    } finally {
      httpFail.restore();
    }
  }, 20000);

  it('throws feed_unavailable when no cache exists and every attempt fails', async () => {
    const http = createFetchMock([
      {
        match: FEED_URLS.ics,
        respond: () => {
          throw new TypeError('network failure');
        },
      },
    ]);
    http.install();
    try {
      const ctx = createMockContext();
      await expect(getCisaFeeds().window('ics', ctx)).rejects.toMatchObject({
        data: { reason: 'feed_unavailable', retryable: true },
      });
    } finally {
      http.restore();
    }
  }, 20000);
});
