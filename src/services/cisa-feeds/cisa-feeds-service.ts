/**
 * @fileoverview CISA RSS feed service — the Tier 4 timer cache. The feeds serve
 * no `etag` and no `last-modified`, and set `cache-control: private, no-cache,
 * must-revalidate`, so there is nothing to make a request conditional on. Each
 * feed is therefore fetched at most once per TTL window per process and the
 * parsed window is held in memory; worst case is three unconditional fetches per
 * window totalling about 1 MB, against a source that publishes no rate limit.
 *
 * Each feed is a rolling window of exactly 30 items with no history and no
 * pagination. That ceiling is the upstream's, not a server choice.
 * @module services/cisa-feeds/cisa-feeds-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { withRetry, xmlParser } from '@cyanheads/mcp-ts-core/utils';
import { assertNotHtml, fetchUpstream, readUpstreamText } from '@/services/upstream-http.js';
import { advisoryIdFromLink, normalizePubDate, stripFeedHtml } from './normalize.js';
import type { FeedId, FeedItem, FeedsState, FeedWindow } from './types.js';

/** The three published feeds, by the identifier the tool exposes. */
export const FEED_URLS: Record<FeedId, string> = {
  advisories: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
  alerts: 'https://www.cisa.gov/cybersecurity-advisories/alerts.xml',
  ics: 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml',
};

/** The rolling window size every feed serves. Upstream's ceiling, not a server choice. */
export const UPSTREAM_WINDOW_SIZE = 30;

/** Characters of stripped description text retained per item. */
export const SUMMARY_CAP = 1200;

/** Ceiling on a feed body. The largest is 531 KB; this is two orders above it. */
const FEED_MAX_BYTES = 32 * 1024 * 1024;

/** Options for {@link initCisaFeeds}. */
export interface CisaFeedsOptions {
  /** TTL in seconds for a parsed feed window. */
  cacheTtlSeconds: number;
  /** Per-request upstream timeout in milliseconds. */
  timeoutMs: number;
}

interface CachedWindow {
  fetchedAtMs: number;
  window: FeedWindow;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function text(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  if (isRecord(value) && typeof value['#text'] === 'string') return value['#text'];
  return '';
}

/** Map one parsed `<item>` into the domain shape. */
function toFeedItem(raw: unknown): FeedItem | null {
  if (!isRecord(raw)) return null;
  const link = text(raw.link).trim();
  const title = text(raw.title).trim();
  if (title === '' && link === '') return null;

  const summary = stripFeedHtml(text(raw.description));
  const truncated = summary.length > SUMMARY_CAP;
  const advisoryId = advisoryIdFromLink(link);

  return {
    title,
    link,
    pubDate: normalizePubDate(text(raw.pubDate)),
    summary: truncated ? `${summary.slice(0, SUMMARY_CAP - 1).trimEnd()}…` : summary,
    summaryTruncated: truncated,
    /* Upstream `guid` is a node path (`/node/25513`), not a URL and not a permalink. */
    guid: text(raw.guid).trim(),
    ...(advisoryId ? { advisoryId } : {}),
  };
}

export class CisaFeedsService {
  private readonly cache = new Map<FeedId, CachedWindow>();

  constructor(private readonly options: CisaFeedsOptions) {}

  /** In-process state for `cisa_list_reference` topic `sources`. Never fetches. */
  state(): FeedsState {
    return {
      windowItems: UPSTREAM_WINDOW_SIZE,
      cached: [...this.cache.entries()].map(([feed, entry]) => ({
        feed,
        oldest: entry.window.oldest,
        newest: entry.window.newest,
        fetchedAt: new Date(entry.fetchedAtMs).toISOString(),
      })),
    };
  }

  /** The parsed window for one feed, refetching when the cached copy is stale. */
  async window(feed: FeedId, ctx: Context): Promise<FeedWindow> {
    const cached = this.cache.get(feed);
    const ttlMs = this.options.cacheTtlSeconds * 1000;
    if (cached && Date.now() - cached.fetchedAtMs < ttlMs) return cached.window;

    try {
      const fresh = await this.fetchWindow(feed, ctx);
      this.cache.set(feed, { window: fresh, fetchedAtMs: Date.now() });
      return fresh;
    } catch (error) {
      if (cached) {
        ctx.log.warning('CISA feed refresh failed; serving the cached window', {
          feed,
          error: error instanceof Error ? error.message : String(error),
        });
        return cached.window;
      }
      throw serviceUnavailable(
        `The CISA ${feed} feed could not be fetched or parsed.`,
        { reason: 'feed_unavailable', retryable: true, ...ctx.recoveryFor('feed_unavailable') },
        { cause: error },
      );
    }
  }

  private fetchWindow(feed: FeedId, ctx: Context): Promise<FeedWindow> {
    const url = FEED_URLS[feed];
    return withRetry(
      async () => {
        const response = await fetchUpstream(url, {
          service: 'CISA advisories feed',
          timeoutMs: this.options.timeoutMs,
          signal: ctx.signal,
        });
        const body = await readUpstreamText(response, {
          maxBytes: FEED_MAX_BYTES,
          service: 'CISA advisories feed',
          url,
        });
        assertNotHtml(body, response.headers.get('content-type'), 'xml', url);

        const parsed = await xmlParser.parse<unknown>(body, ctx);
        const rss = isRecord(parsed) && isRecord(parsed.rss) ? parsed.rss : undefined;
        const channel = rss && isRecord(rss.channel) ? rss.channel : undefined;
        if (!channel) {
          throw serviceUnavailable(`The CISA ${feed} feed body carried no RSS channel.`, {
            reason: 'feed_unavailable',
            retryable: true,
          });
        }

        const rawItems = Array.isArray(channel.item)
          ? channel.item
          : channel.item
            ? [channel.item]
            : [];
        const items = rawItems.map(toFeedItem).filter((item): item is FeedItem => item !== null);
        const dates = items
          .map((item) => item.pubDate)
          .filter(Boolean)
          .sort();

        return {
          feed,
          feedUrl: url,
          feedTitle: text(channel.title).trim(),
          items,
          oldest: dates[0] ?? null,
          newest: dates.at(-1) ?? null,
        };
      },
      {
        operation: 'CisaFeedsService.fetchWindow',
        baseDelayMs: 1000,
        context: ctx,
        signal: ctx.signal,
      },
    );
  }
}

// --- Init/accessor pattern ---

let _service: CisaFeedsService | undefined;

/** Construct the feeds service. Call once from `createApp`'s `setup()`. */
export function initCisaFeeds(options: CisaFeedsOptions): CisaFeedsService {
  _service = new CisaFeedsService(options);
  return _service;
}

/** Access the initialized feeds service. */
export function getCisaFeeds(): CisaFeedsService {
  if (!_service) {
    throw new Error('CisaFeedsService not initialized — call initCisaFeeds() in setup().');
  }
  return _service;
}

/** Reset the singleton — test-only. */
export function resetCisaFeeds(): void {
  _service = undefined;
}
