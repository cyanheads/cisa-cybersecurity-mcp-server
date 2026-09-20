/**
 * @fileoverview Domain types for the CISA RSS feed tier — the feed identifiers,
 * one normalized item, and the rolling window envelope.
 * @module services/cisa-feeds/types
 */

/** The three published feeds, by the identifier `cisa_get_alerts` exposes. */
export type FeedId = 'advisories' | 'alerts' | 'ics';

/** One normalized feed item. */
export interface FeedItem {
  /** Present when the item links to an ICS advisory page; chains into `cisa_get_advisory`. */
  advisoryId?: string;
  /** The upstream node path (e.g. `/node/25513`) — not a URL and not a permalink. */
  guid: string;
  link: string;
  pubDate: string;
  summary: string;
  summaryTruncated: boolean;
  title: string;
}

/** One feed's current rolling window. */
export interface FeedWindow {
  feed: FeedId;
  feedTitle: string;
  feedUrl: string;
  items: FeedItem[];
  newest: string | null;
  oldest: string | null;
}

/** What `cisa_list_reference` topic `sources` reports about the feed tier. */
export interface FeedsState {
  cached: Array<{ feed: FeedId; fetchedAt: string; newest: string | null; oldest: string | null }>;
  windowItems: number;
}
