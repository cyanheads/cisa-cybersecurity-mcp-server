/**
 * @fileoverview `cisa_get_alerts` — the current rolling window of one CISA
 * publication feed, with GUID continuation within the available window.
 * @module mcp-server/tools/definitions/get-alerts.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { applyReadLimit, READ_INPUT_HARD_CEILING } from '@/mcp-server/read-limits.js';
import { CalendarDateInputSchema } from '@/mcp-server/schemas/kev-record.js';
import { getCisaFeeds, UPSTREAM_WINDOW_SIZE } from '@/services/cisa-feeds/cisa-feeds-service.js';
import { ADVISORY_ID_PATTERN } from '@/services/csaf-mirror/normalize.js';

const WINDOW_CAVEAT =
  'This feed is a rolling window of the 30 most recent items. Cursors continue only within the available current or cached window; upstream has no pagination, history, or server-side date filter. Anything older than the oldest window item is unreachable from this feed. For ICS advisory history use cisa_search_ics_advisories.';

const FeedCursorSchema = z.object({
  feed: z.enum(['advisories', 'alerts', 'ics']),
  guid: z.string().min(1),
});

/** Decode caller-controlled JSON at the cursor boundary. */
function parseFeedCursor(cursor: string) {
  try {
    return FeedCursorSchema.parse(JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')));
  } catch {
    return;
  }
}

export const getAlertsTool = tool('cisa_get_alerts', {
  title: 'cisa_get_alerts',
  description:
    "List what CISA has published recently — its combined advisory feed, its alerts feed, or its ICS advisory feed. Cursors continue within the current 30-item rolling window; upstream provides no pagination, history, or date-range query. The window's coverage varies from about a week to about two months depending on the feed. For ICS advisory history beyond the window, use cisa_search_ics_advisories, which covers the full corpus back to 2010.",
  annotations: { readOnlyHint: true, idempotentHint: true },

  input: z.object({
    feed: z
      .enum(['advisories', 'alerts', 'ics'])
      .default('advisories')
      .describe(
        'Which feed to read: advisories (all.xml, ~8 days of coverage), alerts (alerts.xml, ~8 weeks), or ics (ics-advisories.xml, ~2.5 weeks).',
      ),
    limit: z
      .number()
      .int()
      .min(1)
      .max(READ_INPUT_HARD_CEILING)
      .default(UPSTREAM_WINDOW_SIZE)
      .describe(
        'Maximum items to return; values above 30 use 30 when input clamping is enabled. The upstream window contains at most 30 items.',
      ),
    cursor: z
      .string()
      .optional()
      .describe(
        'Opaque continuation cursor from this feed. Resumes after the last returned GUID within the available window; omit to restart.',
      ),
    since: CalendarDateInputSchema.optional().describe(
      'Keep only items published on or after this date, YYYY-MM-DD. Filters within the fetched window; it cannot reach back beyond it.',
    ),
  }),

  output: z.object({
    hasMore: z
      .boolean()
      .describe('Whether more matching items remain after this page within the available window.'),
    cursor: z
      .string()
      .optional()
      .describe(
        'Continuation cursor for this feed; absent on the last page or when the anchor is unavailable.',
      ),
    stale: z
      .boolean()
      .describe('True when refresh failed and this response uses the last cached window.'),
    fetchedAt: z.string().describe('UTC timestamp when this window was successfully fetched.'),
    feed: z.enum(['advisories', 'alerts', 'ics']).describe('The feed that was read.'),
    feedUrl: z.string().describe('The absolute feed URL this window came from.'),
    feedTitle: z.string().describe('The channel title the feed declares.'),
    items: z
      .array(
        z
          .object({
            title: z
              .string()
              .describe('Item title, trimmed — upstream carries trailing whitespace.'),
            link: z.string().describe('Absolute URL of the canonical page for the item.'),
            pubDate: z
              .string()
              .describe(
                'Publication timestamp, ISO 8601. Upstream publishes RFC 822 with a two-digit year.',
              ),
            summary: z
              .string()
              .describe(
                'Item description with HTML stripped and entities decoded, capped at 1,200 characters.',
              ),
            summaryTruncated: z.boolean().describe('True when the summary was capped.'),
            guid: z
              .string()
              .describe(
                'The upstream guid — a node path such as /node/25513, not a URL and not a permalink.',
              ),
            advisoryId: z
              .string()
              .regex(ADVISORY_ID_PATTERN)
              .optional()
              .describe('Present for ICS advisory items; chains straight into cisa_get_advisory.'),
          })
          .describe('One feed item.'),
      )
      .describe(
        'Items from the fetched window, newest first as published; stale identifies cached fallback.',
      ),
    window: z
      .object({
        itemCount: z.number().int().describe('Items returned after limit and since were applied.'),
        oldest: z
          .string()
          .nullable()
          .describe('Publication date of the oldest item in the fetched window; null when empty.'),
        newest: z
          .string()
          .nullable()
          .describe('Publication date of the newest item in the fetched window; null when empty.'),
        upstreamWindowSize: z
          .number()
          .int()
          .describe('Items the upstream feed serves — a fixed ceiling, not a server choice.'),
      })
      .describe('What the fetched window covers.'),
  }),

  enrichment: {
    windowCaveat: z.string().describe('Limits of continuation within the upstream rolling window.'),
    effectiveQuery: z
      .string()
      .optional()
      .describe('The since filter as applied, and how many window items it excluded.'),
    truncated: z.boolean().optional().describe('True when the limit capped the returned items.'),
    shown: z.number().int().optional().describe('Items returned.'),
    cap: z.number().int().optional().describe('The limit that was applied.'),
    notice: z
      .string()
      .optional()
      .describe(
        'Safe retry guidance on refresh failure, or guidance when the since filter excluded every item.',
      ),
  },

  enrichmentTrailer: {
    windowCaveat: { label: 'Window' },
  },

  errors: [
    {
      reason: 'read_limit_exceeded',
      code: JsonRpcErrorCode.ValidationError,
      when: 'limit exceeds the per-call cap and input clamping is disabled.',
      retryable: false,
      thrownBy: 'service',
      recovery:
        'Send limit at most 30; this feed cannot expose history beyond its available window.',
    },
    {
      reason: 'invalid_cursor',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'The cursor is malformed or belongs to a different feed.',
      retryable: false,
      recovery:
        'Omit cursor to restart, or pass the cursor from the previous response with the same feed.',
    },
    {
      reason: 'feed_unavailable',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'The feed fetch failed or returned a body that carried no RSS channel.',
      retryable: true,
      recovery:
        'The CISA feed is unreachable; retry in a few minutes, or use cisa_search_ics_advisories for ICS advisory history, which serves from a local index.',
      thrownBy: 'service',
    },
  ],

  async handler(input, ctx) {
    const limit = applyReadLimit('cisa_get_alerts', input.limit, ctx);
    const decoded = input.cursor === undefined ? undefined : parseFeedCursor(input.cursor);
    if (input.cursor !== undefined && decoded?.feed !== input.feed)
      throw ctx.fail('invalid_cursor', 'The continuation cursor is invalid for this feed.');
    const anchorGuid = decoded?.guid;
    const window = await getCisaFeeds().window(input.feed, ctx);
    const anchorIndex =
      anchorGuid === undefined ? -1 : window.items.findIndex((item) => item.guid === anchorGuid);
    const anchorUnavailable = anchorGuid !== undefined && anchorIndex === -1;
    const remaining = anchorUnavailable ? [] : window.items.slice(anchorIndex + 1);
    const filtered = input.since
      ? remaining.filter((item) => item.pubDate.slice(0, 10) >= (input.since as string))
      : remaining;
    const items = filtered.slice(0, limit);
    const hasMore = items.length < filtered.length;
    const last = items.at(-1);

    ctx.log.info('Read a CISA feed window', {
      feed: input.feed,
      fetched: window.items.length,
      returned: items.length,
    });

    ctx.enrich({ windowCaveat: WINDOW_CAVEAT });

    if (input.since) {
      ctx.enrich.echo(
        `since=${input.since} (excluded ${remaining.length - filtered.length} of ${remaining.length} window items${anchorGuid === undefined ? '' : ' after the resume point'})`,
      );
    }
    const notices: string[] = [];
    if (hasMore) {
      notices.push(
        `Results capped at ${limit}; showing ${items.length}. Follow the cursor for more items within this window.`,
      );
      ctx.enrich.truncated({ shown: items.length, cap: limit, guidance: notices.join(' ') });
    }
    if (anchorUnavailable)
      notices.push(
        `The continuation anchor is unavailable in this ${window.stale ? 'cached' : 'current'} window.${window.oldest ? ` The window's oldest item is ${window.oldest}.` : ' The window is empty.'} Restart without a cursor to read the available window.`,
      );
    if (window.stale)
      notices.push(
        'The feed refresh failed; this cached window may omit newer publications. Retry in a few minutes, or use cisa_search_ics_advisories for ICS advisory history.',
      );
    if (input.since && filtered.length === 0 && !anchorUnavailable) {
      notices.push(
        `No item in the ${window.stale ? 'cached' : 'current'} 30-item window${anchorGuid === undefined ? '' : ' after the continuation anchor'} is on or after ${input.since}.${window.stale ? ' Refresh failed, so this does not establish current publication absence; retry in a few minutes.' : ''} The window's oldest item is ${
          window.oldest ?? 'unknown'
        }; anything earlier is not in this feed.`,
      );
    }
    if (notices.length > 0) ctx.enrich.notice(notices.join(' '));

    return {
      hasMore,
      ...(hasMore && last
        ? {
            cursor: Buffer.from(JSON.stringify({ feed: input.feed, guid: last.guid })).toString(
              'base64url',
            ),
          }
        : {}),
      stale: window.stale,
      fetchedAt: window.fetchedAt,
      feed: window.feed,
      feedUrl: window.feedUrl,
      feedTitle: window.feedTitle,
      items,
      window: {
        itemCount: items.length,
        oldest: window.oldest,
        newest: window.newest,
        upstreamWindowSize: UPSTREAM_WINDOW_SIZE,
      },
    };
  },

  format: (result) => {
    const lines: string[] = [
      `# ${result.feedTitle || result.feed}`,
      `**Feed:** ${result.feed} · **Source:** ${result.feedUrl}`,
      `**Fetched:** ${result.fetchedAt} · **Stale:** ${result.stale ? 'yes — refresh failed; newer publications may be missing. Retry in a few minutes.' : 'no'}`,
      `**More available:** ${result.hasMore ? 'yes' : 'no'}`,
      ...(result.cursor ? [`**Next cursor:** ${result.cursor}`] : []),
      `**Window:** ${result.window.itemCount} item(s) shown, covering ${
        result.window.oldest ?? 'unknown'
      } → ${result.window.newest ?? 'unknown'} out of an upstream window of ${result.window.upstreamWindowSize}.`,
      '',
    ];
    for (const item of result.items) {
      lines.push(`### ${item.title}`);
      lines.push(`**Published:** ${item.pubDate} · **Link:** ${item.link}`);
      lines.push(`**guid (upstream node path):** ${item.guid}`);
      if (item.advisoryId) lines.push(`**Advisory ID:** ${item.advisoryId}`);
      lines.push(item.summary);
      lines.push(`**Summary truncated:** ${item.summaryTruncated ? 'yes' : 'no'}`);
      lines.push('');
    }
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
