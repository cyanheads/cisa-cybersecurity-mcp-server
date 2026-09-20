/**
 * @fileoverview `cisa_get_alerts` — the current rolling window of one CISA
 * publication feed. Each feed is exactly 30 items with no history, no
 * pagination, and no server-side date query, so every response says so.
 * @module mcp-server/tools/definitions/get-alerts.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { ISO_DATE_REGEX } from '@/mcp-server/schemas/kev-record.js';
import { getCisaFeeds, UPSTREAM_WINDOW_SIZE } from '@/services/cisa-feeds/cisa-feeds-service.js';
import { ADVISORY_ID_PATTERN } from '@/services/csaf-mirror/normalize.js';

const WINDOW_CAVEAT =
  'This feed is a rolling window of the 30 most recent items. There is no history, no pagination, and no server-side date filter; anything older than the oldest item shown is unreachable from this feed. For ICS advisory history use cisa_search_ics_advisories.';

export const getAlertsTool = tool('cisa_get_alerts', {
  title: 'cisa_get_alerts',
  description:
    "List what CISA has published recently — its combined advisory feed, its alerts feed, or its ICS advisory feed. Each feed is a rolling window of exactly 30 items with no history, no pagination, and no date-range query, so the window's coverage varies from about a week to about two months depending on the feed. For ICS advisory history beyond the window, use cisa_search_ics_advisories, which covers the full corpus back to 2010.",
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
      .max(UPSTREAM_WINDOW_SIZE)
      .default(UPSTREAM_WINDOW_SIZE)
      .describe(
        'Maximum items to return. The 30 ceiling is the upstream window, not a server choice.',
      ),
    since: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe(
        'Keep only items published on or after this date, YYYY-MM-DD. Filters within the fetched window; it cannot reach back beyond it.',
      ),
  }),

  output: z.object({
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
      .describe('Items from the current window, newest first as published.'),
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
    windowCaveat: z
      .string()
      .describe('That the feed has no history, no pagination, and no date query.'),
    effectiveQuery: z
      .string()
      .optional()
      .describe('The since filter as applied, and how many window items it excluded.'),
    truncated: z.boolean().optional().describe('True when the limit capped the returned items.'),
    shown: z.number().int().optional().describe('Items returned.'),
    cap: z.number().int().optional().describe('The limit that was applied.'),
    notice: z.string().optional().describe('Guidance when the since filter excluded every item.'),
  },

  enrichmentTrailer: {
    windowCaveat: { label: 'Window' },
  },

  errors: [
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
    const window = await getCisaFeeds().window(input.feed, ctx);

    const filtered = input.since
      ? window.items.filter((item) => item.pubDate.slice(0, 10) >= (input.since as string))
      : window.items;
    const items = filtered.slice(0, input.limit);

    ctx.log.info('Read a CISA feed window', {
      feed: input.feed,
      fetched: window.items.length,
      returned: items.length,
    });

    ctx.enrich({ windowCaveat: WINDOW_CAVEAT });

    if (input.since) {
      ctx.enrich.echo(
        `since=${input.since} (excluded ${window.items.length - filtered.length} of ${window.items.length} window items)`,
      );
    }
    if (items.length < filtered.length) {
      ctx.enrich.truncated({ shown: items.length, cap: input.limit });
    }
    if (input.since && filtered.length === 0) {
      ctx.enrich.notice(
        `No item in the current 30-item window is on or after ${input.since}. The window's oldest item is ${
          window.oldest ?? 'unknown'
        }; anything earlier is not in this feed.`,
      );
    }

    return {
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
