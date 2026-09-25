/**
 * @fileoverview `cisa_search_kev` — filtered search over the cached KEV catalog
 * snapshot. Every filter is applied against the complete snapshot, never a page,
 * and the result is paged with an opaque cursor.
 * @module mcp-server/tools/definitions/search-kev.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { extractCursor, paginateArray } from '@cyanheads/mcp-ts-core/utils';
import {
  CweIdInputSchema,
  ISO_DATE_REGEX,
  KevRecordSchema,
  renderKevRecord,
  toKevRecordOutput,
} from '@/mcp-server/schemas/kev-record.js';
import {
  getKevCatalog,
  type KevFilterCount,
  type KevFilterKey,
  type KevSearchFilters,
  queryTokens,
} from '@/services/kev-catalog/kev-catalog-service.js';
import type { KevRecord } from '@/services/kev-catalog/types.js';

const MAX_PAGE_SIZE = 100;

export const searchKevTool = tool('cisa_search_kev', {
  title: 'cisa_search_kev',
  description:
    'Search the CISA Known Exploited Vulnerabilities catalog across every entry in the cached snapshot. Filter by vendor or product using CISA\'s own labels, by name substring, by CWE, by the date an entry was added, by due date, by overdue status, by ransomware linkage, by the three-day forensic-triage tier, or by which binding operational directive the entry cites. Results are paged and sortable by due date or date added. Vendor and product values are CISA\'s free-text labels, not CPE names — call cisa_list_reference for the field vocabulary before guessing one. The catalog records additions but carries no per-record modified timestamp, so dateAddedFrom answers "what is new since D" while a revised due date on an existing entry is not detectable from the feed.',
  annotations: { readOnlyHint: true, idempotentHint: true },

  input: z.object({
    vendorProject: z
      .string()
      .min(2)
      .optional()
      .describe("Case-insensitive substring of CISA's own vendor label."),
    product: z
      .string()
      .min(2)
      .optional()
      .describe("Case-insensitive substring of CISA's own product label."),
    nameContains: z
      .string()
      .min(2)
      .optional()
      .describe(
        'Strict token match over the vulnerability name and short description: every token must appear. Matching folds case and accents and keeps only the letters a-z and the digits 0-9; a word carrying any other letter or digit, such as one in another script, loses those characters and the response names it, and a value left with none of them is rejected. No fuzzy fallback.',
      ),
    cwe: CweIdInputSchema.optional().describe(
      'Exact CWE identifier, e.g. CWE-362. Case and surrounding whitespace are normalized. Entries with no CWEs never match.',
    ),
    cveIdPrefix: z
      .string()
      .trim()
      .toUpperCase()
      .regex(/^CVE-[0-9]{4}$/)
      .optional()
      .describe(
        'Year scope for the CVE ID, e.g. CVE-2026. Case and surrounding whitespace are normalized.',
      ),
    dateAddedFrom: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Earliest date added, inclusive, YYYY-MM-DD.'),
    dateAddedTo: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Latest date added, inclusive, YYYY-MM-DD.'),
    dueBefore: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Latest due date, inclusive, YYYY-MM-DD.'),
    dueAfter: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Earliest due date, inclusive, YYYY-MM-DD.'),
    overdue: z
      .boolean()
      .optional()
      .describe('True selects entries whose due date is strictly before the echoed asOf date.'),
    ransomware: z
      .boolean()
      .optional()
      .describe('True selects entries CISA has linked to ransomware campaigns.'),
    forensicTriage: z
      .boolean()
      .optional()
      .describe('True selects the BOD 26-04 three-day forensic-triage tier.'),
    directive: z
      .enum(['BOD 26-04', 'BOD 22-01', 'none'])
      .optional()
      .describe('Which directive the entry cites. "none" selects the entries citing neither.'),
    sortBy: z.enum(['dueDate', 'dateAdded']).default('dateAdded').describe('Field to sort by.'),
    order: z.enum(['asc', 'desc']).default('desc').describe('Sort direction.'),
    limit: z
      .number()
      .int()
      .min(1)
      .max(MAX_PAGE_SIZE)
      .default(25)
      .describe('Maximum entries per page.'),
    cursor: z
      .string()
      .optional()
      .describe('Opaque pagination cursor from a previous call. Omit for the first page.'),
  }),

  output: z.object({
    results: z.array(KevRecordSchema).describe('Matching KEV entries for this page.'),
    cursor: z
      .string()
      .optional()
      .describe('Opaque cursor for the next page. Absent when this is the last page.'),
    hasMore: z.boolean().describe('Whether more matches exist beyond this page.'),
  }),

  enrichment: {
    totalCount: z.number().int().describe('Total matches before paging.'),
    truncated: z.boolean().optional().describe('True when the page limit capped this result.'),
    shown: z.number().int().optional().describe('Entries returned on this page.'),
    cap: z.number().int().optional().describe('The page limit that was applied.'),
    catalog: z
      .object({
        catalogVersion: z.string().describe('Version string of the loaded catalog snapshot.'),
        dateReleased: z.string().describe('Release timestamp the snapshot carries.'),
        count: z.number().int().describe('Entries in the loaded snapshot.'),
        fetchedAt: z.string().describe('When this server fetched the snapshot, ISO 8601.'),
      })
      .describe('Which catalog snapshot answered this call.'),
    asOf: z
      .string()
      .describe('The UTC date overdue and daysUntilDue were computed against, YYYY-MM-DD.'),
    appliedFilters: z
      .record(z.string(), z.string().describe('The filter value as the server parsed it.'))
      .describe('The filters the server actually applied, as it parsed them.'),
    snapshotCaveat: z
      .string()
      .optional()
      .describe('Disclosure that additions are queryable but revisions are not detectable.'),
    notice: z
      .string()
      .optional()
      .describe(
        'Guidance when nothing matched, when a page was capped, or when nameContains dropped characters it cannot match.',
      ),
  },

  enrichmentTrailer: {
    catalog: {
      render: (catalog) =>
        `**Catalog:** ${catalog.catalogVersion} (released ${catalog.dateReleased}, ${catalog.count} entries, fetched ${catalog.fetchedAt})`,
    },
    appliedFilters: {
      render: (filters) => {
        const entries = Object.entries(filters);
        return entries.length === 0
          ? '**Applied filters:** none'
          : `**Applied filters:** ${entries.map(([key, value]) => `${key}=${value}`).join(', ')}`;
      },
    },
    asOf: { label: 'As of' },
    snapshotCaveat: { label: 'Snapshot caveat' },
  },

  errors: [
    {
      reason: 'catalog_unavailable',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'No KEV catalog snapshot is held and the fetch from cisa.gov failed.',
      retryable: true,
      recovery:
        'The KEV catalog snapshot is not loaded yet; retry in a few seconds, or call cisa_list_reference with topic sources to see the current catalog state.',
      thrownBy: 'service',
    },
    {
      reason: 'invalid_date_range',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A From bound is later than its matching To bound.',
      recovery:
        'Swap the range bounds so the From date is not later than the To date, then call this tool again.',
    },
    {
      reason: 'empty_search_text',
      code: JsonRpcErrorCode.ValidationError,
      when: 'nameContains holds no letter a-z or digit 0-9 once case and accents are folded and punctuation is removed, so there is nothing to search for.',
      recovery:
        'Put at least one word or number in nameContains that uses the letters a-z, accented or not, or the digits 0-9, such as a product or vulnerability term, or omit nameContains to search by the other filters alone.',
      thrownBy: 'service',
    },
  ],

  async handler(input, ctx) {
    if (input.dateAddedFrom && input.dateAddedTo && input.dateAddedFrom > input.dateAddedTo) {
      throw ctx.fail(
        'invalid_date_range',
        `dateAddedFrom ${input.dateAddedFrom} is later than dateAddedTo ${input.dateAddedTo}.`,
        { ...ctx.recoveryFor('invalid_date_range') },
      );
    }
    if (input.dueAfter && input.dueBefore && input.dueAfter > input.dueBefore) {
      throw ctx.fail(
        'invalid_date_range',
        `dueAfter ${input.dueAfter} is later than dueBefore ${input.dueBefore}.`,
        { ...ctx.recoveryFor('invalid_date_range') },
      );
    }

    const catalog = getKevCatalog();
    const filters: KevSearchFilters = {
      vendorProject: input.vendorProject,
      product: input.product,
      nameContains: input.nameContains,
      cwe: input.cwe,
      cveIdPrefix: input.cveIdPrefix,
      dateAddedFrom: input.dateAddedFrom,
      dateAddedTo: input.dateAddedTo,
      dueBefore: input.dueBefore,
      dueAfter: input.dueAfter,
      overdue: input.overdue,
      ransomware: input.ransomware,
      forensicTriage: input.forensicTriage,
      directive: input.directive,
    };

    const snapshot = await catalog.snapshot(ctx);
    const asOf = catalog.asOf();
    const matched = await catalog.search(filters, input.sortBy, input.order, ctx);
    const page = paginateArray(
      matched,
      extractCursor({ ...(input.cursor ? { cursor: input.cursor } : {}) }),
      input.limit,
      MAX_PAGE_SIZE,
      ctx,
    );

    ctx.log.info('Searched the KEV catalog', { matched: matched.length, shown: page.items.length });

    const applied: Record<string, string> = {};
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined) applied[key] = String(value);
    }
    applied.sortBy = input.sortBy;
    applied.order = input.order;
    applied.limit = String(input.limit);

    ctx.enrich({
      catalog: {
        catalogVersion: snapshot.catalogVersion,
        dateReleased: snapshot.dateReleased,
        count: snapshot.count,
        fetchedAt: snapshot.fetchedAt,
      },
      asOf,
      appliedFilters: applied,
    });
    ctx.enrich.total(matched.length);

    if (input.dateAddedFrom) {
      ctx.enrich({
        snapshotCaveat:
          'Additions are queryable by dateAdded. The KEV feed carries no per-record modified timestamp, so an entry whose dueDate or requiredAction changed after it was added is indistinguishable from an unchanged one. This result covers additions in the window, not revisions.',
      });
    }

    /* `notice` is last-wins across enrich calls, `truncated()` included, so every
     * notice source is collected here and written once. */
    const notices: string[] = [];
    if (filters.nameContains) {
      const { tokens, dropped } = queryTokens(filters.nameContains);
      if (dropped.length > 0) {
        notices.push(
          `nameContains dropped the characters of ${dropped.map((word) => `"${word}"`).join(', ')} outside the letters a-z and the digits 0-9 — matching folds case and accents and keeps only those, so the dropped characters can never match. Searched for: ${tokens.join(' ')}.`,
        );
      }
    }
    if (matched.length === 0) {
      const counts = await catalog.filterCounts(filters, ctx);
      notices.push(zeroHitNotice(filters, counts, snapshot.records, asOf));
    }

    if (page.items.length >= input.limit && page.nextCursor) {
      const shown = page.items.length;
      ctx.enrich.truncated({
        shown,
        cap: input.limit,
        ...(notices.length > 0
          ? {
              guidance: [
                `Results capped at ${input.limit}; showing ${shown}. Raise the cap or narrow with filters.`,
                ...notices,
              ].join(' '),
            }
          : {}),
      });
    } else if (notices.length > 0) {
      ctx.enrich.notice(notices.join(' '));
    }

    return {
      results: page.items.map((record) => toKevRecordOutput(record, asOf)),
      ...(page.nextCursor ? { cursor: page.nextCursor } : {}),
      hasMore: page.nextCursor !== undefined,
    };
  },

  format: (result) => {
    const lines: string[] = [
      `**${result.results.length} KEV entries on this page** (more available: ${result.hasMore ? 'yes' : 'no'}).`,
    ];
    if (result.cursor) lines.push(`**Next cursor:** \`${result.cursor}\``);
    lines.push('');
    for (const record of result.results) lines.push(...renderKevRecord(record), '');
    return [{ type: 'text', text: lines.join('\n') }];
  },
});

/** A count as prose, thousands-grouped. */
const formatCount = (count: number) => count.toLocaleString('en-US');

/** A filter as the caller set it, e.g. `cveIdPrefix=CVE-2099`. */
const setAs = (filters: KevSearchFilters, key: KevFilterKey) => `${key}=${String(filters[key])}`;

/**
 * The dateAdded range of the entries citing a directive, or `undefined` when no
 * entry cites it.
 */
function directiveWindow(
  records: KevRecord[],
  directive: NonNullable<KevSearchFilters['directive']>,
): { first: string; last: string } | undefined {
  const wanted = directive === 'none' ? null : directive;
  const added = records
    .filter((record) => record.directive === wanted)
    .map((record) => record.dateAdded)
    .sort();
  const [first] = added;
  const last = added.at(-1);
  return first && last ? { first, last } : undefined;
}

/**
 * Explain a zero-hit search from the per-filter counts. A filter that matches no
 * entry on its own is named — with the free-text-label or empty-cwes fragment for
 * vendor/product and cwe — and, when it is the only one, so is what dropping it
 * restores, which is nothing when the other filters also miss together. When
 * every filter matches on its own, the combination is the miss: each filter
 * whose removal restores results is named with that count. The directive-window and overdue/dueAfter fragments read the loaded
 * snapshot and the echoed asOf date, never a fixed threshold or the wall clock.
 */
function zeroHitNotice(
  filters: KevSearchFilters,
  counts: KevFilterCount[],
  records: KevRecord[],
  asOf: string,
): string {
  const fragments: string[] = [];
  const unmatchedCounts = counts.filter((count) => count.alone === 0);
  const unmatched = unmatchedCounts.map((count) => count.filter);

  const labels = unmatched.filter((key) => key === 'vendorProject' || key === 'product');
  if (labels.length > 0) {
    fragments.push(
      `${labels.map((key) => setAs(filters, key)).join(' and ')} ${labels.length === 1 ? 'matches no entry on its own' : 'each match no entry on their own'}. Vendor and product are CISA's own free-text labels, not CPE names — call cisa_list_reference with topic kev_fields for the value domain, or drop the ${labels.length === 1 ? 'filter' : 'filters'} and match on nameContains instead.`,
    );
  }
  if (unmatched.includes('cwe')) {
    const emptyCwes = records.filter((record) => record.cwes.length === 0).length;
    fragments.push(
      `No KEV entry carries ${filters.cwe}. ${formatCount(emptyCwes)} of ${formatCount(records.length)} entries carry an empty cwes array, so a CWE filter excludes them regardless of relevance.`,
    );
  }
  const others = unmatched.filter(
    (key) => key !== 'vendorProject' && key !== 'product' && key !== 'cwe',
  );
  if (others.length > 0) {
    fragments.push(
      `${others.map((key) => setAs(filters, key)).join(', ')} ${others.length === 1 ? 'matches no entry on its own — relax or drop it.' : 'each match no entry on their own — relax or drop them.'}`,
    );
  }
  /* Every entry fails a filter that matches nothing, so what dropping it restores
   * is exactly what the other filters match together — often nothing. */
  const [onlyUnmatched] = unmatchedCounts;
  if (onlyUnmatched && unmatchedCounts.length === 1 && counts.length > 1) {
    const restored = onlyUnmatched.restoredByDropping;
    fragments.push(
      restored > 0
        ? `Dropping ${onlyUnmatched.filter} restores ${formatCount(restored)} ${restored === 1 ? 'entry' : 'entries'}.`
        : `Dropping ${onlyUnmatched.filter} alone restores nothing: the other filters match no entry together either.`,
    );
  }

  if (filters.overdue === true && filters.dueAfter && filters.dueAfter >= asOf) {
    fragments.push(
      `overdue and dueAfter are contradictory as given: overdue selects due dates before ${asOf}, and dueAfter=${filters.dueAfter} excludes all of them — relax one.`,
    );
  }
  if (filters.directive && (filters.dateAddedFrom || filters.dateAddedTo)) {
    const window = directiveWindow(records, filters.directive);
    if (
      window &&
      ((filters.dateAddedTo && filters.dateAddedTo < window.first) ||
        (filters.dateAddedFrom && filters.dateAddedFrom > window.last))
    ) {
      fragments.push(
        `Entries citing ${filters.directive === 'none' ? 'no directive' : filters.directive} were added from ${window.first} through ${window.last}; the dateAdded window falls outside that range.`,
      );
    }
  }

  if (unmatched.length === 0 && counts.length > 1) {
    const restorers = counts.filter((count) => count.restoredByDropping > 0);
    fragments.push(
      restorers.length > 0
        ? `Every filter matches entries on its own; ${restorers
            .map(
              (count) =>
                `dropping ${count.filter} restores ${formatCount(count.restoredByDropping)} ${count.restoredByDropping === 1 ? 'entry' : 'entries'}`,
            )
            .join(', ')}.`
        : 'Every filter matches entries on its own, but no single filter explains the miss — only relaxing two or more of them together restores a result.',
    );
  }

  if (fragments.length === 0) {
    fragments.push(
      'The loaded KEV catalog snapshot holds no entries. Call cisa_list_reference with topic sources to check its state.',
    );
  }
  return fragments.join(' ');
}
