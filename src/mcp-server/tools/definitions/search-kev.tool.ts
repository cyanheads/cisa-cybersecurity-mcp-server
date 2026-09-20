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
  ISO_DATE_REGEX,
  KevRecordSchema,
  renderKevRecord,
  toKevRecordOutput,
} from '@/mcp-server/schemas/kev-record.js';
import {
  getKevCatalog,
  type KevSearchFilters,
} from '@/services/kev-catalog/kev-catalog-service.js';

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
      .describe("Case-insensitive substring of CISA's own vendor label. 283 distinct values."),
    product: z
      .string()
      .min(2)
      .optional()
      .describe("Case-insensitive substring of CISA's own product label. 694 distinct values."),
    nameContains: z
      .string()
      .min(2)
      .optional()
      .describe(
        'Strict token match over the vulnerability name and short description: every token must appear. No fuzzy fallback.',
      ),
    cwe: z
      .string()
      .regex(/^CWE-[0-9]+$/)
      .optional()
      .describe('Exact CWE identifier, e.g. CWE-362. Excludes the 175 entries with no CWEs.'),
    cveIdPrefix: z
      .string()
      .regex(/^CVE-[0-9]{4}$/)
      .optional()
      .describe('Year scope for the CVE ID, e.g. CVE-2026.'),
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
      .describe('True selects entries CISA has linked to ransomware campaigns (360 entries).'),
    forensicTriage: z
      .boolean()
      .optional()
      .describe('True selects the BOD 26-04 three-day forensic-triage tier (58 entries).'),
    directive: z
      .enum(['BOD 26-04', 'BOD 22-01', 'none'])
      .optional()
      .describe(
        'Which directive the entry cites. "none" selects the 1,277 entries citing neither.',
      ),
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
    notice: z.string().optional().describe('Guidance when nothing matched.'),
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

    if (page.items.length >= input.limit && page.nextCursor) {
      ctx.enrich.truncated({ shown: page.items.length, cap: input.limit });
    }

    if (matched.length === 0) {
      ctx.enrich.notice(zeroHitNotice(input));
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

/** Compose the zero-hit notice from whichever filter most plausibly explains the miss. */
function zeroHitNotice(input: {
  cwe?: string | undefined;
  dateAddedTo?: string | undefined;
  directive?: string | undefined;
  dueAfter?: string | undefined;
  overdue?: boolean | undefined;
  product?: string | undefined;
  vendorProject?: string | undefined;
}): string {
  const fragments: string[] = [];

  if (input.vendorProject || input.product) {
    fragments.push(
      "Vendor and product are CISA's own free-text labels, not CPE names — call cisa_list_reference with topic kev_fields for the value domain, or drop the filter and match on nameContains instead.",
    );
  }
  if (input.cwe) {
    fragments.push(
      'No KEV entry carries that CWE. 175 of 1,716 entries carry an empty cwes array, so a CWE filter excludes them regardless of relevance.',
    );
  }
  if (input.directive === 'BOD 26-04' && input.dateAddedTo && input.dateAddedTo < '2026-01-01') {
    fragments.push(
      'BOD 26-04 entries begin in 2026; earlier entries cite BOD 22-01 or no directive at all.',
    );
  }
  if (
    input.overdue === true &&
    input.dueAfter &&
    input.dueAfter > new Date().toISOString().slice(0, 10)
  ) {
    fragments.push('overdue and dueAfter are contradictory as given — relax one.');
  }
  if (fragments.length === 0) {
    fragments.push(
      'No KEV entry matches. Relax the narrowest filter, or call cisa_check_cve_status if you already have specific CVE IDs.',
    );
  }
  return fragments.join(' ');
}
