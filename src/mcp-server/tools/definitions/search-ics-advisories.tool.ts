/**
 * @fileoverview `cisa_search_ics_advisories` — filtered and full-text search over
 * the local index of the CSAF ICS advisory corpus.
 *
 * KEV membership joins the in-memory KEV snapshot to the index's CVE junction.
 * It is best-effort unless the caller asks about KEV: `inKev` waits on the
 * snapshot and fails retryably without it, but a search without `inKev` reads
 * only a snapshot already in memory — a KEV outage never fails, and never
 * stalls, an advisory search that did not ask about KEV. Such a result omits
 * `kevCves` and says so.
 * @module mcp-server/tools/definitions/search-ics-advisories.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { decodeCursor, encodeCursor } from '@cyanheads/mcp-ts-core/utils';
import {
  CveIdInputSchema,
  CweIdInputSchema,
  ISO_DATE_REGEX,
} from '@/mcp-server/schemas/kev-record.js';
import { SEVERITY_BANDS } from '@/reference/cvss.js';
import { SECTOR_FILTER_VALUES } from '@/reference/sectors.js';
import { getCsafMirror } from '@/services/csaf-mirror/csaf-mirror-service.js';
import { ADVISORY_ID_PATTERN } from '@/services/csaf-mirror/normalize.js';
import type {
  AdvisoryFilterCount,
  AdvisoryFilterKey,
  AdvisorySearchFilters,
} from '@/services/csaf-mirror/types.js';
import { getKevCatalog } from '@/services/kev-catalog/kev-catalog-service.js';

const MAX_PAGE_SIZE = 50;

export const searchIcsAdvisoriesTool = tool('cisa_search_ics_advisories', {
  title: 'cisa_search_ics_advisories',
  description:
    'Search the CISA industrial control system advisory corpus — every CSAF 2.0 advisory covering PLC, HMI, SCADA, building-automation, and medical-device products from 2010 onward. Filter by vendor, product, CVE, CWE, CVSS range, severity band, critical-infrastructure sector, advisory series, publication date, revision date, or whether an advisory covers a CVE in the CISA Known Exploited Vulnerabilities catalog, and run full-text search over advisory titles and product names. Sector filtering reaches only advisories that carry a sector note, which begins in 2017; the response reports how many documents a sector filter can never match. Returns advisory IDs for cisa_get_advisory, the CVEs each advisory covers and which of them are in KEV, and the source URL and attribution every advisory response carries.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    q: z
      .string()
      .min(2)
      .optional()
      .describe(
        'Full-text search over advisory titles, vendor names, and product names. Tokens are AND-combined; FTS5 operators in the input are neutralized rather than honored, and a token with no letter or digit is ignored. Needs at least one word or number.',
      ),
    vendor: z
      .string()
      .min(2)
      .optional()
      .describe(
        'Case-insensitive substring of a vendor label, matched literally — % and _ are ordinary characters. Vendor names are unnormalized upstream — the same company appears under several spellings — so this is substring, not exact.',
      ),
    product: z
      .string()
      .min(2)
      .optional()
      .describe(
        'Case-insensitive substring of a product name, matched literally — % and _ are ordinary characters.',
      ),
    cve: CveIdInputSchema.optional().describe(
      'Exact CVE membership, e.g. CVE-2021-44228. Case and surrounding whitespace are normalized.',
    ),
    cwe: CweIdInputSchema.optional().describe(
      'Exact CWE identifier, e.g. CWE-787, matched against every vulnerability entry in the advisory. Case and surrounding whitespace are normalized. A parent class does not match its children.',
    ),
    inKev: z
      .boolean()
      .optional()
      .describe(
        'true selects advisories covering at least one CVE in the CISA Known Exploited Vulnerabilities catalog; false selects advisories covering none. Checked against every CVE an advisory covers, not only the twenty listed per result.',
      ),
    cvssMin: z
      .number()
      .min(0)
      .max(10)
      .optional()
      .describe("Minimum value of the advisory's maximum CVSS base score, inclusive."),
    cvssMax: z
      .number()
      .min(0)
      .max(10)
      .optional()
      .describe("Maximum value of the advisory's maximum CVSS base score, inclusive."),
    severity: z
      .enum(SEVERITY_BANDS)
      .optional()
      .describe("Severity band of the advisory's maximum CVSS score."),
    sector: z
      .enum(SECTOR_FILTER_VALUES as unknown as [string, ...string[]])
      .optional()
      .describe(
        'Critical-infrastructure sector, matched against the normalized sector set. Multiple is the sentinel the corpus uses for an advisory affecting many sectors.',
      ),
    series: z
      .enum(['ICSA', 'ICSMA'])
      .optional()
      .describe(
        'Advisory series: ICSA industrial control system advisories, or ICSMA medical-device advisories, a small minority of the corpus.',
      ),
    publisher: z
      .enum(['coordinator', 'other'])
      .optional()
      .describe(
        'coordinator selects CISA-authored advisories; other selects vendor advisories CISA republished, over a quarter of the corpus.',
      ),
    publishedFrom: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Earliest initial release date, inclusive, YYYY-MM-DD.'),
    publishedTo: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Latest initial release date, inclusive, YYYY-MM-DD.'),
    revisedFrom: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Earliest current release date, inclusive, YYYY-MM-DD.'),
    revisedTo: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Latest current release date, inclusive, YYYY-MM-DD.'),
    sortBy: z
      .enum(['relevance', 'published', 'revised', 'maxCvss'])
      .default('revised')
      .describe('Field to sort by. relevance requires q and ranks by FTS5 bm25.'),
    order: z
      .enum(['asc', 'desc'])
      .default('desc')
      .describe('Sort direction. Under relevance, desc means most relevant first.'),
    limit: z
      .number()
      .int()
      .min(1)
      .max(MAX_PAGE_SIZE)
      .default(20)
      .describe('Maximum advisories per page.'),
    cursor: z
      .string()
      .optional()
      .describe('Opaque pagination cursor from a previous call. Omit for the first page.'),
  }),

  output: z.object({
    results: z
      .array(
        z
          .object({
            advisoryId: z
              .string()
              .regex(ADVISORY_ID_PATTERN)
              .describe(
                'The advisory identifier, e.g. ICSA-26-260-07. Pass it to cisa_get_advisory.',
              ),
            title: z.string().describe('The advisory title.'),
            series: z.enum(['ICSA', 'ICSMA']).describe('Advisory series.'),
            vendors: z
              .array(z.string().describe('One vendor label.'))
              .describe('Up to ten vendor labels; vendorCount carries the full count.'),
            vendorCount: z.number().int().describe('Distinct vendors named in the product tree.'),
            productCount: z
              .number()
              .int()
              .describe('Flattened product entries in the product tree.'),
            cves: z
              .array(z.string().describe('One CVE identifier.'))
              .describe('Up to twenty CVEs; cveCount carries the full count.'),
            cveCount: z.number().int().describe('Distinct CVEs the advisory covers.'),
            kevCves: z
              .array(z.string().describe('One CVE identifier.'))
              .optional()
              .describe(
                'Every CVE this advisory covers that is in the KEV catalog, drawn from its full CVE list rather than the twenty in cves. Empty when none is; absent when KEV membership could not be evaluated.',
              ),
            maxCvss: z
              .object({
                score: z.number().describe('Highest CVSS base score in the advisory.'),
                severity: z.enum(SEVERITY_BANDS).describe('Severity band for that score.'),
                version: z.string().describe('CVSS version the highest score was published under.'),
                severityDerived: z
                  .boolean()
                  .describe(
                    'True when the band was derived from a CVSS v2 score rather than published upstream.',
                  ),
              })
              .optional()
              .describe(
                'Highest CVSS score across the advisory. Absent when the advisory carries no CVSS score.',
              ),
            sectors: z
              .array(z.string().describe('One canonical sector name.'))
              .describe('Normalized sector names. Empty when the advisory carries no sector note.'),
            sectorsRaw: z
              .string()
              .optional()
              .describe('The sector note verbatim, when the advisory carries one.'),
            published: z.string().describe('Initial release date, ISO 8601.'),
            revised: z.string().describe('Current release date, ISO 8601.'),
            revision: z.string().describe('Document revision number.'),
            publisherCategory: z
              .string()
              .describe('coordinator for CISA-authored, other for a republished vendor advisory.'),
            url: z.string().describe('Absolute URL of the cisa.gov web version of the advisory.'),
            csafUrl: z.string().describe('Absolute URL of the raw CSAF JSON document.'),
            attribution: z
              .string()
              .describe('Who authored the text and under what terms it may be redistributed.'),
          })
          .describe('One matching advisory.'),
      )
      .describe('Matching advisories for this page.'),
    cursor: z
      .string()
      .optional()
      .describe('Opaque cursor for the next page. Absent when this is the last page.'),
    hasMore: z.boolean().describe('Whether more matches exist beyond this page.'),
  }),

  enrichment: {
    totalCount: z.number().int().describe('Total matches before paging.'),
    truncated: z.boolean().optional().describe('True when the page limit capped this result.'),
    shown: z.number().int().optional().describe('Advisories returned on this page.'),
    cap: z.number().int().optional().describe('The page limit that was applied.'),
    appliedFilters: z
      .record(z.string(), z.string().describe('The filter value as the server parsed it.'))
      .describe('The filters the server actually applied.'),
    mirror: z
      .object({
        documentCount: z.number().int().describe('Advisories held in the local index.'),
        checkpoint: z.string().describe('Newest current_release_date ingested, or "none".'),
        lastRefreshedAt: z.string().describe('When a full sync last completed, or "never".'),
      })
      .describe('Which index state answered this call.'),
    sectorCoverage: z
      .string()
      .optional()
      .describe('Disclosure of how many advisories a sector filter can never match.'),
    cvssCoverage: z
      .string()
      .optional()
      .describe('Disclosure of derived-band and no-score coverage under a score filter.'),
    notice: z
      .string()
      .optional()
      .describe(
        'Guidance when nothing matched — the filter that matches no advisory on its own and what dropping it restores, or the filters whose removal restores results and how many — when a page was capped, when KEV membership was not evaluated, or when a cwe result may be incomplete.',
      ),
  },

  enrichmentTrailer: {
    appliedFilters: {
      render: (filters) => {
        const entries = Object.entries(filters);
        return entries.length === 0
          ? '**Applied filters:** none'
          : `**Applied filters:** ${entries.map(([key, value]) => `${key}=${value}`).join(', ')}`;
      },
    },
    mirror: {
      render: (mirror) =>
        `**Index:** ${mirror.documentCount} advisories, checkpoint ${mirror.checkpoint}, last refreshed ${mirror.lastRefreshedAt}`,
    },
    sectorCoverage: { label: 'Sector coverage' },
    cvssCoverage: { label: 'CVSS coverage' },
  },

  errors: [
    {
      reason: 'mirror_not_ready',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'The advisory index has never completed a full sync.',
      retryable: true,
      recovery:
        'The ICS advisory index is still building; call cisa_list_reference with topic sources to check its progress, then retry this search.',
    },
    {
      reason: 'mirror_unavailable',
      code: JsonRpcErrorCode.ConfigurationError,
      when: 'The advisory index store cannot be opened: its location is not writable, is read-only, runs through a missing directory or a file, or holds a file that is not a SQLite database.',
      recovery:
        'The ICS advisory index cannot be opened at its configured location; the server operator must set CISA_CSAF_MIRROR_PATH to a writable path and restart. Retrying will not help, but cisa_check_cve_status, cisa_search_kev, cisa_get_ssvc, and cisa_get_alerts still work.',
    },
    {
      reason: 'invalid_cvss_range',
      code: JsonRpcErrorCode.ValidationError,
      when: 'cvssMin exceeds cvssMax.',
      recovery: 'Set cvssMin to a value no greater than cvssMax, then call this tool again.',
    },
    {
      reason: 'invalid_date_range',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A From bound is later than its matching To bound.',
      recovery:
        'Swap the range bounds so the From date is not later than the To date, then call this tool again.',
    },
    {
      reason: 'relevance_sort_without_query',
      code: JsonRpcErrorCode.ValidationError,
      when: 'sortBy is relevance but no q was supplied, so there is no bm25 rank to sort by.',
      recovery:
        'Add a q value to sort by relevance, or choose a different sortBy such as revised, published, or maxCvss.',
    },
    {
      reason: 'empty_search_text',
      code: JsonRpcErrorCode.ValidationError,
      when: 'q contains no word or number once quotes and punctuation are removed, so there is nothing to search for.',
      recovery:
        'Put at least one word or number in q, such as a vendor, product, or title term, or omit q to search by filters alone.',
      thrownBy: 'service',
    },
    {
      reason: 'catalog_unavailable',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'inKev is set, no KEV catalog snapshot is held, and the fetch from cisa.gov failed.',
      retryable: true,
      recovery:
        'The KEV catalog snapshot is not loaded yet; retry in a few seconds, drop inKev to search without it, or call cisa_list_reference with topic sources to see the catalog state.',
      thrownBy: 'service',
    },
  ],

  async handler(input, ctx) {
    if (
      input.cvssMin !== undefined &&
      input.cvssMax !== undefined &&
      input.cvssMin > input.cvssMax
    ) {
      throw ctx.fail(
        'invalid_cvss_range',
        `cvssMin ${input.cvssMin} exceeds cvssMax ${input.cvssMax}.`,
        { ...ctx.recoveryFor('invalid_cvss_range') },
      );
    }
    if (input.publishedFrom && input.publishedTo && input.publishedFrom > input.publishedTo) {
      throw ctx.fail(
        'invalid_date_range',
        `publishedFrom ${input.publishedFrom} is later than publishedTo ${input.publishedTo}.`,
        { ...ctx.recoveryFor('invalid_date_range') },
      );
    }
    if (input.revisedFrom && input.revisedTo && input.revisedFrom > input.revisedTo) {
      throw ctx.fail(
        'invalid_date_range',
        `revisedFrom ${input.revisedFrom} is later than revisedTo ${input.revisedTo}.`,
        { ...ctx.recoveryFor('invalid_date_range') },
      );
    }
    if (input.sortBy === 'relevance' && !input.q) {
      throw ctx.fail(
        'relevance_sort_without_query',
        'sortBy relevance needs a q value to rank against.',
        { ...ctx.recoveryFor('relevance_sort_without_query') },
      );
    }

    const mirror = getCsafMirror();
    const availability = await mirror.availability();
    if (availability.status === 'unavailable') {
      throw ctx.fail(
        'mirror_unavailable',
        `The ICS advisory index cannot be opened (${availability.reason.replaceAll('_', ' ')}).`,
        { ...ctx.recoveryFor('mirror_unavailable') },
      );
    }
    if (availability.status === 'not_ready') {
      throw ctx.fail(
        'mirror_not_ready',
        'The ICS advisory index has not completed its first sync.',
        { ...ctx.recoveryFor('mirror_not_ready') },
      );
    }

    const catalog = getKevCatalog();
    const kev = input.inKev === undefined ? catalog.currentSnapshot() : await catalog.snapshot(ctx);
    const kevCves = kev ? new Set(kev.byId.keys()) : undefined;

    const offset = input.cursor ? decodeCursor(input.cursor, ctx).offset : 0;
    const filters: AdvisorySearchFilters = {
      q: input.q,
      vendor: input.vendor,
      product: input.product,
      cve: input.cve,
      cwe: input.cwe,
      inKev: input.inKev,
      cvssMin: input.cvssMin,
      cvssMax: input.cvssMax,
      severity: input.severity,
      sector: input.sector as AdvisorySearchFilters['sector'],
      series: input.series,
      publisher: input.publisher,
      publishedFrom: input.publishedFrom,
      publishedTo: input.publishedTo,
      revisedFrom: input.revisedFrom,
      revisedTo: input.revisedTo,
      sortBy: input.sortBy,
      order: input.order,
      limit: input.limit,
      offset,
    };

    const page = await mirror.search(filters, ctx, kevCves);
    const state = await mirror.state();
    const hasMore = offset + page.items.length < page.total;
    /* Until the ingest-content re-ingest lands, advisory_cwes may be empty or partial. */
    const cweMayBeIncomplete = input.cwe !== undefined && (await mirror.contentState()).stale;

    const applied: Record<string, string> = {};
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined) applied[key] = String(value);
    }
    if (input.inKev !== undefined && kev) applied.kevCatalogVersion = kev.catalogVersion;

    ctx.enrich({
      appliedFilters: applied,
      mirror: {
        documentCount: state.documentCount ?? 0,
        checkpoint: state.checkpoint ?? 'none',
        lastRefreshedAt: state.lastCompletedAt ?? 'never',
      },
    });
    ctx.enrich.total(page.total);

    if (input.sector) {
      const coverage = await mirror.coverageCounts();
      ctx.enrich({
        sectorCoverage: `${formatCount(coverage.noSector)} of ${advisories(coverage.total)} ${coverage.noSector === 1 ? 'carries' : 'carry'} no sector note and cannot match a sector filter. Coverage begins in 2017 and is complete from 2023; every advisory published before 2017 is excluded by this filter regardless of which sectors it affects.`,
      });
    }
    if (input.cvssMin !== undefined || input.cvssMax !== undefined || input.severity) {
      const coverage = await mirror.coverageCounts();
      ctx.enrich({
        cvssCoverage: `${advisories(coverage.v2Only)} ${coverage.v2Only === 1 ? 'scores' : 'score'} only in CVSS v2, where the upstream publishes no severity label and the band is derived. ${advisories(coverage.noCvss)} ${coverage.noCvss === 1 ? 'carries' : 'carry'} no CVSS score and cannot match a score filter.`,
      });
    }

    /* `notice` is last-wins across enrich calls, `truncated()` included, so every
     * notice source is collected here and written once. */
    const notices: string[] = [];
    if (page.total === 0) {
      const counts = await mirror.filterCounts(filters, kevCves);
      const zeroHit = zeroHitNotice(filters, counts, cweMayBeIncomplete);
      if (zeroHit) notices.push(zeroHit);
    }
    if (cweMayBeIncomplete) {
      notices.push(
        'This cwe result may be incomplete: the advisory index was built before CWE membership was recorded and has not been re-ingested since, so an advisory it has not re-ingested cannot match. The server re-ingests such an index in the background when it starts, and cisa_list_reference with topic sources shows sync status in_progress while that runs; repeat the search once it finishes, when this notice no longer appears.',
      );
    }
    if (!kevCves && page.items.length > 0) {
      notices.push(
        'KEV membership was not evaluated: the KEV catalog snapshot has not loaded yet, so these results carry no kevCves. Retry in a few seconds, or pass the listed CVEs to cisa_check_cve_status.',
      );
    }
    const truncated = page.items.length >= input.limit && hasMore;
    if (truncated) {
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

    ctx.log.info('Searched the ICS advisory index', {
      total: page.total,
      shown: page.items.length,
    });

    return {
      results: page.items,
      ...(hasMore
        ? { cursor: encodeCursor({ offset: offset + page.items.length, limit: input.limit }) }
        : {}),
      hasMore,
    };
  },

  format: (result) => {
    const lines: string[] = [
      `**${result.results.length} advisories on this page** (more available: ${result.hasMore ? 'yes' : 'no'}).`,
    ];
    if (result.cursor) lines.push(`**Next cursor:** \`${result.cursor}\``);
    lines.push('');

    for (const advisory of result.results) {
      lines.push(`### ${advisory.advisoryId} — ${advisory.title}`);
      lines.push(
        `**Series:** ${advisory.series} · **Publisher category:** ${advisory.publisherCategory} · **Revision:** ${advisory.revision}`,
      );
      lines.push(`**Published:** ${advisory.published} · **Revised:** ${advisory.revised}`);
      lines.push(
        `**Vendors (${advisory.vendorCount}):** ${
          advisory.vendors.length > 0 ? advisory.vendors.join(', ') : 'none listed'
        } · **Products:** ${advisory.productCount}`,
      );
      lines.push(
        `**CVEs (${advisory.cveCount}):** ${advisory.cves.length > 0 ? advisory.cves.join(', ') : 'none listed'}`,
      );
      if (advisory.kevCves) {
        lines.push(
          `**In KEV (${advisory.kevCves.length}):** ${
            advisory.kevCves.length > 0 ? advisory.kevCves.join(', ') : 'none of its CVEs'
          }`,
        );
      }
      if (advisory.maxCvss) {
        lines.push(
          `**Max CVSS:** ${advisory.maxCvss.score} ${advisory.maxCvss.severity} (v${advisory.maxCvss.version}${
            advisory.maxCvss.severityDerived ? ', band derived from the CVSS v2 scale' : ''
          })`,
        );
      }
      lines.push(
        `**Sectors:** ${advisory.sectors.length > 0 ? advisory.sectors.join(', ') : 'no sector note'}`,
      );
      if (advisory.sectorsRaw) lines.push(`**Sector note (verbatim):** ${advisory.sectorsRaw}`);
      lines.push(`**Web:** ${advisory.url} · **CSAF:** ${advisory.csafUrl}`);
      lines.push(`**Attribution:** ${advisory.attribution}`);
      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});

/** A count as prose, thousands-grouped. */
const formatCount = (count: number) => count.toLocaleString('en-US');

/** `1 advisory`, `1,046 advisories`. */
const advisories = (count: number) =>
  `${formatCount(count)} ${count === 1 ? 'advisory' : 'advisories'}`;

/** A filter as the caller set it, e.g. `cvssMax=1`. */
const setAs = (filters: AdvisorySearchFilters, key: AdvisoryFilterKey) =>
  `${key}=${String(filters[key])}`;

/**
 * The fragment a filter carries when it matches no advisory on its own, for the
 * filters whose miss has a known cause or a better next call. Other filters are
 * named plainly.
 */
function unmatchedFragment(
  filters: AdvisorySearchFilters,
  key: AdvisoryFilterKey,
): string | undefined {
  switch (key) {
    case 'vendor':
      return `${setAs(filters, key)} matches no advisory on its own. Vendor names are the advisory's own labels and are not normalized — the same company appears under several spellings. Try a shorter substring, or search with q instead.`;
    case 'sector':
      return `${setAs(filters, key)} matches no advisory on its own. Sector coverage begins in 2017, and an advisory with no sector note never matches a sector filter; sectorCoverage gives the count.`;
    case 'cve':
      return 'No ICS advisory covers that CVE; call cisa_check_cve_status to see whether it is in KEV instead.';
    case 'cwe':
      return 'No ICS advisory lists that CWE on any of its vulnerabilities. CWE IDs match exactly — a parent class such as CWE-20 does not match its children. Call cisa_search_kev with the same cwe to check the KEV side.';
    case 'series':
      return filters.series === 'ICSMA'
        ? 'ICSMA covers medical devices, and no advisory in the index is in that series. Drop the series filter to include ICSA.'
        : undefined;
    case 'inKev':
      return filters.inKev
        ? 'No advisory in the index covers a CVE in the loaded KEV catalog snapshot; drop inKev to see advisories regardless of KEV status.'
        : undefined;
    default:
      return;
  }
}

/**
 * Explain a zero-hit search from the per-filter counts. A filter that matches no
 * advisory on its own is named — through its own fragment where it has one —
 * and, when it is the only one, so is what dropping it restores, which is
 * nothing when the other filters also miss together. When every filter matches
 * on its own, the combination is the miss: each filter whose removal restores
 * results is named with that count. Every figure comes from the counts.
 *
 * On an index still being re-ingested, `advisory_cwes` may be partial, so a `cwe`
 * that matches nothing is not evidence: it is never named, and no count sentence
 * that depends on it is printed — the incomplete-`cwe` notice beside this one is
 * the honest explanation. Empty when nothing else applies.
 */
function zeroHitNotice(
  filters: AdvisorySearchFilters,
  allCounts: AdvisoryFilterCount[],
  cweMayBeIncomplete: boolean,
): string {
  const cweWithheld =
    cweMayBeIncomplete && allCounts.some((count) => count.filter === 'cwe' && count.alone === 0);
  const counts = cweWithheld ? allCounts.filter((count) => count.filter !== 'cwe') : allCounts;
  const unmatched = counts.filter((count) => count.alone === 0);

  const fragments: string[] = [];
  const plain: string[] = [];
  for (const { filter } of unmatched) {
    const fragment = unmatchedFragment(filters, filter);
    if (fragment) fragments.push(fragment);
    else plain.push(setAs(filters, filter));
  }
  if (plain.length > 0) {
    fragments.push(
      `${plain.join(', ')} ${plain.length === 1 ? 'matches no advisory on its own — relax or drop it.' : 'each match no advisory on their own — relax or drop them.'}`,
    );
  }
  if (cweWithheld) return fragments.join(' ');

  /* Every advisory fails a filter that matches nothing, so what dropping it
   * restores is exactly what the other filters match together — often nothing. */
  const [onlyUnmatched] = unmatched;
  if (onlyUnmatched && unmatched.length === 1 && counts.length > 1) {
    const restored = onlyUnmatched.restoredByDropping;
    fragments.push(
      restored > 0
        ? `Dropping ${onlyUnmatched.filter} restores ${advisories(restored)}.`
        : `Dropping ${onlyUnmatched.filter} alone restores nothing: the other filters match no advisory together either.`,
    );
  }
  if (unmatched.length === 0 && counts.length > 1) {
    const restorers = counts.filter((count) => count.restoredByDropping > 0);
    fragments.push(
      restorers.length > 0
        ? `Every filter matches advisories on its own; ${restorers
            .map(
              (count) =>
                `dropping ${count.filter} restores ${advisories(count.restoredByDropping)}`,
            )
            .join(', ')}.`
        : 'Every filter matches advisories on its own, but no single filter explains the miss — only relaxing two or more of them together restores a result.',
    );
  }

  if (fragments.length === 0) {
    fragments.push(
      'No advisory matches. Relax the narrowest filter, or call cisa_list_reference with topic sources to check the state of the index.',
    );
  }
  return fragments.join(' ');
}
