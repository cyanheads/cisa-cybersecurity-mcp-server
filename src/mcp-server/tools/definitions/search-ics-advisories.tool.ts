/**
 * @fileoverview `cisa_search_ics_advisories` — filtered and full-text search over
 * the local index of the CSAF ICS advisory corpus.
 * @module mcp-server/tools/definitions/search-ics-advisories.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { decodeCursor, encodeCursor } from '@cyanheads/mcp-ts-core/utils';
import { ISO_DATE_REGEX } from '@/mcp-server/schemas/kev-record.js';
import { SEVERITY_BANDS } from '@/reference/cvss.js';
import { SECTOR_FILTER_VALUES } from '@/reference/sectors.js';
import { getCsafMirror } from '@/services/csaf-mirror/csaf-mirror-service.js';
import { ADVISORY_ID_PATTERN } from '@/services/csaf-mirror/normalize.js';
import type { AdvisorySearchFilters } from '@/services/csaf-mirror/types.js';

const MAX_PAGE_SIZE = 50;

export const searchIcsAdvisoriesTool = tool('cisa_search_ics_advisories', {
  title: 'cisa_search_ics_advisories',
  description:
    'Search the CISA industrial control system advisory corpus — 3,926 CSAF 2.0 documents covering PLC, HMI, SCADA, building-automation, and medical-device products from 2010 onward. Filter by vendor, product, CVE, CVSS range, severity band, critical-infrastructure sector, advisory series, publication date, or revision date, and run full-text search over advisory titles and product names. Sector filtering reaches only advisories that carry a sector note, which begins in 2017; the response reports how many documents a sector filter can never match. Returns advisory IDs for cisa_get_advisory, the CVEs each advisory covers, and the source URL and attribution every advisory response carries.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    q: z
      .string()
      .min(2)
      .optional()
      .describe(
        'Full-text search over advisory titles, vendor names, and product names. Tokens are AND-combined; FTS5 operators in the input are neutralized rather than honored.',
      ),
    vendor: z
      .string()
      .min(2)
      .optional()
      .describe(
        'Case-insensitive substring of a vendor label. Vendor names are unnormalized upstream — the same company appears under several spellings — so this is substring, not exact.',
      ),
    product: z.string().min(2).optional().describe('Case-insensitive substring of a product name.'),
    cve: z
      .string()
      .regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/)
      .optional()
      .describe('Exact CVE membership. The corpus covers 12,321 distinct CVEs.'),
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
      .describe('Advisory series: ICSA (3,738 documents) or ICSMA medical devices (188).'),
    publisher: z
      .enum(['coordinator', 'other'])
      .optional()
      .describe(
        'coordinator selects CISA-authored advisories (2,863); other selects republished vendor advisories (1,063).',
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
                'Highest CVSS score across the advisory. Absent on the two advisories with no CVSS.',
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
    notice: z.string().optional().describe('Guidance when nothing matched.'),
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
    if (!(await mirror.ready())) {
      throw ctx.fail(
        'mirror_not_ready',
        'The ICS advisory index has not completed its first sync.',
        { ...ctx.recoveryFor('mirror_not_ready') },
      );
    }

    const offset = input.cursor ? decodeCursor(input.cursor, ctx).offset : 0;
    const filters: AdvisorySearchFilters = {
      q: input.q,
      vendor: input.vendor,
      product: input.product,
      cve: input.cve,
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

    const page = await mirror.search(filters, ctx);
    const state = await mirror.state();
    const hasMore = offset + page.items.length < page.total;

    const applied: Record<string, string> = {};
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined) applied[key] = String(value);
    }

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
        sectorCoverage: `${coverage.noSector} of ${coverage.total} advisories carry no sector note and cannot match a sector filter. Coverage begins in 2017 and is complete from 2023; every advisory published before 2017 is excluded by this filter regardless of which sectors it affects.`,
      });
    }
    if (input.cvssMin !== undefined || input.cvssMax !== undefined || input.severity) {
      const coverage = await mirror.coverageCounts();
      ctx.enrich({
        cvssCoverage: `${coverage.v2Only} advisories score only in CVSS v2, where the upstream publishes no severity label and the band is derived. ${coverage.noCvss} advisories carry no CVSS score and cannot match a score filter.`,
      });
    }

    if (page.items.length >= input.limit && hasMore) {
      ctx.enrich.truncated({ shown: page.items.length, cap: input.limit });
    }
    if (page.total === 0) {
      ctx.enrich.notice(zeroHitNotice(input));
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

/** Compose the zero-hit notice from whichever filter most plausibly explains the miss. */
function zeroHitNotice(input: {
  cve?: string | undefined;
  sector?: string | undefined;
  series?: string | undefined;
  vendor?: string | undefined;
}): string {
  const fragments: string[] = [];
  if (input.vendor) {
    fragments.push(
      "Vendor names are the advisory's own labels and are not normalized — the same company appears under several spellings. Try a shorter substring, or search with q instead.",
    );
  }
  if (input.sector) {
    fragments.push(
      'Sector coverage begins in 2017; 729 advisories carry no sector note at all. Drop the sector filter to reach them.',
    );
  }
  if (input.series === 'ICSMA') {
    fragments.push(
      'ICSMA covers medical devices and is 188 of 3,926 advisories. Drop the series filter to include ICSA.',
    );
  }
  if (input.cve) {
    fragments.push(
      'No ICS advisory covers that CVE. The corpus covers 12,321 distinct CVEs; call cisa_check_cve_status to see whether it is in KEV instead.',
    );
  }
  if (fragments.length === 0) {
    fragments.push(
      'No advisory matches. Relax the narrowest filter, or call cisa_list_reference with topic sectors or advisory_id_formats for the value vocabulary.',
    );
  }
  return fragments.join(' ');
}
