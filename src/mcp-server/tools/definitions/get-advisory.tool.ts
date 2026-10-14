/**
 * @fileoverview `cisa_get_advisory` — read one ICS advisory in full, or a section
 * outline when the document overflows the inline budget.
 *
 * At the 2026-09-17 index checkpoint, 783 of 3,926 advisories exceeded the 24 KB
 * budget, 102 exceeded 100 KB, and the largest was 1.38 MB with 544 vulnerability
 * entries and 585 products. Returning
 * those whole burns the caller's context; truncating them either hides data or
 * desyncs `content[]` from `structuredContent`. The outline is a complete, honest
 * listing of what is available plus a re-call contract, and the re-call is
 * stateless — the index lookup is deterministic, so the handler re-reads the row
 * and projects it.
 *
 * `vulnerabilities` is one section, and on the largest advisories it alone is
 * several hundred kilobytes. `cves` is the sub-section selector for it: the
 * outline lists the section's CVE IDs, and a re-call names the ones it wants.
 * @module mcp-server/tools/definitions/get-advisory.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { formatOutline, outlineOnOverflow, selectSections } from '@cyanheads/mcp-ts-core/utils';
import {
  ADVISORY_OUTLINE_BUDGET,
  ADVISORY_SECTIONS,
  AdvisoryDocumentOutputShape,
  AdvisoryIdInputSchema,
  advisoryCves,
  cvesNarrowingHint,
  extractAdvisorySections,
  indexFreshnessNote,
  presentSections,
  renderAdvisoryAcknowledgments,
  renderAdvisoryHeader,
  renderAdvisoryProducts,
  renderAdvisoryReferences,
  renderAdvisoryRevisions,
  renderAdvisorySummary,
  renderAdvisoryVulnerabilities,
  renderOutlineCves,
} from '@/mcp-server/schemas/advisory.js';
import { CveIdInputSchema } from '@/mcp-server/schemas/kev-record.js';
import { getCsafMirror } from '@/services/csaf-mirror/csaf-mirror-service.js';
import type { NormalizedAdvisory } from '@/services/csaf-mirror/types.js';

const MISS_GUIDANCE =
  'No advisory with that ID is in the index. IDs look like ICSA-26-260-07 or ICSMA-26-253-02, with an optional revision suffix. Call cisa_search_ics_advisories to find the right ID, or cisa_list_reference with topic advisory_id_formats for the format.';

export const getAdvisoryTool = tool('cisa_get_advisory', {
  title: 'cisa_get_advisory',
  description:
    'Read one CISA industrial control system advisory: product definitions and relationship component references; per-CVE CVSS score, vector, and CWE; vendor remediations; sectors; and revision history. Large advisories return a section outline with byte sizes and vulnerability CVE IDs. Re-call with sections, cves for named vulnerabilities, or productIds for exact product definitions referenced by vulnerability status, scores, or remediations. Product IDs are case-sensitive; relationship selection does not expand components. Every response carries source URLs and attribution. Find advisory IDs with cisa_search_ics_advisories.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    advisoryId: AdvisoryIdInputSchema.describe(
      'Advisory identifier, e.g. ICSA-26-260-07 or ICSMA-26-253-02, with an optional revision suffix: a single letter A-F or a numeric -N. Case, surrounding whitespace, and a trailing .json are normalized.',
    ),
    sections: z
      .array(z.enum(ADVISORY_SECTIONS).describe('One section name, as the outline reports it.'))
      .optional()
      .describe(
        'Sections to return. Omit for the whole document, or for its outline when the document overflows the inline budget.',
      ),
    cves: z
      .array(
        CveIdInputSchema.describe(
          'One CVE identifier the advisory covers, e.g. CVE-2023-3935. Case and surrounding whitespace are normalized.',
        ),
      )
      .optional()
      .describe(
        'Narrow the vulnerabilities section to these CVE IDs; the outline lists the ones the advisory holds. Alone, it selects the vulnerabilities section; with sections, that list must include "vulnerabilities".',
      ),
    productIds: z
      .array(
        z
          .string()
          .trim()
          .min(1)
          .describe('Exact case-sensitive CSAF product ID; surrounding whitespace is trimmed.'),
      )
      .optional()
      .describe(
        'Narrow products to these IDs from vulnerability status, score, or remediation references. Alone selects products; combined with cves selects both sections. Explicit sections must include products.',
      ),
  }),

  output: z.object({
    found: z.boolean().describe('Whether an advisory with that ID is in the index.'),
    ...AdvisoryDocumentOutputShape,
    guidance: z
      .string()
      .optional()
      .describe(
        'What to do instead, present when found is false: how current the index is, and whether the advisory may be newer than it.',
      ),
    indexCheckpoint: z
      .string()
      .nullable()
      .optional()
      .describe(
        'Present when found is false: the newest revision timestamp the index holds, or null if none.',
      ),
    indexLastSyncedAt: z
      .string()
      .nullable()
      .optional()
      .describe(
        'Present when found is false: when the index last completed a sync, ISO 8601, or null if never.',
      ),
  }),

  errors: [
    {
      reason: 'product_ids_need_products_section',
      code: JsonRpcErrorCode.ValidationError,
      when: 'productIds is nonempty but explicit sections omits products.',
      recovery:
        'Add "products" to sections, or omit sections so productIds selects its target section.',
    },
    {
      reason: 'unknown_product_id',
      code: JsonRpcErrorCode.ValidationError,
      when: 'productIds names an ID with no definition in this advisory.',
      recovery:
        'Use exact case-sensitive IDs from vulnerability product status, scores, or remediations, or request sections ["products"] without productIds to see all defined products. Upstream references may lack definitions.',
    },
    {
      reason: 'mirror_busy',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'A transient SQLite lock prevents the advisory index from opening.',
      retryable: true,
      recovery:
        'Retry this lookup shortly; another process temporarily holds the advisory index lock. Call cisa_list_reference with topic sources to check its state.',
    },
    {
      reason: 'mirror_not_ready',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'The advisory index has never completed a full sync.',
      retryable: true,
      recovery:
        'The ICS advisory index is still building; call cisa_list_reference with topic sources to check its progress, then retry this lookup.',
    },
    {
      reason: 'mirror_unavailable',
      code: JsonRpcErrorCode.ConfigurationError,
      when: 'The advisory index store cannot be opened: its location is not writable, is read-only, runs through a missing directory or a file, or holds a file that is not a SQLite database.',
      recovery:
        'The ICS advisory index cannot be opened at its configured location; the server operator must set CISA_CSAF_MIRROR_PATH to a writable path and restart. Retrying will not help, but cisa_check_cve_status, cisa_search_kev, cisa_get_ssvc, and cisa_get_alerts still work.',
    },
    {
      reason: 'unknown_section',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A requested section is one this advisory does not carry.',
      recovery:
        'Call this tool without sections to get the outline of the sections this advisory actually has, then request those by name.',
    },
    {
      reason: 'cves_need_vulnerabilities_section',
      code: JsonRpcErrorCode.ValidationError,
      when: 'cves is set but sections does not include "vulnerabilities", so there is nothing for cves to narrow.',
      recovery:
        'Add "vulnerabilities" to sections, or omit sections so cves selects the vulnerabilities section on its own.',
    },
    {
      reason: 'unknown_cve',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A cves entry names a CVE this advisory does not cover.',
      recovery:
        'Call this tool without cves to see which CVE IDs the advisory holds — the outline lists them — then pass only those; to find the advisory that covers a CVE, call cisa_search_ics_advisories with cve.',
    },
  ],

  async handler(input, ctx) {
    const cves = input.cves && input.cves.length > 0 ? [...new Set(input.cves)] : undefined;
    const productIds = input.productIds?.length ? [...new Set(input.productIds)] : undefined;
    const requested =
      input.sections && input.sections.length > 0
        ? input.sections
        : cves || productIds
          ? [
              ...(productIds ? ['products' as const] : []),
              ...(cves ? ['vulnerabilities' as const] : []),
            ]
          : undefined;
    if (productIds && requested && !requested.includes('products')) {
      throw ctx.fail(
        'product_ids_need_products_section',
        `productIds narrows products, but sections requests only ${requested.join(', ')}.`,
      );
    }
    if (cves && requested && !requested.includes('vulnerabilities')) {
      throw ctx.fail(
        'cves_need_vulnerabilities_section',
        `cves narrows the vulnerabilities section, but sections requests only ${requested.join(', ')}.`,
      );
    }

    const mirror = getCsafMirror();
    const availability = await mirror.availability();
    if (availability.status === 'busy') {
      throw ctx.fail('mirror_busy', 'The ICS advisory index is temporarily busy.');
    }
    if (availability.status === 'unavailable') {
      throw ctx.fail(
        'mirror_unavailable',
        `The ICS advisory index cannot be opened (${availability.reason.replaceAll('_', ' ')}).`,
      );
    }
    if (availability.status === 'not_ready') {
      throw ctx.fail(
        'mirror_not_ready',
        'The ICS advisory index has not completed its first sync.',
      );
    }

    const { advisoryId } = input;
    const doc = await mirror.getAdvisory(advisoryId);
    if (!doc) {
      const index = await mirror.state();
      ctx.log.info('Advisory not in the index', { advisoryId });
      return {
        found: false,
        guidance: `${MISS_GUIDANCE} ${indexFreshnessNote(advisoryId, index)}`,
        indexCheckpoint: index.checkpoint,
        indexLastSyncedAt: index.lastCompletedAt,
      };
    }

    if (requested) {
      const available = presentSections(doc);
      const missing = requested.filter((section) => !available.includes(section));
      if (missing.length > 0) {
        throw ctx.fail(
          'unknown_section',
          `${advisoryId} carries no ${missing.join(', ')} section. It carries: ${available.join(', ')}.`,
        );
      }
      const selected = selectSections(doc as unknown as Record<string, unknown>, [...requested], {
        alwaysKeep: ['advisory'],
      }) as Partial<NormalizedAdvisory>;
      if (productIds) {
        const defined = new Set(
          doc.products.vendors.flatMap((vendor) =>
            vendor.products.flatMap((product) =>
              product.versions.map((version) => version.productId),
            ),
          ),
        );
        const unknown = productIds.filter((id) => !defined.has(id));
        if (unknown.length)
          throw ctx.fail(
            'unknown_product_id',
            `${advisoryId} has no definition for ${unknown.join(', ')}.`,
          );
        const wanted = new Set(productIds);
        const vendors = doc.products.vendors
          .map((vendor) => ({
            ...vendor,
            products: vendor.products
              .map((product) => ({
                ...product,
                versions: product.versions.filter((version) => wanted.has(version.productId)),
              }))
              .filter((product) => product.versions.length > 0),
          }))
          .filter((vendor) => vendor.products.length > 0);
        selected.products = {
          ...doc.products,
          vendors,
          selected: true,
          shownProducts: vendors.reduce(
            (count, vendor) =>
              count + vendor.products.reduce((sum, product) => sum + product.versions.length, 0),
            0,
          ),
        };
      }
      if (cves) {
        const covered = new Set(advisoryCves(doc));
        const unknown = cves.filter((cve) => !covered.has(cve));
        if (unknown.length > 0) {
          throw ctx.fail(
            'unknown_cve',
            `${advisoryId} does not cover ${unknown.join(', ')}; its vulnerabilities section holds ${covered.size} CVE${covered.size === 1 ? '' : 's'}.`,
          );
        }
        const wanted = new Set(cves);
        selected.vulnerabilities = doc.vulnerabilities.filter((entry) => wanted.has(entry.cve));
      }
      return { found: true, kind: 'full' as const, ...selected };
    }

    const result = outlineOnOverflow(doc as unknown as Record<string, unknown>, {
      budget: ADVISORY_OUTLINE_BUDGET,
      extract: () => extractAdvisorySections(doc),
    });

    ctx.log.info('Read advisory from the index', { advisoryId, kind: result.kind });
    if (result.kind === 'outline') {
      /* `outlineNotice` rather than `notice`: a bare `notice` key reads as
       * agent-facing enrichment, and this one is the outline arm's own payload. */
      const { notice, ...outline } = result;
      const hint = cvesNarrowingHint(outline.sections, ADVISORY_OUTLINE_BUDGET);
      return { found: true, ...outline, outlineNotice: hint ? `${notice} ${hint}` : notice };
    }
    return { found: true, ...result };
  },

  format: (result) => {
    const lines: string[] = [];
    const index: string[] = [];
    if (result.indexCheckpoint !== undefined)
      index.push(`**Index checkpoint:** ${result.indexCheckpoint ?? 'none'}`);
    if (result.indexLastSyncedAt !== undefined)
      index.push(`**Index last synced:** ${result.indexLastSyncedAt ?? 'never'}`);
    if (!result.found) {
      lines.push('**Advisory not found in the index.**', ...index);
      if (result.guidance) lines.push(result.guidance);
      return [{ type: 'text', text: lines.join('\n') }];
    }

    if (result.guidance) lines.push(result.guidance);
    lines.push(...index);
    lines.push(`**Advisory found:** ${result.found ? 'yes' : 'no'}`);
    if (result.kind) lines.push(`**Result kind:** ${result.kind}`, '');
    if (result.advisory) lines.push(...renderAdvisoryHeader(result.advisory));
    if (result.summary) lines.push(...renderAdvisorySummary(result.summary));
    if (result.products) lines.push(...renderAdvisoryProducts(result.products));
    if (result.vulnerabilities)
      lines.push(...renderAdvisoryVulnerabilities(result.vulnerabilities));
    if (result.revisionHistory) lines.push(...renderAdvisoryRevisions(result.revisionHistory));
    if (result.references) lines.push(...renderAdvisoryReferences(result.references));
    if (result.acknowledgments)
      lines.push(...renderAdvisoryAcknowledgments(result.acknowledgments));

    const blocks = [{ type: 'text' as const, text: lines.join('\n') }];
    if (result.sections) {
      blocks.push(
        ...(formatOutline({
          kind: 'outline',
          sections: result.sections,
          notice: result.outlineNotice ?? '',
        }) as Array<{ type: 'text'; text: string }>),
      );
      const cveLines = renderOutlineCves(result.sections);
      if (cveLines.length > 0) blocks.push({ type: 'text', text: cveLines.join('\n') });
    }
    return blocks;
  },
});
