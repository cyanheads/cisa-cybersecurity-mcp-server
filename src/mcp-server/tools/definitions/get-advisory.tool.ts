/**
 * @fileoverview `cisa_get_advisory` — read one ICS advisory in full, or a section
 * outline when the document overflows the inline budget.
 *
 * 783 of 3,926 advisories exceed the 24 KB budget, 102 exceed 100 KB, and the
 * largest is 1.38 MB with 544 vulnerability entries and 585 products. Returning
 * those whole burns the caller's context; truncating them either hides data or
 * desyncs `content[]` from `structuredContent`. The outline is a complete, honest
 * listing of what is available plus a re-call contract, and the re-call is
 * stateless — the index lookup is deterministic, so the handler re-reads the row
 * and projects it.
 * @module mcp-server/tools/definitions/get-advisory.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { formatOutline, outlineOnOverflow, selectSections } from '@cyanheads/mcp-ts-core/utils';
import {
  ADVISORY_OUTLINE_BUDGET,
  ADVISORY_SECTIONS,
  AdvisoryDocumentOutputShape,
  isEmptySection,
  presentSections,
  renderAdvisoryAcknowledgments,
  renderAdvisoryHeader,
  renderAdvisoryProducts,
  renderAdvisoryReferences,
  renderAdvisoryRevisions,
  renderAdvisorySummary,
  renderAdvisoryVulnerabilities,
} from '@/mcp-server/schemas/advisory.js';
import { getCsafMirror } from '@/services/csaf-mirror/csaf-mirror-service.js';
import {
  ADVISORY_ID_INPUT_PATTERN,
  normalizeAdvisoryId,
} from '@/services/csaf-mirror/normalize.js';

const MISS_GUIDANCE =
  'No advisory with that ID is in the index. IDs look like ICSA-26-260-07 or ICSMA-26-253-02, with an optional revision suffix. Call cisa_search_ics_advisories to find the right ID, or cisa_list_reference with topic advisory_id_formats for the format.';

export const getAdvisoryTool = tool('cisa_get_advisory', {
  title: 'cisa_get_advisory',
  description:
    "Read one CISA industrial control system advisory in full: affected products flattened from the CSAF product tree into vendor, product, and version ranges; per-CVE CVSS score, vector, and CWE; remediations with their category and vendor instructions; critical-infrastructure sectors; and the revision history. Large advisories return a section outline instead of the whole document — re-call with the sections you need. Republished vendor advisories carry the originating vendor's text; every response reports the source URL and attribution. Find advisory IDs with cisa_search_ics_advisories.",
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    advisoryId: z
      .string()
      .regex(ADVISORY_ID_INPUT_PATTERN)
      .describe(
        'Advisory identifier, e.g. ICSA-26-260-07 or ICSMA-26-253-02. Case-insensitive; an optional revision suffix is a single letter a-f or a numeric -N. A trailing .json is stripped.',
      ),
    sections: z
      .array(z.enum(ADVISORY_SECTIONS).describe('One section name, as the outline reports it.'))
      .optional()
      .describe(
        'Sections to return. Omit for the whole document, or for its outline when the document overflows the inline budget.',
      ),
  }),

  output: z.object({
    found: z.boolean().describe('Whether an advisory with that ID is in the index.'),
    ...AdvisoryDocumentOutputShape,
    guidance: z.string().optional().describe('What to do instead, present when found is false.'),
  }),

  errors: [
    {
      reason: 'mirror_not_ready',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'The advisory index has never completed a full sync.',
      retryable: true,
      recovery:
        'The ICS advisory index is still building; call cisa_list_reference with topic sources to check its progress, then retry this lookup.',
    },
    {
      reason: 'unknown_section',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A requested section is one this advisory does not carry.',
      recovery:
        'Call this tool without sections to get the outline of the sections this advisory actually has, then request those by name.',
    },
  ],

  async handler(input, ctx) {
    const mirror = getCsafMirror();
    if (!(await mirror.ready())) {
      throw ctx.fail(
        'mirror_not_ready',
        'The ICS advisory index has not completed its first sync.',
        { ...ctx.recoveryFor('mirror_not_ready') },
      );
    }

    const advisoryId = normalizeAdvisoryId(input.advisoryId);
    const doc = await mirror.getAdvisory(advisoryId);
    if (!doc) {
      ctx.log.info('Advisory not in the index', { advisoryId });
      return { found: false, guidance: MISS_GUIDANCE };
    }

    if (input.sections && input.sections.length > 0) {
      const available = presentSections(doc);
      const missing = input.sections.filter((section) => !available.includes(section));
      if (missing.length > 0) {
        throw ctx.fail(
          'unknown_section',
          `${advisoryId} carries no ${missing.join(', ')} section. It carries: ${available.join(', ')}.`,
          { ...ctx.recoveryFor('unknown_section') },
        );
      }
      return {
        found: true,
        kind: 'full' as const,
        ...selectSections(doc as unknown as Record<string, unknown>, input.sections, {
          alwaysKeep: ['advisory'],
        }),
      };
    }

    const result = outlineOnOverflow(doc as unknown as Record<string, unknown>, {
      budget: ADVISORY_OUTLINE_BUDGET,
      /* Only sections the advisory actually carries — the same set `unknown_section` validates against. */
      extract: (document) =>
        Object.entries(document)
          .filter(([, value]) => !isEmptySection(value))
          .map(([name, value]) => ({ name, bytes: JSON.stringify(value)?.length ?? 0 })),
    });

    ctx.log.info('Read advisory from the index', { advisoryId, kind: result.kind });
    if (result.kind === 'outline') {
      /* `outlineNotice` rather than `notice`: a bare `notice` key reads as
       * agent-facing enrichment, and this one is the outline arm's own payload. */
      const { notice, ...outline } = result;
      return { found: true, ...outline, outlineNotice: notice };
    }
    return { found: true, ...result };
  },

  format: (result) => {
    const lines: string[] = [];
    if (!result.found) {
      lines.push('**Advisory not found in the index.**');
      if (result.guidance) lines.push(result.guidance);
      return [{ type: 'text', text: lines.join('\n') }];
    }

    if (result.guidance) lines.push(result.guidance);
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
    }
    return blocks;
  },
});
