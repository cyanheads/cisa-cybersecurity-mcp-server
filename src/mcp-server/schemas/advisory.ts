/**
 * @fileoverview Output schemas and markdown renderers for a single ICS advisory,
 * shared by `cisa_get_advisory` and the `cisa://advisory/{advisoryId}` resource.
 *
 * The seven section schemas mirror the seven top-level keys of the stored
 * normalized advisory, which is also what the section outline enumerates — so the
 * outline's section names are exactly the names a caller passes back in
 * `sections`.
 * @module mcp-server/schemas/advisory
 */

import { z } from '@cyanheads/mcp-ts-core';
import { OUTLINE_VARIANT } from '@cyanheads/mcp-ts-core/utils';
import { ADVISORY_ID_PATTERN } from '@/services/csaf-mirror/normalize.js';
import type { NormalizedAdvisory } from '@/services/csaf-mirror/types.js';

/** The seven addressable sections of an advisory, largest-first in the outline. */
export const ADVISORY_SECTIONS = [
  'advisory',
  'summary',
  'products',
  'vulnerabilities',
  'revisionHistory',
  'references',
  'acknowledgments',
] as const;

/**
 * Serialized-byte budget above which the outline replaces the document. A helper
 * argument rather than an env var: a deploy-tunable threshold would drift the
 * response *shape* across environments. Shared so the tool and the resource
 * overflow at exactly the same point.
 */
export const ADVISORY_OUTLINE_BUDGET = 24_000;

export const AdvisoryHeaderSchema = z
  .object({
    advisoryId: z.string().regex(ADVISORY_ID_PATTERN).describe('The advisory identifier.'),
    title: z.string().describe('The advisory title.'),
    series: z.enum(['ICSA', 'ICSMA']).describe('Advisory series.'),
    status: z.string().describe('CSAF tracking status, e.g. final or interim.'),
    csafVersion: z.string().describe('CSAF schema version the document declares.'),
    published: z.string().describe('Initial release date, ISO 8601.'),
    revised: z.string().describe('Current release date, ISO 8601.'),
    revision: z.string().describe('Document revision number.'),
    publisherCategory: z
      .string()
      .describe('coordinator for CISA-authored, other for a republished vendor advisory.'),
    publisherName: z.string().describe('Publisher name as the document records it.'),
    url: z.string().describe('Absolute URL of the cisa.gov web version of the advisory.'),
    csafUrl: z.string().describe('Absolute URL of the raw CSAF JSON document.'),
    attribution: z
      .string()
      .describe('Who authored the text and under what terms it may be redistributed.'),
  })
  .describe('Advisory identity, dates, and source attribution.');

export const AdvisorySummarySchema = z
  .object({
    riskEvaluation: z.string().optional().describe('The risk-evaluation note, when present.'),
    exploitability: z.string().optional().describe('The exploitability note, when present.'),
    summaryText: z.string().optional().describe('The advisory summary or overview note.'),
    sectors: z
      .array(z.string().describe('One canonical sector name.'))
      .describe('Normalized sector names. Empty when the advisory carries no sector note.'),
    sectorsRaw: z.string().optional().describe('The sector note verbatim, when present.'),
    countriesDeployed: z.string().optional().describe('The countries/areas-deployed note.'),
    headquarters: z.string().optional().describe('The company-headquarters-location note.'),
  })
  .describe('Narrative notes and sector classification.');

export const AdvisoryProductsSchema = z
  .object({
    vendorCount: z.number().int().describe('Distinct vendors in the product tree.'),
    productCount: z.number().int().describe('Flattened product entries in the whole product tree.'),
    vendors: z
      .array(
        z
          .object({
            name: z.string().describe('Vendor label as the advisory spells it.'),
            products: z
              .array(
                z
                  .object({
                    name: z.string().describe('Product name.'),
                    family: z
                      .string()
                      .optional()
                      .describe('Product family, when the tree names one.'),
                    versions: z
                      .array(
                        z
                          .object({
                            kind: z
                              .string()
                              .describe(
                                'CSAF branch category this entry came from, e.g. product_version or product_version_range.',
                              ),
                            value: z.string().describe('The version or version-range expression.'),
                            productId: z
                              .string()
                              .describe(
                                'The CSAFPID token vulnerability entries reference — how a CVE maps to exact affected versions.',
                              ),
                          })
                          .describe('One affected version or version range.'),
                      )
                      .describe('Version entries under this product.'),
                  })
                  .describe('One product under the vendor.'),
              )
              .describe('Products under this vendor.'),
          })
          .describe('One vendor and its products.'),
      )
      .describe('Vendors flattened out of the CSAF product tree.'),
    truncated: z.boolean().optional().describe('True when the flattened version rows were capped.'),
    shownProducts: z.number().int().describe('Flattened version rows actually returned.'),
  })
  .describe('Affected products, flattened from the CSAF product tree.');

export const AdvisoryVulnerabilitySchema = z
  .object({
    cve: z
      .string()
      .regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/)
      .describe('The CVE identifier.'),
    cweId: z.string().optional().describe('CWE identifier, when the entry carries one.'),
    cweName: z.string().optional().describe('CWE name, when the entry carries one.'),
    title: z.string().optional().describe('Vulnerability title, when the entry carries one.'),
    scores: z
      .array(
        z
          .object({
            version: z.string().describe('CVSS version of this score.'),
            baseScore: z.number().describe('CVSS base score, 0.0 through 10.0.'),
            baseSeverity: z.string().describe('Severity band for the score.'),
            severityDerived: z
              .boolean()
              .describe('True when the band was derived here rather than published upstream.'),
            vectorString: z.string().describe('The full CVSS vector string.'),
            productIds: z
              .array(z.string().describe('One CSAFPID token.'))
              .describe('Products this score applies to.'),
          })
          .describe('One CVSS score.'),
      )
      .describe('CVSS scores. Empty on the 431 vulnerability objects that carry none.'),
    remediations: z
      .array(
        z
          .object({
            category: z
              .string()
              .describe(
                'CSAF remediation category: mitigation, vendor_fix, workaround, none_available, or no_fix_planned.',
              ),
            details: z.string().describe('The remediation instructions, verbatim.'),
            url: z.string().optional().describe('Vendor link for the remediation, when present.'),
            productIds: z
              .array(z.string().describe('One CSAFPID token.'))
              .describe('Products this remediation applies to.'),
            restartRequired: z
              .string()
              .optional()
              .describe('Restart category the remediation requires, when stated.'),
          })
          .describe('One remediation entry.'),
      )
      .describe('Remediations for this vulnerability.'),
    productStatus: z
      .object({
        known_affected: z
          .array(z.string().describe('One CSAFPID token.'))
          .describe('Products known to be affected.'),
        fixed: z
          .array(z.string().describe('One CSAFPID token.'))
          .describe('Products already fixed.'),
        known_not_affected: z
          .array(z.string().describe('One CSAFPID token.'))
          .describe('Products known not to be affected.'),
        recommended: z
          .array(z.string().describe('One CSAFPID token.'))
          .describe('Products recommended by the publisher.'),
      })
      .describe('Per-product status buckets, as CSAF names them.'),
    notes: z
      .array(
        z
          .object({
            category: z.string().describe('CSAF note category.'),
            title: z.string().optional().describe('Note title, when present.'),
            text: z.string().describe('Note text, verbatim.'),
          })
          .describe('One note attached to the vulnerability.'),
      )
      .describe(
        'Notes attached to the vulnerability. CVSS v4 appears here as prose — it is never parsed into a score field.',
      ),
  })
  .describe('One vulnerability the advisory covers.');

export const AdvisoryRevisionSchema = z
  .object({
    number: z.string().describe('Revision number.'),
    date: z.string().describe('Revision date, ISO 8601.'),
    summary: z.string().describe('What changed in this revision.'),
    legacyVersion: z
      .string()
      .optional()
      .describe('Legacy version label, when the entry carries one.'),
  })
  .describe('One revision-history entry.');

export const AdvisoryReferenceSchema = z
  .object({
    category: z.string().describe('CSAF reference category, e.g. self or external.'),
    summary: z.string().optional().describe('Reference summary, when present.'),
    url: z.string().describe('The reference URL.'),
  })
  .describe('One document-level reference.');

export const AdvisoryAcknowledgmentSchema = z
  .object({
    organization: z.string().optional().describe('Acknowledged organization, when named.'),
    names: z
      .array(z.string().describe('One acknowledged person.'))
      .describe('Acknowledged people.'),
    summary: z.string().optional().describe('What the acknowledgment records.'),
  })
  .describe('One acknowledgment entry.');

/**
 * The document-or-outline output fields shared by `cisa_get_advisory` and the
 * `cisa://advisory/{advisoryId}` resource. The tool adds `found`/`guidance` for
 * its miss arm; the resource throws on a miss, so it uses the shape as-is.
 */
export const AdvisoryDocumentOutputShape = {
  kind: z
    .enum(['full', 'outline'])
    .optional()
    .describe('full when the document is returned; outline when only the section listing is.'),
  advisory: AdvisoryHeaderSchema.optional().describe(
    'Advisory identity, dates, and attribution. Always kept, including on a section selection.',
  ),
  summary: AdvisorySummarySchema.optional().describe('Narrative notes and sector classification.'),
  products: AdvisoryProductsSchema.optional().describe('Affected products and version ranges.'),
  vulnerabilities: z
    .array(AdvisoryVulnerabilitySchema)
    .optional()
    .describe(
      'Vulnerabilities the advisory covers, with scores, remediations, and product status.',
    ),
  revisionHistory: z
    .array(AdvisoryRevisionSchema)
    .optional()
    .describe('Revision history, oldest first as published.'),
  references: z.array(AdvisoryReferenceSchema).optional().describe('Document-level references.'),
  acknowledgments: z
    .array(AdvisoryAcknowledgmentSchema)
    .optional()
    .describe('Acknowledgment entries.'),
  sections: z
    .array(
      OUTLINE_VARIANT.shape.sections.element.describe(
        'One section this advisory carries, with its serialized byte size.',
      ),
    )
    .optional()
    .describe('Outline arm — the sections available, largest first, with their byte sizes.'),
  outlineNotice: OUTLINE_VARIANT.shape.notice
    .optional()
    .describe('Outline arm — how to call cisa_get_advisory for specific sections.'),
} as const;

/** `true` when a section carries nothing a caller could read. */
export function isEmptySection(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') return Object.keys(value).length === 0;
  return false;
}

/** The section names an advisory actually carries, in declaration order. */
export function presentSections(doc: NormalizedAdvisory): string[] {
  return ADVISORY_SECTIONS.filter((section) => !isEmptySection(doc[section]));
}

// ── Renderers ───────────────────────────────────────────────────────────────

type Header = z.infer<typeof AdvisoryHeaderSchema>;
type Summary = z.infer<typeof AdvisorySummarySchema>;
type Products = z.infer<typeof AdvisoryProductsSchema>;
type Vulnerability = z.infer<typeof AdvisoryVulnerabilitySchema>;
type Revision = z.infer<typeof AdvisoryRevisionSchema>;
type Reference = z.infer<typeof AdvisoryReferenceSchema>;
type Acknowledgment = z.infer<typeof AdvisoryAcknowledgmentSchema>;

/** Render the advisory header block. */
export function renderAdvisoryHeader(advisory: Header): string[] {
  return [
    `# ${advisory.advisoryId} — ${advisory.title}`,
    `**Series:** ${advisory.series} · **Status:** ${advisory.status} · **CSAF version:** ${advisory.csafVersion}`,
    `**Published:** ${advisory.published} · **Revised:** ${advisory.revised} · **Revision:** ${advisory.revision}`,
    `**Publisher:** ${advisory.publisherName} (category ${advisory.publisherCategory})`,
    `**Web:** ${advisory.url} · **CSAF:** ${advisory.csafUrl}`,
    `**Attribution:** ${advisory.attribution}`,
    '',
  ];
}

/** Render the summary block. */
export function renderAdvisorySummary(summary: Summary): string[] {
  const lines = ['## Summary'];
  if (summary.summaryText) lines.push(summary.summaryText);
  if (summary.riskEvaluation) lines.push(`**Risk evaluation:** ${summary.riskEvaluation}`);
  if (summary.exploitability) lines.push(`**Exploitability:** ${summary.exploitability}`);
  lines.push(
    `**Sectors:** ${summary.sectors.length > 0 ? summary.sectors.join(', ') : 'no sector note'}`,
  );
  if (summary.sectorsRaw) lines.push(`**Sector note (verbatim):** ${summary.sectorsRaw}`);
  if (summary.countriesDeployed) lines.push(`**Countries deployed:** ${summary.countriesDeployed}`);
  if (summary.headquarters) lines.push(`**Headquarters:** ${summary.headquarters}`);
  lines.push('');
  return lines;
}

/** Render the products block. */
export function renderAdvisoryProducts(products: Products): string[] {
  const lines = [
    '## Affected products',
    `**Vendors:** ${products.vendorCount} · **Products:** ${products.productCount} · **Shown:** ${products.shownProducts}`,
    `**Truncated:** ${products.truncated ? 'yes — request the products section alone for the rest' : 'no'}`,
  ];
  for (const vendor of products.vendors) {
    lines.push(`### ${vendor.name}`);
    for (const product of vendor.products) {
      lines.push(`- **${product.name}**${product.family ? ` (family: ${product.family})` : ''}`);
      for (const version of product.versions) {
        lines.push(`  - [${version.kind}] ${version.value} → \`${version.productId}\``);
      }
    }
  }
  lines.push('');
  return lines;
}

/** Render the vulnerabilities block. */
export function renderAdvisoryVulnerabilities(vulnerabilities: Vulnerability[]): string[] {
  const lines = ['## Vulnerabilities'];
  for (const vulnerability of vulnerabilities) {
    lines.push(`### ${vulnerability.cve}${vulnerability.title ? ` — ${vulnerability.title}` : ''}`);
    if (vulnerability.cweId || vulnerability.cweName) {
      lines.push(
        `**CWE:** ${vulnerability.cweId ?? 'unknown'} ${vulnerability.cweName ?? ''}`.trim(),
      );
    }
    if (vulnerability.scores.length === 0) {
      lines.push('**Scores:** none published for this entry');
    } else {
      for (const score of vulnerability.scores) {
        lines.push(
          `**CVSS v${score.version}:** ${score.baseScore} ${score.baseSeverity}${
            score.severityDerived ? ' (band derived)' : ''
          } \`${score.vectorString}\` → ${score.productIds.join(', ') || 'no product ids'}`,
        );
      }
    }
    for (const remediation of vulnerability.remediations) {
      lines.push(
        `**Remediation (${remediation.category}):** ${remediation.details}${
          remediation.url ? ` — ${remediation.url}` : ''
        }${remediation.restartRequired ? ` (restart: ${remediation.restartRequired})` : ''} → ${
          remediation.productIds.join(', ') || 'no product ids'
        }`,
      );
    }
    const status = vulnerability.productStatus;
    lines.push(
      `**Product status:** known_affected ${status.known_affected.join(', ') || 'none'}; fixed ${
        status.fixed.join(', ') || 'none'
      }; known_not_affected ${status.known_not_affected.join(', ') || 'none'}; recommended ${
        status.recommended.join(', ') || 'none'
      }`,
    );
    for (const note of vulnerability.notes) {
      lines.push(`**Note (${note.category}${note.title ? `, ${note.title}` : ''}):** ${note.text}`);
    }
    lines.push('');
  }
  return lines;
}

/** Render the revision-history block. */
export function renderAdvisoryRevisions(revisions: Revision[]): string[] {
  const lines = ['## Revision history'];
  for (const revision of revisions) {
    lines.push(
      `- **${revision.number}** (${revision.date})${
        revision.legacyVersion ? ` [${revision.legacyVersion}]` : ''
      } — ${revision.summary}`,
    );
  }
  lines.push('');
  return lines;
}

/** Render the references block. */
export function renderAdvisoryReferences(references: Reference[]): string[] {
  const lines = ['## References'];
  for (const reference of references) {
    lines.push(
      `- [${reference.category}] ${reference.summary ? `${reference.summary}: ` : ''}${reference.url}`,
    );
  }
  lines.push('');
  return lines;
}

/** Render the acknowledgments block. */
export function renderAdvisoryAcknowledgments(acknowledgments: Acknowledgment[]): string[] {
  const lines = ['## Acknowledgments'];
  for (const entry of acknowledgments) {
    lines.push(
      `- ${entry.organization ?? 'Unattributed'}${
        entry.names.length > 0 ? ` (${entry.names.join(', ')})` : ''
      }${entry.summary ? ` — ${entry.summary}` : ''}`,
    );
  }
  lines.push('');
  return lines;
}
