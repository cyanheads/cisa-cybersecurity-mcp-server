/**
 * @fileoverview The KEV record output schema shared by `cisa_check_cve_status`,
 * `cisa_search_kev`, and the `cisa://kev/{cveId}` resource, plus the full and
 * summary projections and the markdown renderer both tools use.
 *
 * One shape across all three surfaces is the point: a caller that learns to read
 * a KEV record from a batch check reads the identical object out of a search hit
 * and a resource read. Error contracts stay inline per tool — this is the payload
 * schema, not the failure surface.
 * @module mcp-server/schemas/kev-record
 */

import { z } from '@cyanheads/mcp-ts-core';
import { daysBetween } from '@/services/kev-catalog/parse.js';
import type { KevRecord } from '@/services/kev-catalog/types.js';

/** The CVE ID pattern the published KEV schema declares. */
export const CVE_ID_REGEX = /^CVE-[0-9]{4}-[0-9]{4,19}$/;

/**
 * A CVE identifier as callers type it: whitespace and a lowercase `cve-` prefix
 * are normalized before the pattern check, so `" cve-2026-53266 "` is accepted as
 * `CVE-2026-53266` rather than rejected.
 */
export const CveIdInputSchema = z.string().trim().toUpperCase().regex(CVE_ID_REGEX);

/** A CWE identifier as callers type it, normalized the same way — `" cwe-79 "` is `CWE-79`. */
export const CweIdInputSchema = z
  .string()
  .trim()
  .toUpperCase()
  .regex(/^CWE-[0-9]+$/);

/** An ISO calendar date, `YYYY-MM-DD`. */
export const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;

/** One reference URL parsed out of a KEV entry's `notes` field. */
export const KevReferenceSchema = z
  .object({
    kind: z
      .enum(['nvd', 'cisa', 'bod_guidance', 'forensic_triage', 'vendor', 'other'])
      .describe(
        'What the link points at: the NVD detail record, a cisa.gov page, BOD 26-04 guidance, the forensic-triage requirements, a vendor page, or an unclassifiable URL.',
      ),
    label: z
      .string()
      .optional()
      .describe("CISA's own label for the segment, when the notes entry carried one."),
    url: z.string().describe('Absolute reference URL, verbatim from the notes field.'),
  })
  .describe('One reference URL parsed from the entry notes.');

/** A KEV entry as every KEV surface on this server returns it. */
export const KevRecordSchema = z
  .object({
    cveId: z.string().regex(CVE_ID_REGEX).describe('The CVE identifier that was looked up.'),
    inKev: z
      .boolean()
      .describe('Whether the CVE is in the KEV catalog. False is a normal result, not an error.'),
    dateAdded: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Date CISA added the entry to the catalog, YYYY-MM-DD.'),
    dueDate: z
      .string()
      .regex(ISO_DATE_REGEX)
      .optional()
      .describe('Federal remediation deadline CISA assigned, YYYY-MM-DD.'),
    daysUntilDue: z
      .number()
      .int()
      .optional()
      .describe('Whole days from the echoed asOf date to the due date; negative once overdue.'),
    overdue: z
      .boolean()
      .optional()
      .describe('True when the due date is strictly before the echoed asOf date.'),
    directive: z
      .enum(['BOD 26-04', 'BOD 22-01'])
      .nullable()
      .optional()
      .describe(
        'The binding operational directive the entry cites, or null when it cites neither — most entries name none, and none is never inferred from age.',
      ),
    requiredAction: z
      .string()
      .optional()
      .describe(
        'CISA\'s required-action text for the entry, verbatim. Absent under detail "summary".',
      ),
    vulnerabilityName: z
      .string()
      .optional()
      .describe('CISA\'s short name for the vulnerability. Absent under detail "summary".'),
    shortDescription: z
      .string()
      .optional()
      .describe('CISA\'s one-paragraph description. Absent under detail "summary".'),
    vendorProject: z
      .string()
      .optional()
      .describe("CISA's own vendor label — free text, not a CPE vendor component."),
    product: z.string().optional().describe("CISA's own product label — free text, not a CPE."),
    knownRansomwareCampaignUse: z
      .enum(['Known', 'Unknown'])
      .optional()
      .describe(
        'Whether CISA has linked the vulnerability to a ransomware campaign. Unknown means no link on record, not that none exists.',
      ),
    forensicTriage: z
      .enum(['Yes', 'No'])
      .optional()
      .describe('Whether the entry falls in the BOD 26-04 three-day forensic-triage tier.'),
    cwes: z
      .array(
        z
          .string()
          .regex(/^CWE-[0-9]+$/)
          .describe('One CWE identifier.'),
      )
      .optional()
      .describe(
        'Associated CWEs. Empty on some entries, and a CWE filter excludes those. Absent under detail "summary".',
      ),
    references: z
      .array(KevReferenceSchema)
      .optional()
      .describe(
        'Every reference URL in the notes field, in notes order, each classified by kind. Absent under detail "summary".',
      ),
    notesCommentary: z
      .string()
      .optional()
      .describe(
        'The prose segments of the notes field, verbatim with any URLs they contain; present when the notes carry prose. Absent under detail "summary".',
      ),
    kevUrl: z
      .string()
      .optional()
      .describe(
        'Absolute URL of the KEV catalog page for this CVE. Absent under detail "summary".',
      ),
  })
  .describe(
    'One KEV catalog entry, or a not-in-KEV result carrying only cveId and inKev. Under cisa_check_cve_status detail "summary" an entry carries only cveId, inKev, the dates and deadline status, directive, vendor and product labels, and the ransomware and forensic-triage flags.',
  );

/** The inferred output shape of {@link KevRecordSchema}. */
export type KevRecordOutput = z.infer<typeof KevRecordSchema>;

/** Project a domain record into the output shape, resolving the date-dependent fields. */
export function toKevRecordOutput(record: KevRecord, asOf: string): KevRecordOutput {
  const daysUntilDue = daysBetween(asOf, record.dueDate);
  return {
    cveId: record.cveId,
    inKev: true,
    dateAdded: record.dateAdded,
    dueDate: record.dueDate,
    daysUntilDue,
    overdue: record.dueDate < asOf,
    directive: record.directive,
    requiredAction: record.requiredAction,
    vulnerabilityName: record.vulnerabilityName,
    shortDescription: record.shortDescription,
    vendorProject: record.vendorProject,
    product: record.product,
    knownRansomwareCampaignUse: record.knownRansomwareCampaignUse,
    forensicTriage: record.forensicTriage,
    cwes: record.cwes,
    references: record.references,
    ...(record.notesCommentary ? { notesCommentary: record.notesCommentary } : {}),
    kevUrl: record.kevUrl,
  };
}

/**
 * The triage view `cisa_check_cve_status` returns under `detail: "summary"`:
 * identity, deadline and overdue status, directive, CISA's labels, and the two
 * tier flags, in full-record order. It drops the prose, CWEs, references, and
 * the catalog URL, which is derivable from the CVE ID.
 */
export function toKevRecordSummary(record: KevRecord, asOf: string): KevRecordOutput {
  return {
    cveId: record.cveId,
    inKev: true,
    dateAdded: record.dateAdded,
    dueDate: record.dueDate,
    daysUntilDue: daysBetween(asOf, record.dueDate),
    overdue: record.dueDate < asOf,
    directive: record.directive,
    vendorProject: record.vendorProject,
    product: record.product,
    knownRansomwareCampaignUse: record.knownRansomwareCampaignUse,
    forensicTriage: record.forensicTriage,
  };
}

/** A not-in-KEV result — a normal answer, not an error. */
export function toMissingKevOutput(cveId: string): KevRecordOutput {
  return { cveId, inKev: false };
}

/** Render one KEV record as markdown, covering every field the schema carries. */
export function renderKevRecord(record: KevRecordOutput): string[] {
  const lines: string[] = [`### ${record.cveId}`];
  if (!record.inKev) {
    lines.push('**In KEV:** no — CISA has not confirmed exploitation in the wild for this CVE.');
    return lines;
  }

  lines.push(`**In KEV:** yes${record.vulnerabilityName ? ` — ${record.vulnerabilityName}` : ''}`);
  if (record.vendorProject || record.product) {
    lines.push(
      `**Vendor / product:** ${record.vendorProject ?? 'unknown'} / ${record.product ?? 'unknown'}`,
    );
  }
  if (record.dateAdded || record.dueDate) {
    lines.push(
      `**Added:** ${record.dateAdded ?? 'unknown'} · **Due:** ${record.dueDate ?? 'unknown'}`,
    );
  }
  if (record.daysUntilDue !== undefined || record.overdue !== undefined) {
    const status = record.overdue
      ? `overdue by ${Math.abs(record.daysUntilDue ?? 0)} day(s)`
      : `${record.daysUntilDue ?? 0} day(s) remaining`;
    lines.push(
      `**Deadline status:** ${status} (overdue: ${record.overdue ? 'yes' : 'no'}, daysUntilDue: ${record.daysUntilDue ?? 0})`,
    );
  }
  if (record.directive !== undefined) {
    lines.push(`**Directive cited:** ${record.directive ?? 'none'}`);
  }
  if (record.knownRansomwareCampaignUse) {
    lines.push(`**Ransomware campaign use:** ${record.knownRansomwareCampaignUse}`);
  }
  if (record.forensicTriage) {
    lines.push(`**Forensic triage tier:** ${record.forensicTriage}`);
  }
  if (record.shortDescription) lines.push(record.shortDescription);
  if (record.requiredAction) lines.push(`**Required action:** ${record.requiredAction}`);
  if (record.cwes) {
    lines.push(`**CWEs:** ${record.cwes.length > 0 ? record.cwes.join(', ') : 'none listed'}`);
  }
  if (record.notesCommentary) lines.push(`**Notes:** ${record.notesCommentary}`);
  if (record.references && record.references.length > 0) {
    lines.push('**References:**');
    for (const reference of record.references) {
      lines.push(
        `- [${reference.kind}] ${reference.label ? `${reference.label}: ` : ''}${reference.url}`,
      );
    }
  }
  if (record.kevUrl) lines.push(`**KEV catalog entry:** ${record.kevUrl}`);
  return lines;
}
