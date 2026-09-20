/**
 * @fileoverview Pure normalization for KEV feed records — the `notes` parser,
 * the reference classifier, and the raw-record-to-domain-record mapper. No I/O,
 * no clock: every time-dependent value (`overdue`, `daysUntilDue`) is computed at
 * query time against an explicit `asOf` date, not baked into the snapshot.
 * @module services/kev-catalog/parse
 */

import type { KevDirective, KevRecord, KevReference, KevReferenceKind } from './types.js';

/** Canonical catalog entry URL for a CVE — the same link CISA's own enrichment cites. */
export function kevCatalogUrl(cveId: string): string {
  return `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${cveId}`;
}

/** Labels CISA uses on `notes` segments, mapped to the reference kind they imply. */
const LABEL_KINDS: ReadonlyArray<readonly [RegExp, KevReferenceKind]> = [
  [/^bod\s/i, 'bod_guidance'],
  [/^forensics?\s+triage/i, 'forensic_triage'],
  [/^cisa\s/i, 'cisa'],
];

/**
 * Classify a reference URL. A recognized segment label wins — it states CISA's
 * own intent for the link — and anything else falls back to the host: the NVD
 * detail path, any cisa.gov host, otherwise a vendor link. A string that does not
 * parse as a URL is `other`.
 */
export function classifyReference(url: string, label?: string): KevReferenceKind {
  if (label) {
    for (const [pattern, kind] of LABEL_KINDS) {
      if (pattern.test(label)) return kind;
    }
  }
  let host: string;
  let pathname: string;
  try {
    const parsed = new URL(url);
    host = parsed.hostname.toLowerCase();
    pathname = parsed.pathname;
  } catch {
    return 'other';
  }
  if (host === 'nvd.nist.gov' && pathname.startsWith('/vuln/detail/')) return 'nvd';
  if (host === 'cisa.gov' || host.endsWith('.cisa.gov')) return 'cisa';
  return 'vendor';
}

/** A leading `<Label>:` on a `notes` segment, with the rest of the segment after it. */
const LABELED_SEGMENT = /^([^:]{1,60}):\s*(https?:\/\/\S+)$/;

/** Parsed shape of a KEV entry's `notes` field. */
export interface ParsedKevNotes {
  commentary?: string;
  references: KevReference[];
}

/**
 * Split a KEV `notes` value into references and free prose. Segments are
 * `;`-delimited; a segment shaped `<Label>: <url>` yields a labeled reference, a
 * bare URL yields an unlabeled one classified by host, and anything else is
 * commentary (116 of 1,716 entries open with prose). Every reference keeps the
 * label verbatim so a caller sees CISA's own wording.
 */
export function parseKevNotes(notes: string): ParsedKevNotes {
  const references: KevReference[] = [];
  const prose: string[] = [];

  for (const raw of notes.split(';')) {
    const segment = raw.trim();
    if (segment === '') continue;

    const labeled = LABELED_SEGMENT.exec(segment);
    if (labeled?.[1] && labeled[2] && !/^https?$/i.test(labeled[1])) {
      const label = labeled[1].trim();
      references.push({ kind: classifyReference(labeled[2], label), label, url: labeled[2] });
      continue;
    }

    if (/^https?:\/\/\S+$/i.test(segment)) {
      references.push({ kind: classifyReference(segment), url: segment });
      continue;
    }

    prose.push(segment);
  }

  const commentary = prose.join('; ').trim();
  return { references, ...(commentary ? { commentary } : {}) };
}

/**
 * Read the directive a KEV entry cites from its `requiredAction` and `notes`.
 * BOD 26-04 wins when both appear (it supersedes and revokes 22-01); neither
 * present yields `null` rather than an inference from the entry's age.
 */
export function readDirective(requiredAction: string, notes: string): KevDirective {
  const haystack = `${requiredAction}\n${notes}`;
  if (/\bBOD\s*26-04\b/i.test(haystack)) return 'BOD 26-04';
  if (/\bBOD\s*22-01\b/i.test(haystack)) return 'BOD 22-01';
  return null;
}

/**
 * The shapes every KEV surface advertises for the three fields it is addressed
 * and sorted by. Defined here rather than imported from the output schema, which
 * imports this module.
 */
const CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,19}$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const CWE_ID = /^CWE-[0-9]+$/;

/** One raw record from the KEV feed, typed as the published schema describes it. */
export interface RawKevRecord {
  cveID?: unknown;
  cwes?: unknown;
  dateAdded?: unknown;
  dueDate?: unknown;
  forensicTriage?: unknown;
  knownRansomwareCampaignUse?: unknown;
  notes?: unknown;
  product?: unknown;
  requiredAction?: unknown;
  shortDescription?: unknown;
  vendorProject?: unknown;
  vulnerabilityName?: unknown;
}

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * Map one raw feed record to the normalized domain record. Returns `null` for an
 * entry this server cannot serve: no CVE ID in the pattern every surface
 * addresses it by, or no `dateAdded` / `dueDate` in the calendar-date shape the
 * deadline fields are declared as.
 *
 * The feed is upstream text, and these three fields are published under exactly
 * these patterns on the surfaces that return them — so one entry that drifts off
 * shape would fail validation for the whole page it lands on, taking a search
 * down rather than itself. All three are required by the published KEV schema
 * and present on every record in the live catalog; dropping one that is not
 * costs an entry nothing can look up anyway.
 */
export function toKevRecord(raw: RawKevRecord): KevRecord | null {
  const cveId = str(raw.cveID).toUpperCase();
  if (!CVE_ID.test(cveId)) return null;

  const dateAdded = str(raw.dateAdded);
  const dueDate = str(raw.dueDate);
  if (!ISO_DATE.test(dateAdded) || !ISO_DATE.test(dueDate)) return null;

  const notes = str(raw.notes);
  const requiredAction = str(raw.requiredAction);
  const parsed = parseKevNotes(notes);

  return {
    cveId,
    vendorProject: str(raw.vendorProject),
    product: str(raw.product),
    vulnerabilityName: str(raw.vulnerabilityName),
    dateAdded,
    shortDescription: str(raw.shortDescription),
    requiredAction,
    dueDate,
    knownRansomwareCampaignUse:
      str(raw.knownRansomwareCampaignUse) === 'Known' ? 'Known' : 'Unknown',
    forensicTriage: str(raw.forensicTriage) === 'Yes' ? 'Yes' : 'No',
    /* `cwes` is optional upstream and published under this pattern; a member off
     * it is dropped rather than carried into a result page it would invalidate. */
    cwes: Array.isArray(raw.cwes)
      ? raw.cwes.filter((cwe): cwe is string => typeof cwe === 'string' && CWE_ID.test(cwe))
      : [],
    references: parsed.references,
    ...(parsed.commentary ? { notesCommentary: parsed.commentary } : {}),
    directive: readDirective(requiredAction, notes),
    kevUrl: kevCatalogUrl(cveId),
  };
}

/** Whole days from `from` to `to`, both `YYYY-MM-DD`. Negative when `to` is earlier. */
export function daysBetween(from: string, to: string): number {
  const start = Date.parse(`${from}T00:00:00Z`);
  const end = Date.parse(`${to}T00:00:00Z`);
  if (Number.isNaN(start) || Number.isNaN(end)) return 0;
  return Math.round((end - start) / 86_400_000);
}
