/**
 * @fileoverview Pure normalization for CSAF ICS advisories — advisory-ID
 * normalization, product-tree flattening, CVSS computation, sector extraction,
 * the `changes.csv` manifest parser, and the FTS5 `MATCH` builder. No network, no
 * database: every function here takes a parsed document (or a string) and returns
 * plain data, which is what makes the whole ingest path unit-testable against a
 * fixture.
 * @module services/csaf-mirror/normalize
 */

import type { MirrorRow } from '@cyanheads/mcp-ts-core/mirror';
import { deriveCvssV2Severity, deriveCvssV3Severity } from '@/reference/cvss.js';
import { extractSectors, SECTOR_NOTE_TITLE } from '@/reference/sectors.js';
import { assertSearchTextLength } from '@/services/search-text.js';
import type {
  AdvisoryAcknowledgment,
  AdvisoryHeader,
  AdvisoryMaxCvss,
  AdvisoryNote,
  AdvisoryProducts,
  AdvisoryReference,
  AdvisoryRemediation,
  AdvisoryRevision,
  AdvisoryScore,
  AdvisorySeries,
  AdvisorySummary,
  AdvisoryVendor,
  AdvisoryVulnerability,
  NormalizedAdvisory,
} from './types.js';

/** Raw-content base for the CSAF repository's OT (ICS) distribution. */
export const CSAF_OT_BASE =
  'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white';

/**
 * The advisory-ID pattern, case-insensitive. Both real suffix forms are covered:
 * a single letter (120 documents carry `a`–`f`) and the one numeric form,
 * `ICSA-16-231-01-0`. `ICS[AM]` would spell `ICSA` or `ICSM` and reject all 188
 * `ICSMA-` advisories, so the alternation is spelled out.
 */
export const ADVISORY_ID_PATTERN = /^ICS(A|MA)-\d{2}-\d{3}-\d{2}(?:[a-z]|-\d+)?$/i;

/**
 * The same pattern for caller input, which may carry the filename's `.json`
 * suffix and surrounding whitespace; {@link normalizeAdvisoryId} strips both.
 */
export const ADVISORY_ID_INPUT_PATTERN =
  /^\s*ICS(A|MA)-\d{2}-\d{3}-\d{2}(?:[a-z]|-\d+)?(?:\.json)?\s*$/i;

/** Flattened version rows kept in an advisory's products arm. */
export const PRODUCT_ROW_CAP = 200;

/**
 * The shape of a document path inside a distribution directory: a four-digit
 * year, one filename, `.json`. Every distribution publishes exactly this —
 * `2026/icsa-26-260-07.json`, `2019/icsma-19-253-02.json`, `2026/va-26-260-01.json`.
 *
 * Paths arrive from `changes.csv` and from archive entry names, both of which
 * are upstream text rather than anything this server composed. A path is
 * appended to the distribution base to build the fetch URL of the document and
 * the `csafUrl` every advisory response carries, so one carrying `../`, a
 * second directory, a query, or a fragment would point both at something other
 * than the advisory it claims to be. Anything off this shape is not addressable
 * as an advisory and is dropped.
 */
const CSAF_SOURCE_PATH = /^\d{4}\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/;

/** Whether a repository-relative path is addressable as an advisory document. */
export function isCsafSourcePath(path: string): boolean {
  return CSAF_SOURCE_PATH.test(path);
}

/**
 * Normalize a caller-supplied advisory ID: trim, strip a trailing `.json`, and
 * uppercase. Each step is one-to-one and meaning-preserving — the document spells
 * the ID uppercase and the filename spells it lowercase, so both must resolve.
 */
export function normalizeAdvisoryId(input: string): string {
  return input
    .trim()
    .replace(/\.json$/i, '')
    .toUpperCase();
}

/** The series prefix an advisory ID carries. */
export function advisorySeries(advisoryId: string): AdvisorySeries {
  return advisoryId.toUpperCase().startsWith('ICSMA') ? 'ICSMA' : 'ICSA';
}

/** Whether a URL is an https advisory page served by cisa.gov itself. */
function isCisaAdvisoryUrl(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  const host = parsed.hostname.toLowerCase();
  return (
    parsed.protocol === 'https:' &&
    (host === 'cisa.gov' || host.endsWith('.cisa.gov')) &&
    parsed.pathname.includes('/news-events/ics')
  );
}

/** The cisa.gov web path for an advisory, by series. */
export function advisoryWebUrl(advisoryId: string): string {
  const segment =
    advisorySeries(advisoryId) === 'ICSMA' ? 'ics-medical-advisories' : 'ics-advisories';
  return `https://www.cisa.gov/news-events/${segment}/${advisoryId.toLowerCase()}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

/** Fold a note title for comparison: lowercase, whitespace collapsed. */
function foldTitle(value: unknown): string {
  return typeof value === 'string' ? value.toLowerCase().replace(/\s+/g, ' ').trim() : '';
}

// ── Product tree ────────────────────────────────────────────────────────────

/** Branch categories that append to a version label rather than opening a level. */
const LABEL_SUFFIX_CATEGORIES = new Set(['specification', 'service_pack', 'patch_level']);

interface FlattenState {
  family: string | undefined;
  productName: string | undefined;
  suffixes: string[];
  vendor: string | undefined;
}

/**
 * Walk the CSAF product tree and flatten it into vendor → product → versions.
 * A branch carrying `product.product_id` is a leaf: the `CSAFPID-*` token is what
 * a vulnerability entry references, so it is kept — it is how a caller maps a CVE
 * to the exact affected versions.
 *
 * `productCount` counts every leaf in the tree; the returned vendor structure is
 * capped at {@link PRODUCT_ROW_CAP} version rows, because a single advisory can
 * carry 585 products and the section outline treats `products` as one indivisible
 * section.
 */
export function flattenProductTree(productTree: unknown): AdvisoryProducts {
  const vendors = new Map<
    string,
    Map<string, { family?: string; versions: AdvisoryVersionRow[] }>
  >();
  let productCount = 0;
  let shownProducts = 0;

  const walk = (branches: unknown, state: FlattenState): void => {
    if (!Array.isArray(branches)) return;
    for (const branch of branches) {
      if (!isRecord(branch)) continue;
      const category = str(branch.category) ?? '';
      const name = str(branch.name) ?? '';
      const next: FlattenState = { ...state, suffixes: [...state.suffixes] };

      if (category === 'vendor') next.vendor = name;
      else if (category === 'product_family') next.family = name;
      else if (category === 'product_name') next.productName = name;
      else if (LABEL_SUFFIX_CATEGORIES.has(category) && name !== '') next.suffixes.push(name);

      const product = isRecord(branch.product) ? branch.product : undefined;
      const productId = product ? str(product.product_id) : undefined;
      if (productId) {
        productCount += 1;
        if (shownProducts < PRODUCT_ROW_CAP) {
          shownProducts += 1;
          const vendorName = next.vendor ?? 'Unspecified';
          const productLabel = next.productName ?? str(product?.name) ?? name ?? 'Unspecified';
          const value = [name || (str(product?.name) ?? ''), ...next.suffixes]
            .filter(Boolean)
            .join(' ');

          const products = vendors.get(vendorName) ?? new Map();
          vendors.set(vendorName, products);
          const entry = products.get(productLabel) ?? {
            ...(next.family ? { family: next.family } : {}),
            versions: [],
          };
          products.set(productLabel, entry);
          entry.versions.push({ kind: category || 'product', value, productId });
        }
      }

      walk(branch.branches, next);
    }
  };

  walk(isRecord(productTree) ? productTree.branches : undefined, {
    vendor: undefined,
    family: undefined,
    productName: undefined,
    suffixes: [],
  });

  const flattened: AdvisoryVendor[] = [...vendors.entries()].map(([name, products]) => ({
    name,
    products: [...products.entries()].map(([productName, entry]) => ({
      name: productName,
      ...(entry.family ? { family: entry.family } : {}),
      versions: entry.versions,
    })),
  }));

  return {
    vendorCount: flattened.length,
    productCount,
    vendors: flattened,
    shownProducts,
    ...(productCount > shownProducts ? { truncated: true } : {}),
  };
}

/** Internal alias so the walker's row shape reads clearly above. */
type AdvisoryVersionRow = { kind: string; productId: string; value: string };

// ── CVSS ────────────────────────────────────────────────────────────────────

/** Read the CVSS scores attached to one vulnerability entry. */
export function readScores(vulnerability: Record<string, unknown>): AdvisoryScore[] {
  const raw = Array.isArray(vulnerability.scores) ? vulnerability.scores : [];
  const scores: AdvisoryScore[] = [];

  for (const entry of raw) {
    if (!isRecord(entry)) continue;
    const productIds = strings(entry.products);

    const v3 = isRecord(entry.cvss_v3) ? entry.cvss_v3 : undefined;
    if (v3 && typeof v3.baseScore === 'number') {
      const upstream = str(v3.baseSeverity);
      scores.push({
        version: str(v3.version) ?? '3.x',
        baseScore: v3.baseScore,
        baseSeverity: upstream ?? deriveCvssV3Severity(v3.baseScore),
        severityDerived: upstream === undefined,
        vectorString: str(v3.vectorString) ?? '',
        productIds,
      });
    }

    const v2 = isRecord(entry.cvss_v2) ? entry.cvss_v2 : undefined;
    if (v2 && typeof v2.baseScore === 'number') {
      /* cvss_v2 never carries baseSeverity across all 697 occurrences. */
      const upstream = str(v2.baseSeverity);
      scores.push({
        version: str(v2.version) ?? '2.0',
        baseScore: v2.baseScore,
        baseSeverity: upstream ?? deriveCvssV2Severity(v2.baseScore),
        severityDerived: upstream === undefined,
        vectorString: str(v2.vectorString) ?? '',
        productIds,
      });
    }
  }

  return scores;
}

/**
 * The maximum base score across every vulnerability's scores.
 * `document.aggregate_severity` exists on only 52 of 3,926 documents, so it can
 * never back a severity filter and is not consulted.
 */
export function computeMaxCvss(
  vulnerabilities: AdvisoryVulnerability[],
): AdvisoryMaxCvss | undefined {
  let best: AdvisoryScore | undefined;
  for (const vulnerability of vulnerabilities) {
    for (const score of vulnerability.scores) {
      if (!best || score.baseScore > best.baseScore) best = score;
    }
  }
  if (!best) return undefined;

  const isV2 = best.version.startsWith('2');
  return {
    score: best.baseScore,
    severity: isV2 ? deriveCvssV2Severity(best.baseScore) : deriveCvssV3Severity(best.baseScore),
    version: best.version,
    severityDerived: best.severityDerived,
  };
}

// ── Notes, references, acknowledgments ──────────────────────────────────────

function readNotes(value: unknown): AdvisoryNote[] {
  if (!Array.isArray(value)) return [];
  const notes: AdvisoryNote[] = [];
  for (const note of value) {
    if (!isRecord(note)) continue;
    const text = str(note.text);
    if (!text) continue;
    const title = str(note.title);
    notes.push({
      category: str(note.category) ?? 'other',
      ...(title ? { title } : {}),
      text,
    });
  }
  return notes;
}

/** Find a document note by folded title, tolerating case and spacing drift. */
function noteByTitle(notes: AdvisoryNote[], folded: string): string | undefined {
  return notes.find((note) => foldTitle(note.title) === folded)?.text;
}

function readReferences(value: unknown): AdvisoryReference[] {
  if (!Array.isArray(value)) return [];
  const references: AdvisoryReference[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    const url = str(entry.url);
    if (!url) continue;
    const summary = str(entry.summary);
    references.push({
      category: str(entry.category) ?? 'external',
      ...(summary ? { summary } : {}),
      url,
    });
  }
  return references;
}

function readAcknowledgments(value: unknown): AdvisoryAcknowledgment[] {
  if (!Array.isArray(value)) return [];
  const acknowledgments: AdvisoryAcknowledgment[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    const organization = str(entry.organization);
    const summary = str(entry.summary);
    acknowledgments.push({
      ...(organization ? { organization } : {}),
      names: strings(entry.names),
      ...(summary ? { summary } : {}),
    });
  }
  return acknowledgments;
}

function readRevisionHistory(value: unknown): AdvisoryRevision[] {
  if (!Array.isArray(value)) return [];
  const revisions: AdvisoryRevision[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    const legacyVersion = str(entry.legacy_version);
    revisions.push({
      number: str(entry.number) ?? '',
      date: str(entry.date) ?? '',
      summary: str(entry.summary) ?? '',
      ...(legacyVersion ? { legacyVersion } : {}),
    });
  }
  return revisions;
}

/**
 * Build the attribution string every advisory response carries. It is
 * unconditional rather than conditional on `publisher.category`, because a caller
 * should not have to branch on a field to know whether the text is safe to
 * redistribute: the CSAF repository declares no license, and 1,063 of its 3,926
 * ICS advisories are CISA republications of a vendor's own advisory text.
 */
export function buildAttribution(
  publisherName: string,
  publisherCategory: string,
  csafUrl: string,
  revisionHistory: AdvisoryRevision[],
): string {
  if (publisherCategory === 'other') {
    const republication = revisionHistory.find(
      (entry) =>
        /republication/i.test(entry.legacyVersion ?? '') || /republication/i.test(entry.summary),
    );
    const provenance = republication?.summary
      ? ` Revision history records: "${republication.summary}".`
      : '';
    return `Republished by ${publisherName} from an originating vendor advisory (publisher category: other); the advisory text is the vendor's own.${provenance} Source: ${csafUrl}. The CISA CSAF repository declares no license — check the originating vendor's terms before redistributing.`;
  }
  return `Authored by ${publisherName} (publisher category: ${publisherCategory}). Source: ${csafUrl}. The CISA CSAF repository declares no license — cite the source when redistributing.`;
}

// ── Whole-document normalization ────────────────────────────────────────────

/**
 * Normalize one raw CSAF document into the stored shape. Returns `null` when the
 * document carries no `tracking.id` — the key every surface addresses it by.
 *
 * @param raw - The parsed CSAF 2.0 document.
 * @param sourcePath - Repository-relative path under the OT distribution, e.g. `2026/icsa-26-260-07.json`.
 */
export function normalizeAdvisory(raw: unknown, sourcePath: string): NormalizedAdvisory | null {
  if (!isRecord(raw) || !isRecord(raw.document)) return null;
  const document = raw.document;
  const tracking = isRecord(document.tracking) ? document.tracking : {};
  const advisoryId = normalizeAdvisoryId(str(tracking.id) ?? '');
  if (advisoryId === '') return null;

  const publisher = isRecord(document.publisher) ? document.publisher : {};
  const documentNotes = readNotes(document.notes);
  const references = readReferences(document.references);
  const revisionHistory = readRevisionHistory(tracking.revision_history);

  const csafUrl = `${CSAF_OT_BASE}/${sourcePath}`;
  /* The self reference is the advisory's own web version, and the advisory is
   * upstream text — so the host is checked rather than assumed. Off cisa.gov it
   * is not the page this field promises, and the ID composes the real one. */
  const selfWeb = references.find(
    (reference) => reference.category === 'self' && isCisaAdvisoryUrl(reference.url),
  );
  const url = selfWeb?.url ?? advisoryWebUrl(advisoryId);

  const sectorsRaw = noteByTitle(documentNotes, SECTOR_NOTE_TITLE);
  const publisherName = str(publisher.name) ?? 'CISA';
  const publisherCategory = str(publisher.category) ?? 'coordinator';

  const advisory: AdvisoryHeader = {
    advisoryId,
    title: str(document.title) ?? advisoryId,
    series: advisorySeries(advisoryId),
    status: str(tracking.status) ?? '',
    csafVersion: str(document.csaf_version) ?? '',
    published: str(tracking.initial_release_date) ?? '',
    revised: str(tracking.current_release_date) ?? '',
    revision: str(tracking.version) ?? '',
    publisherCategory,
    publisherName,
    url,
    csafUrl,
    attribution: buildAttribution(publisherName, publisherCategory, csafUrl, revisionHistory),
  };

  const summaryText =
    noteByTitle(documentNotes, 'advisory summary') ??
    noteByTitle(documentNotes, 'executive summary') ??
    noteByTitle(documentNotes, 'overview') ??
    documentNotes.find((note) => note.category === 'summary')?.text;

  const riskEvaluation = noteByTitle(documentNotes, 'risk evaluation');
  const exploitability = noteByTitle(documentNotes, 'exploitability');
  const countriesDeployed = noteByTitle(documentNotes, 'countries/areas deployed');
  const headquarters = noteByTitle(documentNotes, 'company headquarters location');

  const summary: AdvisorySummary = {
    ...(riskEvaluation ? { riskEvaluation } : {}),
    ...(exploitability ? { exploitability } : {}),
    ...(summaryText ? { summaryText } : {}),
    sectors: sectorsRaw ? extractSectors(sectorsRaw) : [],
    ...(sectorsRaw ? { sectorsRaw } : {}),
    ...(countriesDeployed ? { countriesDeployed } : {}),
    ...(headquarters ? { headquarters } : {}),
  };

  const vulnerabilities: AdvisoryVulnerability[] = [];
  const rawVulnerabilities = Array.isArray(raw.vulnerabilities) ? raw.vulnerabilities : [];
  for (const entry of rawVulnerabilities) {
    if (!isRecord(entry)) continue;
    const cve = str(entry.cve);
    if (!cve) continue;
    /* `vulnerabilities[].cwe` is always a single object across 14,461 occurrences. */
    const cwe = isRecord(entry.cwe) ? entry.cwe : undefined;
    const status = isRecord(entry.product_status) ? entry.product_status : {};
    const remediations: AdvisoryRemediation[] = [];
    for (const remediation of Array.isArray(entry.remediations) ? entry.remediations : []) {
      if (!isRecord(remediation)) continue;
      const restart = isRecord(remediation.restart_required)
        ? str(remediation.restart_required.category)
        : undefined;
      const url = str(remediation.url);
      remediations.push({
        category: str(remediation.category) ?? 'other',
        details: str(remediation.details) ?? '',
        ...(url ? { url } : {}),
        productIds: strings(remediation.product_ids),
        ...(restart ? { restartRequired: restart } : {}),
      });
    }

    const cweId = cwe ? str(cwe.id) : undefined;
    const cweName = cwe ? str(cwe.name) : undefined;
    const vulnerabilityTitle = str(entry.title);
    vulnerabilities.push({
      cve: cve.toUpperCase(),
      ...(cweId ? { cweId } : {}),
      ...(cweName ? { cweName } : {}),
      ...(vulnerabilityTitle ? { title: vulnerabilityTitle } : {}),
      scores: readScores(entry),
      remediations,
      productStatus: {
        known_affected: strings(status.known_affected),
        fixed: strings(status.fixed),
        known_not_affected: strings(status.known_not_affected),
        recommended: strings(status.recommended),
      },
      notes: readNotes(entry.notes),
    });
  }

  return {
    advisory,
    summary,
    products: flattenProductTree(raw.product_tree),
    vulnerabilities,
    revisionHistory,
    references,
    acknowledgments: readAcknowledgments(document.acknowledgments),
  };
}

/** Project a normalized advisory into the flat mirror row. */
export function toMirrorRow(doc: NormalizedAdvisory, sourcePath: string): MirrorRow {
  const maxCvss = computeMaxCvss(doc.vulnerabilities);
  const vendorNames = doc.products.vendors.map((vendor) => vendor.name);
  const productNames = doc.products.vendors.flatMap((vendor) =>
    vendor.products.map((product) => product.name),
  );
  const cves = [...new Set(doc.vulnerabilities.map((vulnerability) => vulnerability.cve))];

  return {
    advisoryId: doc.advisory.advisoryId,
    series: doc.advisory.series,
    title: doc.advisory.title,
    vendorsText: vendorNames.join(' | '),
    productsText: productNames.join(' | '),
    vendorCount: doc.products.vendorCount,
    productCount: doc.products.productCount,
    cveCount: cves.length,
    maxCvss: maxCvss?.score ?? null,
    maxCvssSeverity: maxCvss?.severity ?? null,
    maxCvssVersion: maxCvss?.version ?? null,
    sectorsText: doc.summary.sectors.join(' | '),
    sectorsRaw: doc.summary.sectorsRaw ?? null,
    published: doc.advisory.published,
    revised: doc.advisory.revised,
    revision: doc.advisory.revision,
    publisherCategory: doc.advisory.publisherCategory,
    sourcePath,
    url: doc.advisory.url,
    csafUrl: doc.advisory.csafUrl,
    /* Column rather than a read-time parse: search projects it on every row, and
     * parsing a 1.38 MB document per result to recover one string is not a read path. */
    attribution: doc.advisory.attribution,
    document: JSON.stringify(doc),
  };
}

// ── Manifest + query helpers ────────────────────────────────────────────────

/** One row of the `changes.csv` manifest. */
export interface ChangeRow {
  path: string;
  timestamp: string;
}

/**
 * Parse the `changes.csv` manifest. Quoting is inconsistent across the
 * repository's distributions — the OT and VA distributions quote both fields and
 * use microsecond timestamps, the IT distribution is unquoted with second
 * precision — so both forms are accepted. The file is a full manifest rather than
 * an append-only log, which is what makes deletions detectable.
 *
 * Rows whose path is not addressable as an advisory document are dropped; see
 * {@link isCsafSourcePath} for what that path is allowed to look like and why.
 */
export function parseChangesCsv(text: string): ChangeRow[] {
  const rows: ChangeRow[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '') continue;
    const quoted = /^"([^"]*)"\s*,\s*"([^"]*)"$/.exec(line);
    if (quoted?.[1] && quoted[2]) {
      if (isCsafSourcePath(quoted[1])) rows.push({ path: quoted[1], timestamp: quoted[2] });
      continue;
    }
    const comma = line.indexOf(',');
    if (comma === -1) continue;
    const path = line.slice(0, comma).trim().replace(/^"|"$/g, '');
    const timestamp = line
      .slice(comma + 1)
      .trim()
      .replace(/^"|"$/g, '');
    if (isCsafSourcePath(path) && timestamp !== '') rows.push({ path, timestamp });
  }
  return rows;
}

/**
 * Build an FTS5 `MATCH` expression from caller free text. Each token is stripped
 * of embedded quotes and wrapped in double quotes, which neutralizes every FTS5
 * operator (`-`, `*`, `:`, `NEAR`, `AND`, `OR`, `NOT`), so reserved syntax in
 * caller input cannot alter the query or raise a SQLite syntax error. Tokens are
 * AND-combined. Returns an empty string when the input has no searchable tokens.
 *
 * Length is checked first: the expression this builds is roughly the size of its
 * input, and FTS5 parses the whole of it before any row is examined.
 */
export function toFtsMatch(input: string): string {
  assertSearchTextLength(input, 'q');
  return input
    .trim()
    .split(/\s+/)
    .map((token) => token.replace(/"/g, '').trim())
    .filter((token) => token.length > 0)
    .map((token) => `"${token}"`)
    .join(' AND ');
}
