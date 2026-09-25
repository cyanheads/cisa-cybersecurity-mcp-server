/**
 * @fileoverview Domain types for the ICS advisory mirror — the normalized
 * advisory document stored as JSON in the `document` column, the flat search row,
 * and the search filter/result envelopes.
 *
 * The normalized document is what the mirror stores, not the raw CSAF: the
 * product-tree flattening, sector extraction, and CVSS computation run once at
 * ingest rather than per read, and `cisa_get_advisory`'s section outline then
 * measures what it actually returns.
 * @module services/csaf-mirror/types
 */

import type { SeverityBand } from '@/reference/cvss.js';
import type { SectorName } from '@/reference/sectors.js';

/** Advisory series — the two prefixes the OT distribution carries. */
export type AdvisorySeries = 'ICSA' | 'ICSMA';

/** `coordinator` is CISA-authored; `other` is a republished vendor advisory. */
export type PublisherCategory = 'coordinator' | 'other';

/** Header block — identity, dates, and the source/attribution pair. */
export interface AdvisoryHeader {
  advisoryId: string;
  attribution: string;
  csafUrl: string;
  csafVersion: string;
  published: string;
  publisherCategory: string;
  publisherName: string;
  revised: string;
  revision: string;
  series: AdvisorySeries;
  status: string;
  title: string;
  url: string;
}

/** Narrative block — the document-level notes worth surfacing, plus sectors. */
export interface AdvisorySummary {
  countriesDeployed?: string;
  exploitability?: string;
  headquarters?: string;
  riskEvaluation?: string;
  sectors: SectorName[];
  sectorsRaw?: string;
  summaryText?: string;
}

/** One version entry under a product, tagged with the CSAF branch category it came from. */
export interface AdvisoryVersion {
  kind: string;
  productId: string;
  value: string;
}

/** One product under a vendor. */
export interface AdvisoryProduct {
  family?: string;
  name: string;
  versions: AdvisoryVersion[];
}

/** One vendor and its products, flattened out of the CSAF product tree. */
export interface AdvisoryVendor {
  name: string;
  products: AdvisoryProduct[];
}

/**
 * Products block — every flattened version row. `truncated` is never written by
 * current ingest; it survives only on documents stored by an older build that
 * capped rows, until the ingest-content re-ingest replaces them.
 */
export interface AdvisoryProducts {
  productCount: number;
  shownProducts: number;
  truncated?: boolean;
  vendorCount: number;
  vendors: AdvisoryVendor[];
}

/** One CVSS score attached to a vulnerability, with the derived-band flag. */
export interface AdvisoryScore {
  baseScore: number;
  baseSeverity: string;
  productIds: string[];
  severityDerived: boolean;
  vectorString: string;
  version: string;
}

/** One remediation entry. */
export interface AdvisoryRemediation {
  category: string;
  details: string;
  productIds: string[];
  restartRequired?: string;
  url?: string;
}

/** Product-status buckets, as CSAF names them. */
export interface AdvisoryProductStatus {
  fixed: string[];
  known_affected: string[];
  known_not_affected: string[];
  recommended: string[];
}

/** A note attached to a vulnerability or the document. */
export interface AdvisoryNote {
  category: string;
  text: string;
  title?: string;
}

/** One vulnerability entry. */
export interface AdvisoryVulnerability {
  cve: string;
  cweId?: string;
  cweName?: string;
  notes: AdvisoryNote[];
  productStatus: AdvisoryProductStatus;
  remediations: AdvisoryRemediation[];
  scores: AdvisoryScore[];
  title?: string;
}

/** One revision-history entry. */
export interface AdvisoryRevision {
  date: string;
  legacyVersion?: string;
  number: string;
  summary: string;
}

/** One document-level reference. */
export interface AdvisoryReference {
  category: string;
  summary?: string;
  url: string;
}

/** One acknowledgment entry. */
export interface AdvisoryAcknowledgment {
  names: string[];
  organization?: string;
  summary?: string;
}

/**
 * The normalized advisory — the exact object stored in the `document` column and
 * the exact object `cisa_get_advisory` sections against. Its top-level keys are
 * the sections the outline enumerates.
 */
export interface NormalizedAdvisory {
  acknowledgments: AdvisoryAcknowledgment[];
  advisory: AdvisoryHeader;
  products: AdvisoryProducts;
  references: AdvisoryReference[];
  revisionHistory: AdvisoryRevision[];
  summary: AdvisorySummary;
  vulnerabilities: AdvisoryVulnerability[];
}

/** The maximum CVSS score across an advisory's vulnerabilities. */
export interface AdvisoryMaxCvss {
  score: number;
  severity: SeverityBand;
  /** `true` when the band was derived from a CVSS v2 score rather than published upstream. */
  severityDerived: boolean;
  version: string;
}

/** The flat search projection returned by `cisa_search_ics_advisories`. */
export interface AdvisorySearchResult {
  advisoryId: string;
  attribution: string;
  csafUrl: string;
  cveCount: number;
  /** The first twenty CVEs, alphabetically; `cveCount` carries the full count. */
  cves: string[];
  /**
   * Every CVE the advisory covers that is in the KEV set the search was given —
   * from its complete membership, not the `cves` preview. Absent when no KEV set
   * was given.
   */
  kevCves?: string[];
  maxCvss?: AdvisoryMaxCvss;
  productCount: number;
  published: string;
  publisherCategory: string;
  revised: string;
  revision: string;
  sectors: SectorName[];
  sectorsRaw?: string;
  series: AdvisorySeries;
  title: string;
  url: string;
  vendorCount: number;
  vendors: string[];
}

/** Filters accepted by the advisory search. All AND together. */
export interface AdvisorySearchFilters {
  /** Exact CVE membership through `advisory_cves`, in canonical uppercase form. */
  cve?: string | undefined;
  cvssMax?: number | undefined;
  cvssMin?: number | undefined;
  /** Exact CWE membership through `advisory_cwes`, in canonical uppercase form, e.g. `CWE-787`. */
  cwe?: string | undefined;
  /**
   * `true` keeps advisories covering at least one CVE in the KEV set passed to
   * `search()`; `false` keeps those covering none. Requires that set.
   */
  inKev?: boolean | undefined;
  limit: number;
  offset: number;
  order: 'asc' | 'desc';
  product?: string | undefined;
  publishedFrom?: string | undefined;
  publishedTo?: string | undefined;
  publisher?: PublisherCategory | undefined;
  q?: string | undefined;
  revisedFrom?: string | undefined;
  revisedTo?: string | undefined;
  sector?: SectorName | undefined;
  series?: AdvisorySeries | undefined;
  severity?: SeverityBand | undefined;
  sortBy: 'relevance' | 'published' | 'revised' | 'maxCvss';
  vendor?: string | undefined;
}

/** One filter the advisory search applies, by the name the caller sets it under. */
export type AdvisoryFilterKey = Exclude<
  keyof AdvisorySearchFilters,
  'limit' | 'offset' | 'order' | 'sortBy'
>;

/** How one applied filter behaves against the whole index. */
export interface AdvisoryFilterCount {
  /** Advisories this filter matches on its own. */
  alone: number;
  filter: AdvisoryFilterKey;
  /** Advisories that fail this filter and pass every other applied one — what dropping it restores. */
  restoredByDropping: number;
}

/** One page of advisory search results. */
export interface AdvisorySearchPage {
  items: AdvisorySearchResult[];
  total: number;
}

/**
 * Which ingest build the index content comes from. A `stale` index still serves
 * every row it holds, but rows may lack what the current ingest derives — until
 * the background re-ingest completes, the `advisory_cwes` junction may be empty or
 * partial, so a zero-hit `cwe` search is not proof that nothing matches.
 */
export interface IngestContentState {
  /** The content version this build's ingest writes. */
  current: number;
  /** `true` when `stored` is absent or lower than `current`. */
  stale: boolean;
  /** The version the last completed full ingest recorded; `null` when none was recorded. */
  stored: number | null;
}

/**
 * Why the index store cannot be opened: the location is not writable, the
 * filesystem or database is read-only, a directory on the path is missing, a
 * path component is a regular file, or the file at the path is not a SQLite
 * database.
 */
export const STORE_UNAVAILABLE_REASONS = [
  'not_writable',
  'read_only',
  'missing_directory',
  'not_a_directory',
  'not_a_database',
] as const;

/** One of {@link STORE_UNAVAILABLE_REASONS}. */
export type StoreUnavailableReason = (typeof STORE_UNAVAILABLE_REASONS)[number];

/** What `cisa_list_reference` topic `sources` reports about the mirror tier. */
export interface CsafMirrorState {
  checkpoint: string | null;
  documentCount: number | null;
  lastCompletedAt: string | null;
  ready: boolean;
  syncStatus: string;
  /** Present only when the store cannot be opened and the failure was classified. */
  unavailableReason?: StoreUnavailableReason;
}
