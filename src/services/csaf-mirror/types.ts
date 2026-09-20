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

/** Products block, capped at a fixed number of flattened version rows. */
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
  cves: string[];
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
  cve?: string | undefined;
  cvssMax?: number | undefined;
  cvssMin?: number | undefined;
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

/** One page of advisory search results. */
export interface AdvisorySearchPage {
  items: AdvisorySearchResult[];
  total: number;
}

/** What `cisa_list_reference` topic `sources` reports about the mirror tier. */
export interface CsafMirrorState {
  checkpoint: string | null;
  documentCount: number | null;
  lastCompletedAt: string | null;
  path: string;
  ready: boolean;
  syncStatus: string;
}
