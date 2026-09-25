/**
 * @fileoverview Domain types for the KEV catalog snapshot — the normalized
 * record shape every KEV surface returns, the parsed `notes` references, and the
 * in-memory snapshot with its derived indexes.
 * @module services/kev-catalog/types
 */

/** Classification of a URL parsed out of a KEV entry's `notes` field. */
export type KevReferenceKind =
  | 'nvd'
  | 'cisa'
  | 'bod_guidance'
  | 'forensic_triage'
  | 'vendor'
  | 'other';

/** One reference URL parsed from `notes`, with its label when the segment carried one. */
export interface KevReference {
  kind: KevReferenceKind;
  label?: string;
  url: string;
}

/**
 * The binding operational directive a KEV entry cites, or `null` when it cites
 * none. Most entries name neither (1,277 of 1,716 at catalog 2026.09.18) — `null`
 * is the honest value for those and is never inferred from an entry's age.
 */
export type KevDirective = 'BOD 26-04' | 'BOD 22-01' | null;

/** A KEV entry, normalized once at snapshot time. */
export interface KevRecord {
  cveId: string;
  cwes: string[];
  dateAdded: string;
  directive: KevDirective;
  dueDate: string;
  forensicTriage: 'Yes' | 'No';
  kevUrl: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  notesCommentary?: string;
  product: string;
  references: KevReference[];
  requiredAction: string;
  shortDescription: string;
  vendorProject: string;
  vulnerabilityName: string;
}

/** The parsed KEV feed envelope plus the records and derived indexes. */
export interface KevSnapshot {
  byDateAdded: KevRecord[];
  byDueDate: KevRecord[];
  byId: Map<string, KevRecord>;
  catalogVersion: string;
  count: number;
  dateReleased: string;
  fetchedAt: string;
  lastModified?: string;
  records: KevRecord[];
}

/** What `cisa_list_reference` topic `sources` reports about the KEV tier. */
export interface KevCatalogState {
  catalogVersion: string | null;
  count: number | null;
  dateReleased: string | null;
  lastCheckedAt: string | null;
  lastModified: string | null;
  refreshCron: string;
}
