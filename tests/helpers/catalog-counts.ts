/**
 * @fileoverview A matcher for KEV catalog figures that drift with every release —
 * a thousands-grouped count, or a number of entries, records, or distinct
 * values. Agent-facing text built from static strings must carry none of them.
 * @module tests/helpers/catalog-counts
 */

/**
 * Matches `1,716`, `58 entries`, `(360 entries)`, `694 distinct values`,
 * `175 records` — but not a directive ID such as `pre-26-04 entries`.
 */
export const DRIFTING_CATALOG_COUNT =
  /\b\d{1,3},\d{3}\b|(?<![-\d])\b\d+\s+(?:entries|records|distinct values)\b/;
