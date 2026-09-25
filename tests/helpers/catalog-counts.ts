/**
 * @fileoverview A matcher for corpus figures that drift with every KEV release
 * or advisory-index refresh — a thousands-grouped count, a number of entries,
 * records, distinct values, advisories, documents, or distinct CVEs, a spelled
 * small count of advisories, or a bare parenthesized count. Agent-facing text
 * built from static strings must carry none of them.
 * @module tests/helpers/catalog-counts
 */

/**
 * Matches `1,716`, `58 entries`, `(360 entries)`, `694 distinct values`,
 * `175 records`, `729 advisories`, `188 documents`, `12,321 distinct CVEs`,
 * `the two advisories`, and `(188)` — but not a directive ID such as
 * `pre-26-04 entries`, nor a parenthesized identifier such as `(CVE-2021-44228)`.
 */
export const DRIFTING_CATALOG_COUNT =
  /\b\d{1,3},\d{3}\b|(?<![-\d])\b\d+\s+(?:entries|records|distinct values|advisories|documents|distinct CVEs)\b|\bthe (?:one|two|three|four|five) advisories\b|\(\d[\d,]*\)/;
