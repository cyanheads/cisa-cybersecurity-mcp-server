/**
 * @fileoverview Path composition for the Vulnrichment repository, which shards
 * CVE records into `<year>/<block>/` directories where `<block>` is the CVE's
 * numeric part with its last three characters replaced by `xxx` —
 * `CVE-2025-39964` → `2025/39xxx/`, `CVE-2026-8452` → `2026/8xxx/`.
 *
 * The default branch is `develop`; `main` returns 404.
 * @module services/vulnrichment/paths
 */

/** Raw-content base for the Vulnrichment repository's default branch. */
export const VULNRICHMENT_BASE = 'https://raw.githubusercontent.com/cisagov/vulnrichment/develop';

/** A CVE ID as the tools validate it. */
const CVE_ID = /^CVE-(\d{4})-(\d{4,19})$/i;

/**
 * Build the repository-relative path for a CVE record. Returns `null` when the
 * identifier is not a CVE ID — callers validate at the schema, so this is a
 * total-function guard rather than a runtime expectation.
 */
export function cveToVulnrichmentPath(cveId: string): string | null {
  const match = CVE_ID.exec(cveId.trim());
  if (!match?.[1] || !match[2]) return null;
  const year = match[1];
  const numeric = match[2];
  const block = `${numeric.slice(0, -3)}xxx`;
  return `${year}/${block}/CVE-${year}-${numeric}.json`;
}

/** Full raw-content URL for a CVE's Vulnrichment record. */
export function cveToVulnrichmentUrl(cveId: string): string | null {
  const path = cveToVulnrichmentPath(cveId);
  return path === null ? null : `${VULNRICHMENT_BASE}/${path}`;
}
