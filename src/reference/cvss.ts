/**
 * @fileoverview CVSS severity bands and the v2 derivation. The advisory corpus
 * publishes `baseSeverity` on every `cvss_v3` score and on none of the 697
 * `cvss_v2` scores, so a v2-only advisory's band has to be derived from the v2
 * thresholds and flagged as derived rather than presented as upstream's.
 *
 * The two scales differ: CVSS v2 tops out at HIGH (7.0–10.0) and has no CRITICAL
 * band, so a 10.0 v2 score is HIGH, not CRITICAL. Collapsing them would invent a
 * severity CISA never published.
 * @module reference/cvss
 */

/** CVSS severity bands as the v3 scale names them. */
export const SEVERITY_BANDS = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

/** One of the five severity band labels. */
export type SeverityBand = (typeof SEVERITY_BANDS)[number];

/** Band a CVSS v3.x base score against the v3 qualitative severity scale. */
export function deriveCvssV3Severity(score: number): SeverityBand {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

/**
 * Band a CVSS v2 base score against the v2 qualitative scale, which has no
 * CRITICAL tier — 7.0 and above is HIGH.
 */
export function deriveCvssV2Severity(score: number): SeverityBand {
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

/** The band ranges, as `cisa_list_reference` topic `severity_bands` reports them. */
export const SEVERITY_BAND_RANGES: ReadonlyArray<{
  band: SeverityBand;
  v2Range: string;
  v3Range: string;
}> = [
  { band: 'NONE', v3Range: '0.0', v2Range: 'not defined — the v2 scale has no NONE band' },
  { band: 'LOW', v3Range: '0.1 – 3.9', v2Range: '0.0 – 3.9' },
  { band: 'MEDIUM', v3Range: '4.0 – 6.9', v2Range: '4.0 – 6.9' },
  { band: 'HIGH', v3Range: '7.0 – 8.9', v2Range: '7.0 – 10.0' },
  {
    band: 'CRITICAL',
    v3Range: '9.0 – 10.0',
    v2Range: 'not defined — the v2 scale tops out at HIGH',
  },
];
