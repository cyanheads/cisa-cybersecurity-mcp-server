/**
 * @fileoverview Domain types for the Vulnrichment tier — the normalized per-CVE
 * enrichment record and the outcome discriminator that tells a miss apart from a
 * record carrying CVSS but no SSVC.
 * @module services/vulnrichment/types
 */

/**
 * Why a per-CVE lookup ended the way it did. Only `ssvc` carries decision points;
 * `no_ssvc_metric` still carries whatever CVSS and CWE CISA contributed.
 */
export type SsvcOutcome =
  | 'ssvc'
  | 'not_found'
  | 'no_cisa_container'
  | 'no_ssvc_metric'
  | 'fetch_failed';

/** A CVSS score CISA contributed through its ADP container. */
export interface SsvcCvss {
  baseScore: number;
  baseSeverity: string;
  vectorString: string;
  version: string;
}

/** A CWE from the CISA-ADP container's `problemTypes`. */
export interface SsvcCwe {
  cweId: string;
  description: string;
}

/** One normalized Vulnrichment lookup. */
export interface SsvcRecord {
  automatable?: string;
  cveId: string;
  cvss?: SsvcCvss;
  cwes: SsvcCwe[];
  exploitation?: string;
  /** Present on every non-`ssvc` outcome — what the agent should do instead. */
  guidance?: string;
  outcome: SsvcOutcome;
  sourceUrl: string;
  ssvcRole?: string;
  ssvcTimestamp?: string;
  ssvcVersion?: string;
  technicalImpact?: string;
}

/** What `cisa_list_reference` topic `sources` reports about the Vulnrichment tier. */
export interface VulnrichmentState {
  cacheTtlSeconds: number;
  mode: 'on_demand';
}
