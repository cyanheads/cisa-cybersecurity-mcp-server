/**
 * @fileoverview BOD 26-04 Appendix A, Table 1 — the remediation-timeline decision
 * table, transcribed row for row from the directive's published table image, plus
 * the pure resolver over it. Four decision points select exactly one of sixteen
 * rows: Publicly Exposed, In the KEV, Automatable by Adversary, and Technical
 * Impact.
 *
 * "3 days & forensic triage" means remediate or mitigate within three days *and*
 * carry out a forensic triage of the asset. "Fix on system upgrade" is a
 * condition rather than a day count, so `remediationTimelineDays` is `null` for
 * rows 15 and 16 instead of a fabricated number.
 *
 * No I/O, no clock — the whole module is a lookup table and a switch.
 * @module reference/bod-2604
 */

/** Technical Impact as CISA publishes it in the SSVC decision points. */
export type TechnicalImpact = 'partial' | 'total';

/** One row of BOD 26-04 Appendix A, Table 1. */
export interface Bod2604Row {
  automatable: boolean;
  forensicTriageRequired: boolean;
  inKev: boolean;
  publiclyExposed: boolean;
  /** `3` | `14` | `60`, or `null` for the "Fix on system upgrade" rows. */
  remediationTimelineDays: number | null;
  row: number;
  technicalImpact: TechnicalImpact;
  /** The directive's own wording for the agency timeline. */
  timelineLabel: string;
}

const THREE_AND_TRIAGE = '3 days & forensic triage';
const FIX_ON_UPGRADE = 'Fix on system upgrade';

/** The sixteen rows, in the directive's own order. */
export const BOD_2604_TABLE_1: readonly Bod2604Row[] = [
  {
    row: 1,
    publiclyExposed: true,
    inKev: true,
    automatable: true,
    technicalImpact: 'total',
    timelineLabel: THREE_AND_TRIAGE,
    remediationTimelineDays: 3,
    forensicTriageRequired: true,
  },
  {
    row: 2,
    publiclyExposed: true,
    inKev: true,
    automatable: true,
    technicalImpact: 'partial',
    timelineLabel: '3 days',
    remediationTimelineDays: 3,
    forensicTriageRequired: false,
  },
  {
    row: 3,
    publiclyExposed: true,
    inKev: true,
    automatable: false,
    technicalImpact: 'total',
    timelineLabel: THREE_AND_TRIAGE,
    remediationTimelineDays: 3,
    forensicTriageRequired: true,
  },
  {
    row: 4,
    publiclyExposed: true,
    inKev: true,
    automatable: false,
    technicalImpact: 'partial',
    timelineLabel: '14 days',
    remediationTimelineDays: 14,
    forensicTriageRequired: false,
  },
  {
    row: 5,
    publiclyExposed: true,
    inKev: false,
    automatable: true,
    technicalImpact: 'total',
    timelineLabel: '3 days',
    remediationTimelineDays: 3,
    forensicTriageRequired: false,
  },
  {
    row: 6,
    publiclyExposed: true,
    inKev: false,
    automatable: true,
    technicalImpact: 'partial',
    timelineLabel: '14 days',
    remediationTimelineDays: 14,
    forensicTriageRequired: false,
  },
  {
    row: 7,
    publiclyExposed: true,
    inKev: false,
    automatable: false,
    technicalImpact: 'total',
    timelineLabel: '14 days',
    remediationTimelineDays: 14,
    forensicTriageRequired: false,
  },
  {
    row: 8,
    publiclyExposed: true,
    inKev: false,
    automatable: false,
    technicalImpact: 'partial',
    timelineLabel: '60 days',
    remediationTimelineDays: 60,
    forensicTriageRequired: false,
  },
  {
    row: 9,
    publiclyExposed: false,
    inKev: true,
    automatable: true,
    technicalImpact: 'total',
    timelineLabel: THREE_AND_TRIAGE,
    remediationTimelineDays: 3,
    forensicTriageRequired: true,
  },
  {
    row: 10,
    publiclyExposed: false,
    inKev: true,
    automatable: true,
    technicalImpact: 'partial',
    timelineLabel: '14 days',
    remediationTimelineDays: 14,
    forensicTriageRequired: false,
  },
  {
    row: 11,
    publiclyExposed: false,
    inKev: true,
    automatable: false,
    technicalImpact: 'total',
    timelineLabel: '14 days',
    remediationTimelineDays: 14,
    forensicTriageRequired: false,
  },
  {
    row: 12,
    publiclyExposed: false,
    inKev: true,
    automatable: false,
    technicalImpact: 'partial',
    timelineLabel: '14 days',
    remediationTimelineDays: 14,
    forensicTriageRequired: false,
  },
  {
    row: 13,
    publiclyExposed: false,
    inKev: false,
    automatable: true,
    technicalImpact: 'total',
    timelineLabel: '60 days',
    remediationTimelineDays: 60,
    forensicTriageRequired: false,
  },
  {
    row: 14,
    publiclyExposed: false,
    inKev: false,
    automatable: true,
    technicalImpact: 'partial',
    timelineLabel: '60 days',
    remediationTimelineDays: 60,
    forensicTriageRequired: false,
  },
  {
    row: 15,
    publiclyExposed: false,
    inKev: false,
    automatable: false,
    technicalImpact: 'total',
    timelineLabel: FIX_ON_UPGRADE,
    remediationTimelineDays: null,
    forensicTriageRequired: false,
  },
  {
    row: 16,
    publiclyExposed: false,
    inKev: false,
    automatable: false,
    technicalImpact: 'partial',
    timelineLabel: FIX_ON_UPGRADE,
    remediationTimelineDays: null,
    forensicTriageRequired: false,
  },
];

/** The four decision points that select a Table 1 row. */
export interface Bod2604Inputs {
  automatable: boolean;
  inKev: boolean;
  publiclyExposed: boolean;
  technicalImpact: TechnicalImpact;
}

/**
 * Select the Table 1 row implied by the four decision points. Total function over
 * the input space: the table enumerates all 2 × 2 × 2 × 2 combinations, so a row
 * always exists.
 */
export function resolveBod2604Timeline(inputs: Bod2604Inputs): Bod2604Row {
  const match = BOD_2604_TABLE_1.find(
    (row) =>
      row.publiclyExposed === inputs.publiclyExposed &&
      row.inKev === inputs.inKev &&
      row.automatable === inputs.automatable &&
      row.technicalImpact === inputs.technicalImpact,
  );
  /* istanbul ignore next — the table is exhaustive over the four booleans. */
  if (!match) {
    throw new Error(
      `No BOD 26-04 Table 1 row for publiclyExposed=${inputs.publiclyExposed}, inKev=${inputs.inKev}, automatable=${inputs.automatable}, technicalImpact=${inputs.technicalImpact}`,
    );
  }
  return match;
}

/** The fixed basis string every computed timeline cites. */
export const BOD_2604_BASIS = 'CISA BOD 26-04 Appendix A, Table 1';

/**
 * The fixed caveat every computed timeline carries. The computation is CISA's
 * published decision table applied to CISA's published decision points and the
 * caller's stated exposure — it is not a compliance determination, and it is not
 * CISA's own KEV due-date assignment, which demonstrably differs.
 */
export const BOD_2604_CAVEAT =
  "This timeline is CISA's published decision table applied to CISA's published decision points and the asset exposure supplied in the request. It is not a compliance determination, and it is not CISA's assigned KEV due date.";

/** Supporting definitions from the directive text, surfaced by `cisa_list_reference`. */
export const BOD_2604_DEFINITIONS: ReadonlyArray<{ definition: string; term: string }> = [
  {
    term: 'Publicly exposed',
    definition:
      'Any agency-owned or agency-managed IT resource accessible to unauthenticated or untrusted entities via public networks, regardless of physical or logical location.',
  },
  {
    term: 'Partial control',
    definition:
      'The exploit gives limited control over, or information exposure about, the behavior of the vulnerable software; or a low stochastic opportunity for total control. A denial-of-service attack is a form of limited control.',
  },
  {
    term: 'Total control',
    definition:
      "The exploit gives the adversary total control over the software's behavior, including reliably revealing log-in credentials.",
  },
  {
    term: 'Clock start',
    definition:
      'The earlier of CISA adding the CVE to the KEV catalog, or the agency enumerating the vulnerability on an asset and updating the CDM dashboard.',
  },
  {
    term: 'Timelines are dynamic',
    definition:
      'Removing a system from the internet flips Publicly Exposed to No and shifts the timeline back; a KEV addition shortens it.',
  },
  {
    term: 'Fix on system upgrade',
    definition: "Remediate at the vulnerable asset's next scheduled major upgrade or rebuild.",
  },
];

/** Directives BOD 26-04 supersedes and revokes. */
export const BOD_2604_SUPERSEDES: ReadonlyArray<{
  directive: string;
  issued: string;
  note: string;
}> = [
  {
    directive: 'BOD 22-01',
    issued: '2021-11-03',
    note: 'Reducing the Significant Risk of Known Exploited Vulnerabilities — superseded and revoked by BOD 26-04.',
  },
  {
    directive: 'BOD 19-02',
    issued: '2019-04-29',
    note: 'Vulnerability Remediation Requirements for Internet-Accessible Systems — superseded and revoked by BOD 26-04.',
  },
];
