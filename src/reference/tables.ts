/**
 * @fileoverview The static reference blocks `cisa_list_reference` serves — the
 * vocabulary every other tool on this surface takes as input. Pure data: no
 * network call, no service dependency, so the tool stays callable while another
 * tool is failing and can be the routing target of every recovery hint.
 * @module reference/tables
 */

import { SEVERITY_BANDS } from './cvss.js';
import { SECTOR_FILTER_VALUES } from './sectors.js';

/** Topics `cisa_list_reference` accepts. */
export const REFERENCE_TOPICS = [
  'directives',
  'kev_fields',
  'ssvc_values',
  'sectors',
  'advisory_id_formats',
  'severity_bands',
  'sources',
] as const;

/** One reference topic name. */
export type ReferenceTopic = (typeof REFERENCE_TOPICS)[number];

/** One decoded term within a topic. */
export interface ReferenceEntry {
  description: string;
  key: string;
  label: string;
  values?: string[];
}

/** A topic's static header and entries. */
export interface ReferenceBlock {
  entries: ReferenceEntry[];
  summary: string;
  title: string;
}

/** Static content per topic. The `sources` topic's entries describe the live arm below them. */
export const REFERENCE_BLOCKS: Record<ReferenceTopic, ReferenceBlock> = {
  directives: {
    title: 'BOD 26-04 remediation timelines',
    summary:
      'Binding Operational Directive 26-04 sets federal remediation deadlines from four decision points: whether the asset is publicly exposed, whether the CVE is in the KEV catalog, whether exploitation is automatable, and the technical impact of a successful exploit. The sixteen combinations and their timelines are returned in timelineTable. BOD 26-04 supersedes and revokes BOD 22-01 and BOD 19-02.',
    entries: [
      {
        key: 'publiclyExposed',
        label: 'Publicly Exposed',
        description:
          "The only decision point CISA cannot publish — it is a property of the caller's estate. Supply it as assetExposure on cisa_get_ssvc.",
        values: ['publicly_exposed', 'not_publicly_exposed', 'unknown'],
      },
      {
        key: 'inKev',
        label: 'In the KEV',
        description:
          "Read from this server's KEV catalog snapshot, never from the caller. Check it directly with cisa_check_cve_status.",
        values: ['true', 'false'],
      },
      {
        key: 'automatable',
        label: 'Automatable by Adversary',
        description:
          'The SSVC Automatable decision point CISA publishes per CVE through Vulnrichment. Fetch it with cisa_get_ssvc.',
        values: ['yes', 'no'],
      },
      {
        key: 'technicalImpact',
        label: 'Technical Impact',
        description:
          'The SSVC Technical Impact decision point CISA publishes per CVE through Vulnrichment. Fetch it with cisa_get_ssvc.',
        values: ['partial', 'total'],
      },
      {
        key: 'timelineLabel',
        label: 'Agency timeline',
        description:
          'The directive\'s own wording for the deadline a row implies. "3 days & forensic triage" means remediate or mitigate within three days and carry out a forensic triage of the asset. "Fix on system upgrade" is a condition, not a day count, so remediationTimelineDays is null for those rows.',
        values: [
          '3 days & forensic triage',
          '3 days',
          '14 days',
          '60 days',
          'Fix on system upgrade',
        ],
      },
      {
        key: 'assignedDueDate',
        label: 'Assigned KEV due date vs. computed timeline',
        description:
          'Table 1 does not reproduce the dueDate CISA assigns a KEV entry. The assignment reflects values at the time of addition and judgment this server cannot observe, so the computed timeline and the assigned due date are reported as two separate facts and never reconciled.',
      },
    ],
  },
  kev_fields: {
    title: 'KEV catalog record fields',
    summary:
      "Every field a KEV entry carries and the value domain each one takes. Vendor and product are CISA's own free-text labels, not CPE names — match them as substrings rather than guessing an exact value.",
    entries: [
      {
        key: 'cveID',
        label: 'CVE ID',
        description: 'The CVE identifier, matching ^CVE-[0-9]{4}-[0-9]{4,19}$.',
      },
      {
        key: 'vendorProject',
        label: 'Vendor / project',
        description:
          "CISA's own vendor label, 283 distinct values across the catalog. Free text, not a CPE vendor component, and not normalized against any registry.",
      },
      {
        key: 'product',
        label: 'Product',
        description:
          "CISA's own product label, 694 distinct values. Free text, like vendorProject.",
      },
      {
        key: 'dateAdded',
        label: 'Date added',
        description:
          'The date CISA added the entry, YYYY-MM-DD. The catalog records additions but carries no per-record modified timestamp, so an entry whose dueDate or requiredAction changed after it was added is indistinguishable from an unchanged one.',
      },
      {
        key: 'dueDate',
        label: 'Due date',
        description:
          'The federal remediation deadline CISA assigned, YYYY-MM-DD. Under BOD 26-04 the gap from dateAdded is 3 or 14 days; pre-26-04 entries run 14, 21, or 181 days.',
      },
      {
        key: 'knownRansomwareCampaignUse',
        label: 'Known ransomware campaign use',
        description:
          'Whether CISA has linked the vulnerability to a ransomware campaign. "Unknown" means CISA has no such link on record, not that no link exists.',
        values: ['Known', 'Unknown'],
      },
      {
        key: 'forensicTriage',
        label: 'Forensic triage',
        description:
          'Whether the entry falls in the BOD 26-04 three-day forensic-triage tier. 58 of 1,716 entries are flagged Yes.',
        values: ['Yes', 'No'],
      },
      {
        key: 'cwes',
        label: 'CWEs',
        description:
          'Associated CWE identifiers, matching ^CWE-[0-9]+$. Up to four per entry, and empty on 175 entries — a CWE filter excludes those regardless of relevance.',
      },
      {
        key: 'notes',
        label: 'Notes',
        description:
          'A semicolon-delimited field carrying reference URLs and, on 116 entries, leading prose. This server parses it into a references array (each classified nvd, cisa, bod_guidance, forensic_triage, vendor, or other) plus notesCommentary. Every entry carries an NVD detail URL.',
      },
      {
        key: 'directive',
        label: 'Directive cited',
        description:
          "Which binding operational directive the entry cites in requiredAction or notes. 1,277 of 1,716 entries cite neither, and this server reports null for those rather than inferring one from the entry's age.",
        values: ['BOD 26-04', 'BOD 22-01', 'none'],
      },
    ],
  },
  ssvc_values: {
    title: 'SSVC decision points published by CISA',
    summary:
      'CISA publishes three SSVC decision points per enriched CVE as a CVE Authorized Data Publisher. Coverage is incomplete — not every CVE, including some in the KEV catalog, has a record — and a published value can predate a later KEV addition that contradicts it.',
    entries: [
      {
        key: 'Exploitation',
        label: 'Exploitation',
        description:
          'Evidence of active exploitation at the time the record was published. Values outside the documented set are passed through verbatim rather than coerced.',
        values: ['none', 'poc', 'active'],
      },
      {
        key: 'Automatable',
        label: 'Automatable',
        description:
          'Whether an adversary can reliably automate reconnaissance, weaponization, delivery, and exploitation of the vulnerability. Feeds the BOD 26-04 Table 1 lookup.',
        values: ['yes', 'no'],
      },
      {
        key: 'Technical Impact',
        label: 'Technical Impact',
        description:
          'How much control a successful exploit yields. Note the space in the published key name. Feeds the BOD 26-04 Table 1 lookup.',
        values: ['partial', 'total'],
      },
      {
        key: 'ssvcTimestamp',
        label: 'Decision timestamp',
        description:
          'When CISA published the decision points. Compare it against the KEV dateAdded: a timestamp earlier than the addition means the Exploitation value may not reflect current status.',
      },
      {
        key: 'coverage',
        label: 'Coverage',
        description:
          'A CVE with no CISA-authored enrichment container returns found false with guidance rather than an error. Records carrying CVSS and CWE but no SSVC metric return those values with a note that no decision points were published.',
      },
    ],
  },
  sectors: {
    title: 'Critical-infrastructure sectors',
    summary:
      'The sixteen canonical sector names plus the Multiple sentinel, as the advisory corpus spells them. The upstream sector note is free-form prose rather than an enum, so this server matches canonical names longest-first and keeps the verbatim text alongside the normalized set. Coverage begins in 2017: 729 of 3,926 advisories carry no sector note at all and cannot match a sector filter.',
    entries: [
      {
        key: 'canonical',
        label: 'Accepted sector filter values',
        description:
          'Every value the sector filter on cisa_search_ics_advisories accepts. Multiple is the sentinel the corpus uses for an advisory affecting many sectors; it is not one of the sixteen named sectors.',
        values: [...SECTOR_FILTER_VALUES],
      },
      {
        key: 'coverage',
        label: 'Coverage window',
        description:
          'Zero coverage before 2017, partial 2017 through 2022, complete from 2023. A sector filter silently excludes every advisory published before 2017 regardless of which sectors it affects.',
      },
      {
        key: 'sectorsRaw',
        label: 'Verbatim note',
        description:
          'Every advisory response carries sectorsRaw, the note text exactly as published, so nothing is lost to normalization — including the handful of advisories whose upstream typos resolve to no canonical name.',
      },
    ],
  },
  advisory_id_formats: {
    title: 'ICS advisory ID formats',
    summary:
      'Advisory IDs are uppercase in the document and lowercase in the filename. This server accepts either and normalizes to uppercase, also stripping a trailing .json.',
    entries: [
      {
        key: 'ICSA',
        label: 'ICS advisory',
        description:
          'Industrial control system advisories: ICSA-YY-DDD-NN, where DDD is the day of year. 3,738 of 3,926 documents. Web version at https://www.cisa.gov/news-events/ics-advisories/{id}.',
        values: ['ICSA-26-260-07', 'ICSA-10-316-01A'],
      },
      {
        key: 'ICSMA',
        label: 'ICS medical advisory',
        description:
          'Medical device advisories: ICSMA-YY-DDD-NN. 188 of 3,926 documents. Web version at https://www.cisa.gov/news-events/ics-medical-advisories/{id}.',
        values: ['ICSMA-26-253-02'],
      },
      {
        key: 'suffix',
        label: 'Revision suffix',
        description:
          'Most IDs carry no suffix (3,805 documents). 120 carry a single letter a through f marking a revision, and exactly one carries a numeric suffix, ICSA-16-231-01-0.',
        values: ['ICSA-26-260-07', 'ICSA-10-316-01A', 'ICSA-16-231-01-0'],
      },
    ],
  },
  severity_bands: {
    title: 'CVSS severity bands',
    summary:
      "The advisory corpus carries structured CVSS v3 and v2 scores and no structured v4 anywhere — where CVSS v4 appears it is prose inside a details note, surfaced as a note and never parsed into a score field. cvss_v3 always carries an upstream baseSeverity; cvss_v2 never does, so a v2-only advisory's band is derived here and flagged severityDerived.",
    entries: [
      {
        key: 'bands',
        label: 'Band labels',
        description:
          'The five band labels the severity filter accepts. The two scales differ: CVSS v2 has no NONE and no CRITICAL band, so a 10.0 v2 score bands as HIGH.',
        values: [...SEVERITY_BANDS],
      },
      {
        key: 'maxCvss',
        label: 'How maxCvss is computed',
        description:
          'The maximum baseScore across every vulnerabilities[].scores[] entry in the advisory. document.aggregate_severity exists on only 52 of 3,926 documents and is never relied on. 392 advisories score only in v2; 2 carry no CVSS at all and cannot match a score filter.',
      },
    ],
  },
  sources: {
    title: 'Live data sources',
    summary:
      'What this server currently holds, read from in-process state with no network call — so it answers while another tool is failing. Use it to check whether the KEV snapshot has loaded and whether the ICS advisory index has finished seeding.',
    entries: [
      {
        key: 'kev',
        label: 'KEV catalog snapshot',
        description:
          'An in-memory snapshot of the KEV JSON feed, refreshed on a cron with a conditional GET. catalogVersion and count are null until the first load lands.',
      },
      {
        key: 'csafMirror',
        label: 'ICS advisory index',
        description:
          'A local SQLite index of the full CSAF advisory corpus. ready is true once a full sync has ever completed; the index keeps serving during a refresh and after a failed one.',
      },
      {
        key: 'vulnrichment',
        label: 'Vulnrichment enrichment',
        description:
          'Fetched per CVE on demand and cached; the repository is far too large to mirror. Nothing is held at rest beyond the cache.',
      },
      {
        key: 'feeds',
        label: 'RSS feed windows',
        description:
          'Each feed is a rolling window of exactly 30 items with no history and no conditional-GET mechanism, so each is fetched at most once per TTL window and the parsed window is held in memory.',
      },
    ],
  },
};
