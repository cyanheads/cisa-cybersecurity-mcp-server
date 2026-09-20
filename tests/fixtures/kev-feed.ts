/**
 * @fileoverview A small, hand-built KEV feed fixture covering the record
 * shapes `docs/design.md` documents: a BOD 26-04 entry, a BOD 22-01 entry, an
 * entry citing neither directive, an empty-cwes entry with a single NVD-URL
 * notes segment, and a ransomware/forensic-triage entry.
 * @module tests/fixtures/kev-feed
 */

export const KEV_RECORDS = [
  {
    cveID: 'CVE-2026-00001',
    vendorProject: 'Acme Corp',
    product: 'Widget Pro',
    vulnerabilityName: 'Acme Widget Pro Remote Code Execution',
    dateAdded: '2026-09-01',
    shortDescription: 'Acme Widget Pro contains a remote code execution vulnerability.',
    requiredAction: 'Apply mitigations per BOD 26-04.',
    dueDate: '2026-09-04',
    knownRansomwareCampaignUse: 'Known',
    forensicTriage: 'Yes',
    notes:
      'BOD 26-04: https://www.cisa.gov/bod-26-04; https://nvd.nist.gov/vuln/detail/CVE-2026-00001',
    cwes: ['CWE-20'],
  },
  {
    cveID: 'CVE-2026-00002',
    vendorProject: 'Acme Corp',
    product: 'Gadget',
    vulnerabilityName: 'Acme Gadget Privilege Escalation',
    dateAdded: '2026-09-05',
    shortDescription: 'Acme Gadget contains a privilege escalation vulnerability.',
    requiredAction: 'Apply mitigations per BOD 26-04.',
    dueDate: '2026-09-19',
    knownRansomwareCampaignUse: 'Unknown',
    forensicTriage: 'No',
    notes: 'https://nvd.nist.gov/vuln/detail/CVE-2026-00002',
    cwes: [],
  },
  {
    cveID: 'CVE-2021-00003',
    vendorProject: 'OldVendor',
    product: 'LegacyApp',
    vulnerabilityName: 'LegacyApp SQL Injection',
    dateAdded: '2021-11-05',
    shortDescription: 'LegacyApp contains a SQL injection vulnerability.',
    requiredAction: 'Apply mitigations per BOD 22-01.',
    dueDate: '2021-11-26',
    knownRansomwareCampaignUse: 'Unknown',
    forensicTriage: 'No',
    notes: 'https://nvd.nist.gov/vuln/detail/CVE-2021-00003',
    cwes: ['CWE-89'],
  },
  {
    cveID: 'CVE-2019-00004',
    vendorProject: 'NoDirectiveVendor',
    product: 'Thing',
    vulnerabilityName: 'Thing Cross-Site Scripting',
    dateAdded: '2019-05-01',
    shortDescription: 'Thing contains a cross-site scripting vulnerability.',
    requiredAction: 'Apply updates per vendor instructions.',
    dueDate: '2019-05-22',
    knownRansomwareCampaignUse: 'Unknown',
    forensicTriage: 'No',
    notes: 'https://nvd.nist.gov/vuln/detail/CVE-2019-00004',
    cwes: ['CWE-79'],
  },
  {
    cveID: 'CVE-2026-00005',
    vendorProject: 'PastDue Inc',
    product: 'Overdue Server',
    vulnerabilityName: 'Overdue Server Remote Takeover',
    dateAdded: '2026-01-01',
    shortDescription: 'Overdue Server contains a remote takeover vulnerability.',
    requiredAction: 'Apply mitigations per BOD 26-04.',
    dueDate: '2026-01-04',
    knownRansomwareCampaignUse: 'Known',
    forensicTriage: 'No',
    notes:
      'BOD 26-04: https://www.cisa.gov/bod-26-04; https://nvd.nist.gov/vuln/detail/CVE-2026-00005',
    cwes: ['CWE-20'],
  },
];

export function buildKevFeedBody(): string {
  return JSON.stringify({
    title: 'CISA Catalog of Known Exploited Vulnerabilities',
    catalogVersion: '2026.09.18',
    dateReleased: '2026-09-18T00:00:00.0000Z',
    count: KEV_RECORDS.length,
    vulnerabilities: KEV_RECORDS,
  });
}
