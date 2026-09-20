/**
 * @fileoverview Hand-built CSAF 2.0 document fixtures covering the shapes
 * `docs/design.md` documents under "Upstream sources — verified shapes":
 * a full-featured advisory, a sparse pre-2017 v2-only advisory with no sector
 * note, a republished vendor advisory, and a document sized to overflow the
 * outline budget.
 * @module tests/fixtures/csaf-documents
 */

/** A fully-populated coordinator-authored ICSA advisory. */
export const FULL_ADVISORY = {
  document: {
    title: 'Acme Widgets PLC Remote Code Execution',
    csaf_version: '2.0',
    publisher: { name: 'CISA', category: 'coordinator' },
    tracking: {
      id: 'ICSA-26-260-07',
      status: 'final',
      version: '1.1',
      initial_release_date: '2026-09-17T12:00:00.000000Z',
      current_release_date: '2026-09-18T06:00:00.000000Z',
      revision_history: [
        { number: '1.0', date: '2026-09-17T12:00:00.000000Z', summary: 'Initial publication.' },
        { number: '1.1', date: '2026-09-18T06:00:00.000000Z', summary: 'Corrected CVSS vector.' },
      ],
    },
    notes: [
      {
        category: 'summary',
        title: 'Executive summary',
        text: 'Successful exploitation could allow an attacker to execute arbitrary code.',
      },
      {
        category: 'other',
        title: 'Risk Evaluation',
        text: 'A skilled attacker could remotely exploit this.',
      },
      { category: 'other', title: 'Exploitability', text: 'Exploitation requires network access.' },
      {
        category: 'other',
        title: 'Critical infrastructure sectors',
        text: 'Water and Wastewater Systems, Energy, and Healthcare and Public Health',
      },
      { category: 'other', title: 'Countries/Areas Deployed', text: 'Worldwide' },
      { category: 'other', title: 'Company Headquarters Location', text: 'United States' },
    ],
    references: [
      {
        category: 'self',
        url: 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-07',
      },
      {
        category: 'external',
        summary: 'Vendor advisory',
        url: 'https://acme.example/advisories/2026-01',
      },
    ],
    acknowledgments: [
      {
        organization: 'Acme Security Team',
        names: ['Jane Researcher'],
        summary: 'for reporting this issue',
      },
    ],
  },
  product_tree: {
    branches: [
      {
        category: 'vendor',
        name: 'Acme Industries',
        branches: [
          {
            category: 'product_name',
            name: 'Widget Controller X200',
            branches: [
              {
                category: 'product_version_range',
                name: 'prior to 2.4.1',
                product: { name: 'Widget Controller X200', product_id: 'CSAFPID-0001' },
              },
              {
                category: 'product_version',
                name: '2.4.1',
                product: { name: 'Widget Controller X200', product_id: 'CSAFPID-0002' },
              },
            ],
          },
        ],
      },
    ],
  },
  vulnerabilities: [
    {
      cve: 'CVE-2026-12345',
      title: 'Improper Input Validation',
      cwe: { id: 'CWE-20', name: 'Improper Input Validation' },
      notes: [
        {
          category: 'general',
          title: 'CVE Description',
          text: 'An attacker can send crafted input.',
        },
      ],
      product_status: {
        known_affected: ['CSAFPID-0001'],
        fixed: ['CSAFPID-0002'],
        known_not_affected: [],
        recommended: [],
      },
      scores: [
        {
          products: ['CSAFPID-0001'],
          cvss_v3: {
            version: '3.1',
            baseScore: 9.8,
            baseSeverity: 'CRITICAL',
            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          },
        },
      ],
      remediations: [
        {
          category: 'vendor_fix',
          details: 'Upgrade to firmware 2.4.1 or later.',
          url: 'https://acme.example/downloads/2.4.1',
          product_ids: ['CSAFPID-0001'],
          restart_required: { category: 'machine' },
        },
      ],
    },
  ],
};

/**
 * A pre-2017 converted advisory: CVSS v2-only, no sector note, one
 * vulnerability with no `scores[]` at all — the sparse shape the design doc
 * requires as a test case.
 */
export const SPARSE_ADVISORY = {
  document: {
    title: 'Legacy HMI Denial of Service',
    csaf_version: '2.0',
    publisher: { name: 'CISA', category: 'coordinator' },
    tracking: {
      id: 'ICSA-14-035-01',
      status: 'final',
      version: '1.0',
      initial_release_date: '2014-02-04T00:00:00.000000Z',
      current_release_date: '2014-02-04T00:00:00.000000Z',
      revision_history: [
        { number: '1.0', date: '2014-02-04T00:00:00.000000Z', summary: 'Initial publication.' },
      ],
    },
    notes: [],
    references: [],
  },
  product_tree: {
    branches: [
      {
        category: 'vendor',
        name: 'Legacy Corp',
        branches: [
          {
            category: 'product_name',
            name: 'HMI-9000',
            branches: [
              {
                category: 'product_version',
                name: '1.0',
                product: { name: 'HMI-9000', product_id: 'CSAFPID-LEG-1' },
              },
            ],
          },
        ],
      },
    ],
  },
  vulnerabilities: [
    {
      cve: 'CVE-2014-0001',
      product_status: {
        known_affected: ['CSAFPID-LEG-1'],
        fixed: [],
        known_not_affected: [],
        recommended: [],
      },
      scores: [
        {
          products: ['CSAFPID-LEG-1'],
          cvss_v2: {
            version: '2.0',
            baseScore: 7.8,
            vectorString: 'AV:N/AC:L/Au:N/C:N/I:N/A:C',
          },
        },
      ],
      remediations: [],
    },
    {
      cve: 'CVE-2014-0002',
      product_status: { known_affected: [], fixed: [], known_not_affected: [], recommended: [] },
      scores: [],
      remediations: [],
    },
  ],
};

/** A republished vendor advisory (`publisher.category: 'other'`). */
export const REPUBLISHED_ADVISORY = {
  document: {
    title: 'Vendor-Authored Buffer Overflow',
    csaf_version: '2.0',
    publisher: { name: 'Contoso PLC Co.', category: 'other' },
    tracking: {
      id: 'ICSA-25-100-02',
      status: 'final',
      version: '1.0',
      initial_release_date: '2025-04-10T00:00:00.000000Z',
      current_release_date: '2025-04-10T00:00:00.000000Z',
      revision_history: [
        {
          number: '1.0',
          date: '2025-04-10T00:00:00.000000Z',
          summary: 'CISA republication of vendor advisory.',
        },
      ],
    },
    notes: [
      {
        category: 'other',
        title: 'Critical infrastructure sectors',
        text: 'Critical Manufacturing',
      },
    ],
    references: [],
  },
  product_tree: { branches: [] },
  vulnerabilities: [
    {
      cve: 'CVE-2025-5555',
      product_status: { known_affected: [], fixed: [], known_not_affected: [], recommended: [] },
      scores: [],
      remediations: [],
    },
  ],
};

/** Build a document guaranteed to exceed a 24,000-byte outline budget. */
export function buildOversizedAdvisory(advisoryId: string): unknown {
  const vulnerabilities = Array.from({ length: 40 }, (_, index) => ({
    cve: `CVE-2026-${(10000 + index).toString()}`,
    title: `Padding vulnerability ${index}`,
    notes: [
      {
        category: 'general',
        title: 'CVE Description',
        text: 'x'.repeat(600),
      },
    ],
    product_status: {
      known_affected: ['CSAFPID-BIG-1'],
      fixed: [],
      known_not_affected: [],
      recommended: [],
    },
    scores: [
      {
        products: ['CSAFPID-BIG-1'],
        cvss_v3: {
          version: '3.1',
          baseScore: 7.5,
          baseSeverity: 'HIGH',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        },
      },
    ],
    remediations: [
      { category: 'vendor_fix', details: 'Upgrade firmware.', product_ids: ['CSAFPID-BIG-1'] },
    ],
  }));

  return {
    document: {
      title: 'Oversized Advisory For Outline Testing',
      csaf_version: '2.0',
      publisher: { name: 'CISA', category: 'coordinator' },
      tracking: {
        id: advisoryId,
        status: 'final',
        version: '1.0',
        initial_release_date: '2026-01-01T00:00:00.000000Z',
        current_release_date: '2026-01-02T00:00:00.000000Z',
        revision_history: [
          { number: '1.0', date: '2026-01-01T00:00:00.000000Z', summary: 'Initial publication.' },
        ],
      },
      notes: [
        { category: 'summary', title: 'Executive summary', text: 'x'.repeat(200) },
        { category: 'other', title: 'Critical infrastructure sectors', text: 'Energy' },
      ],
      references: [],
    },
    product_tree: {
      branches: [
        {
          category: 'vendor',
          name: 'BigVendor',
          branches: [
            {
              category: 'product_name',
              name: 'BigProduct',
              branches: [
                {
                  category: 'product_version',
                  name: '1.0',
                  product: { name: 'BigProduct', product_id: 'CSAFPID-BIG-1' },
                },
              ],
            },
          ],
        },
      ],
    },
    vulnerabilities,
  };
}
