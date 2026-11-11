/**
 * @fileoverview CVE 5.x record fixtures for Vulnrichment tests — a record with
 * a full CISA-ADP SSVC block, one with CVSS/CWE but no SSVC metric, and one
 * with a non-CISA ADP container only.
 * @module tests/fixtures/vulnrichment-records
 */

export function buildSsvcRecord(
  options: {
    automatable?: string;
    exploitation?: string;
    ssvcTimestamp?: string;
    technicalImpact?: string;
  } = {},
): unknown {
  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.1',
    cveMetadata: { cveId: 'CVE-2026-12345' },
    containers: {
      adp: [
        {
          providerMetadata: { shortName: 'CISA-ADP' },
          metrics: [
            {
              other: {
                type: 'ssvc',
                content: {
                  version: '2.0.3',
                  timestamp: options.ssvcTimestamp ?? '2026-09-05T00:00:00Z',
                  role: 'CISA Coordinator',
                  options: [
                    { Exploitation: options.exploitation ?? 'active' },
                    { Automatable: options.automatable ?? 'yes' },
                    { 'Technical Impact': options.technicalImpact ?? 'total' },
                  ],
                },
              },
            },
            {
              cvssV3_1: {
                version: '3.1',
                baseScore: 9.8,
                baseSeverity: 'CRITICAL',
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              },
            },
          ],
          problemTypes: [
            {
              descriptions: [{ cweId: 'CWE-20', description: 'CWE-20 Improper Input Validation' }],
            },
          ],
        },
      ],
    },
  };
}

/** Consumed CISA-ADP fields from cisagov/vulnrichment at 6fa0a3fe71639fbd086cf2575e83025b4ca17ad6. */
export const HISTORICAL_SSVC_RECORD = {
  cveMetadata: { cveId: 'CVE-2024-27834' },
  containers: {
    adp: [
      {
        providerMetadata: { shortName: 'CISA-ADP' },
        metrics: [
          {
            cvssV3_1: {
              version: '3.1',
              baseScore: 8.1,
              baseSeverity: 'HIGH',
              vectorString: 'CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H',
            },
          },
          {
            other: {
              type: 'ssvc',
              content: {
                id: 'CVE-2024-27834',
                role: 'CISA Coordinator',
                options: [
                  { Exploitation: 'None' },
                  { Automatable: 'Yes' },
                  { 'Technical Impact': 'Total' },
                ],
                version: '2.0.3',
                timestamp: '2024-05-16T04:00:11.988391Z',
              },
            },
          },
        ],
        problemTypes: [
          {
            descriptions: [
              { cweId: 'CWE-277', description: 'CWE-277 Insecure Inherited Permissions' },
            ],
          },
        ],
      },
    ],
  },
};

/** A CISA-ADP container that carries CVSS/CWE but no SSVC metric. */
export const NO_SSVC_METRIC_RECORD = {
  dataType: 'CVE_RECORD',
  dataVersion: '5.1',
  cveMetadata: { cveId: 'CVE-2026-22222' },
  containers: {
    adp: [
      {
        providerMetadata: { shortName: 'CISA-ADP' },
        metrics: [
          {
            cvssV3_1: {
              version: '3.1',
              baseScore: 5.3,
              baseSeverity: 'MEDIUM',
              vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
            },
          },
        ],
        problemTypes: [],
      },
    ],
  },
};

/** A record whose adp[] holds a non-CISA provider only. */
export const NO_CISA_CONTAINER_RECORD = {
  dataType: 'CVE_RECORD',
  dataVersion: '5.1',
  cveMetadata: { cveId: 'CVE-2026-33333' },
  containers: {
    adp: [{ providerMetadata: { shortName: 'Vendor-SADP' }, metrics: [] }],
  },
};
