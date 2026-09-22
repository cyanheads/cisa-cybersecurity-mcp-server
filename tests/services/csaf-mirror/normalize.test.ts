/**
 * @fileoverview Tests for pure CSAF normalization — advisory-ID handling,
 * product-tree flattening, CVSS scoring, attribution, and the `changes.csv`
 * parser. No network, no database.
 * @module tests/services/csaf-mirror/normalize.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { describe, expect, it } from 'vitest';
import {
  advisorySeries,
  advisoryWebUrl,
  buildAttribution,
  computeMaxCvss,
  flattenProductTree,
  isCsafSourcePath,
  normalizeAdvisory,
  normalizeAdvisoryId,
  parseChangesCsv,
  readScores,
  toFtsMatch,
  toMirrorRow,
} from '@/services/csaf-mirror/normalize.js';
import { MAX_SEARCH_TEXT_LENGTH } from '@/services/search-text.js';
import {
  buildOversizedAdvisory,
  FULL_ADVISORY,
  REPUBLISHED_ADVISORY,
  SPARSE_ADVISORY,
} from '../../fixtures/csaf-documents.js';

describe('normalizeAdvisoryId', () => {
  it('uppercases, trims, and strips a trailing .json', () => {
    expect(normalizeAdvisoryId('  icsa-26-260-07.json  ')).toBe('ICSA-26-260-07');
  });

  it('is idempotent on an already-normalized ID', () => {
    expect(normalizeAdvisoryId('ICSA-16-231-01-0')).toBe('ICSA-16-231-01-0');
  });
});

describe('advisorySeries / advisoryWebUrl', () => {
  it('classifies ICSMA vs ICSA by prefix', () => {
    expect(advisorySeries('ICSMA-26-253-02')).toBe('ICSMA');
    expect(advisorySeries('ICSA-26-260-07')).toBe('ICSA');
  });

  it('builds the medical-advisory web path for ICSMA', () => {
    expect(advisoryWebUrl('ICSMA-26-253-02')).toBe(
      'https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-02',
    );
  });

  it('builds the ICS-advisory web path for ICSA', () => {
    expect(advisoryWebUrl('ICSA-26-260-07')).toBe(
      'https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-07',
    );
  });
});

describe('flattenProductTree', () => {
  it('flattens vendor → product → versions and keeps the CSAFPID token', () => {
    const result = flattenProductTree(FULL_ADVISORY.product_tree);
    expect(result.vendorCount).toBe(1);
    expect(result.productCount).toBe(2);
    expect(result.shownProducts).toBe(2);
    expect(result.truncated).toBeUndefined();
    const vendor = result.vendors[0];
    expect(vendor?.name).toBe('Acme Industries');
    expect(vendor?.products[0]?.name).toBe('Widget Controller X200');
    expect(vendor?.products[0]?.versions).toEqual([
      { kind: 'product_version_range', value: 'prior to 2.4.1', productId: 'CSAFPID-0001' },
      { kind: 'product_version', value: '2.4.1', productId: 'CSAFPID-0002' },
    ]);
  });

  it('keeps every flattened version row of a 585-leaf, multi-level tree — no cap, no truncation flag', () => {
    /* Three vendors, each vendor → product_family → product_name → product_version,
     * sized to the largest advisory in the corpus (585 leaves). */
    const vendorSizes = [300, 200, 85];
    let id = 0;
    const tree = {
      branches: vendorSizes.map((size, vendorIndex) => ({
        category: 'vendor',
        name: `Vendor ${vendorIndex}`,
        branches: [
          {
            category: 'product_family',
            name: `Family ${vendorIndex}`,
            branches: Array.from({ length: size }, (_, productIndex) => {
              const productId = `CSAFPID-${id++}`;
              return {
                category: 'product_name',
                name: `V${vendorIndex} Product ${productIndex}`,
                branches: [
                  {
                    category: 'product_version',
                    name: `1.${productIndex}`,
                    product: {
                      name: `V${vendorIndex} Product ${productIndex} 1.${productIndex}`,
                      product_id: productId,
                    },
                  },
                ],
              };
            }),
          },
        ],
      })),
    };

    const result = flattenProductTree(tree);
    expect(result.productCount).toBe(585);
    expect(result.shownProducts).toBe(585);
    expect(result.truncated).toBeUndefined();
    expect(result.vendorCount).toBe(3);
    expect(result.vendors.map((vendor) => vendor.products.length)).toEqual(vendorSizes);

    /* The last leaf — past any former row cap — is reachable with its full path. */
    const last = result.vendors[2]?.products[84];
    expect(last).toEqual({
      name: 'V2 Product 84',
      family: 'Family 2',
      versions: [{ kind: 'product_version', value: '1.84', productId: 'CSAFPID-584' }],
    });
    const productIds = result.vendors.flatMap((vendor) =>
      vendor.products.flatMap((product) => product.versions.map((version) => version.productId)),
    );
    expect(new Set(productIds).size).toBe(585);
  });

  it('indexes every product name in productsText, including those past row 200', () => {
    const branches = Array.from({ length: 250 }, (_, index) => ({
      category: 'product_name',
      name: `Product ${index}`,
      product: { name: `Product ${index}`, product_id: `CSAFPID-${index}` },
    }));
    const raw = {
      ...FULL_ADVISORY,
      product_tree: { branches: [{ category: 'vendor', name: 'BigVendor', branches }] },
    };
    const doc = normalizeAdvisory(raw, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    const row = toMirrorRow(doc, '2026/icsa-26-260-07.json');
    expect(row.productCount).toBe(250);
    expect(String(row.productsText).split(' | ')).toHaveLength(250);
    expect(row.productsText).toContain('Product 249');
  });

  it('returns an empty products block for a non-object product tree', () => {
    const result = flattenProductTree(undefined);
    expect(result).toEqual({ vendorCount: 0, productCount: 0, vendors: [], shownProducts: 0 });
  });
});

describe('readScores / computeMaxCvss', () => {
  it('reads a cvss_v3 score with an upstream baseSeverity, not derived', () => {
    const vulnerability = FULL_ADVISORY.vulnerabilities[0] as unknown as Record<string, unknown>;
    const scores = readScores(vulnerability);
    expect(scores).toEqual([
      {
        version: '3.1',
        baseScore: 9.8,
        baseSeverity: 'CRITICAL',
        severityDerived: false,
        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        productIds: ['CSAFPID-0001'],
      },
    ]);
  });

  it('derives the band for a cvss_v2 score, which never carries baseSeverity upstream', () => {
    const vulnerability = SPARSE_ADVISORY.vulnerabilities[0] as unknown as Record<string, unknown>;
    const scores = readScores(vulnerability);
    expect(scores).toEqual([
      {
        version: '2.0',
        baseScore: 7.8,
        baseSeverity: 'HIGH',
        severityDerived: true,
        vectorString: 'AV:N/AC:L/Au:N/C:N/I:N/A:C',
        productIds: ['CSAFPID-LEG-1'],
      },
    ]);
  });

  it('returns an empty score list for a vulnerability with no scores[]', () => {
    const vulnerability = SPARSE_ADVISORY.vulnerabilities[1] as unknown as Record<string, unknown>;
    expect(readScores(vulnerability)).toEqual([]);
  });

  it('computeMaxCvss returns undefined when no vulnerability carries a score', () => {
    expect(
      computeMaxCvss([
        {
          cve: 'CVE-2020-0000',
          scores: [],
          remediations: [],
          notes: [],
          productStatus: { known_affected: [], fixed: [], known_not_affected: [], recommended: [] },
        },
      ]),
    ).toBeUndefined();
  });

  it('computeMaxCvss picks the highest baseScore across all vulnerabilities', () => {
    const max = computeMaxCvss([
      {
        cve: 'CVE-2020-0001',
        scores: [
          {
            version: '3.1',
            baseScore: 5.0,
            baseSeverity: 'MEDIUM',
            severityDerived: false,
            vectorString: '',
            productIds: [],
          },
        ],
        remediations: [],
        notes: [],
        productStatus: { known_affected: [], fixed: [], known_not_affected: [], recommended: [] },
      },
      {
        cve: 'CVE-2020-0002',
        scores: [
          {
            version: '3.1',
            baseScore: 9.1,
            baseSeverity: 'CRITICAL',
            severityDerived: false,
            vectorString: '',
            productIds: [],
          },
        ],
        remediations: [],
        notes: [],
        productStatus: { known_affected: [], fixed: [], known_not_affected: [], recommended: [] },
      },
    ]);
    expect(max).toEqual({
      score: 9.1,
      severity: 'CRITICAL',
      version: '3.1',
      severityDerived: false,
    });
  });
});

describe('buildAttribution', () => {
  it('cites CISA directly for a coordinator-authored advisory', () => {
    const attribution = buildAttribution(
      'CISA',
      'coordinator',
      'https://example.test/doc.json',
      [],
    );
    expect(attribution).toContain('Authored by CISA');
    expect(attribution).toContain('publisher category: coordinator');
    expect(attribution).not.toContain('vendor');
  });

  it('names the originating vendor and its own text for a republication', () => {
    const attribution = buildAttribution(
      'Contoso PLC Co.',
      'other',
      'https://example.test/doc.json',
      [{ number: '1.0', date: '2025-04-10', summary: 'CISA republication of vendor advisory.' }],
    );
    expect(attribution).toContain('Republished by Contoso PLC Co.');
    expect(attribution).toContain("the vendor's own");
    expect(attribution).toContain(
      'Revision history records: "CISA republication of vendor advisory."',
    );
  });
});

describe('normalizeAdvisory — whole document', () => {
  it('normalizes a full advisory: header, summary, products, vulnerabilities, sectors', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    expect(doc).not.toBeNull();
    expect(doc?.advisory.advisoryId).toBe('ICSA-26-260-07');
    expect(doc?.advisory.series).toBe('ICSA');
    expect(doc?.advisory.publisherCategory).toBe('coordinator');
    expect(doc?.advisory.url).toBe(
      'https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-07',
    );
    expect(doc?.summary.sectors).toEqual([
      'Energy',
      'Healthcare and Public Health',
      'Water and Wastewater Systems',
    ]);
    expect(doc?.summary.sectorsRaw).toBe(
      'Water and Wastewater Systems, Energy, and Healthcare and Public Health',
    );
    expect(doc?.products.vendorCount).toBe(1);
    expect(doc?.vulnerabilities).toHaveLength(1);
    expect(doc?.vulnerabilities[0]?.cve).toBe('CVE-2026-12345');
    expect(doc?.vulnerabilities[0]?.scores[0]?.baseScore).toBe(9.8);
    expect(doc?.revisionHistory).toHaveLength(2);
    expect(doc?.acknowledgments).toEqual([
      {
        organization: 'Acme Security Team',
        names: ['Jane Researcher'],
        summary: 'for reporting this issue',
      },
    ]);
  });

  it('normalizes a sparse pre-2017 advisory with no sector note and a scoreless vulnerability', () => {
    const doc = normalizeAdvisory(SPARSE_ADVISORY, '2014/icsa-14-035-01.json');
    expect(doc?.summary.sectors).toEqual([]);
    expect(doc?.summary.sectorsRaw).toBeUndefined();
    expect(doc?.vulnerabilities[1]?.scores).toEqual([]);
  });

  it('returns null for a document with no tracking.id', () => {
    const doc = normalizeAdvisory({ document: { tracking: {} } }, 'nowhere.json');
    expect(doc).toBeNull();
  });

  it('returns null for a non-object input', () => {
    expect(normalizeAdvisory(null, 'nowhere.json')).toBeNull();
    expect(normalizeAdvisory('not an object', 'nowhere.json')).toBeNull();
  });

  it('ignores an off-host self reference and composes the cisa.gov URL instead', () => {
    const doc = normalizeAdvisory(
      {
        document: {
          title: 'Off-host self reference',
          tracking: { id: 'ICSA-26-260-09' },
          references: [
            {
              category: 'self',
              url: 'https://attacker.example/news-events/ics-advisories/icsa-26-260-09',
            },
          ],
        },
      },
      '2026/icsa-26-260-09.json',
    );

    expect(doc?.advisory.url).toBe(
      'https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-09',
    );
  });

  it('keeps a self reference served from cisa.gov', () => {
    const doc = normalizeAdvisory(
      {
        document: {
          title: 'Legacy self reference path',
          tracking: { id: 'ICSA-16-231-01-0' },
          references: [
            {
              category: 'self',
              url: 'https://www.cisa.gov/news-events/ics-advisories/icsa-16-231-01-0-legacy',
            },
          ],
        },
      },
      '2016/icsa-16-231-01-0.json',
    );

    expect(doc?.advisory.url).toBe(
      'https://www.cisa.gov/news-events/ics-advisories/icsa-16-231-01-0-legacy',
    );
  });
});

describe('toMirrorRow', () => {
  it('projects the normalized document into the flat search row', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    const row = toMirrorRow(doc, '2026/icsa-26-260-07.json');
    expect(row.advisoryId).toBe('ICSA-26-260-07');
    expect(row.vendorsText).toBe('Acme Industries');
    expect(row.cveCount).toBe(1);
    expect(row.maxCvss).toBe(9.8);
    expect(row.maxCvssSeverity).toBe('CRITICAL');
    expect(row.sectorsText).toBe(
      'Energy | Healthcare and Public Health | Water and Wastewater Systems',
    );
    expect(typeof row.document).toBe('string');
    expect(JSON.parse(row.document as string)).toMatchObject({
      advisory: { advisoryId: 'ICSA-26-260-07' },
    });
  });
});

describe('parseChangesCsv', () => {
  it('parses the quoted-microsecond form (OT/VA distributions)', () => {
    const rows = parseChangesCsv(
      '"2026/icsa-26-260-07.json","2026-09-17T06:00:00.000000Z"\n"2026/icsa-26-260-08.json","2026-09-16T00:00:00.000000Z"',
    );
    expect(rows).toEqual([
      { path: '2026/icsa-26-260-07.json', timestamp: '2026-09-17T06:00:00.000000Z' },
      { path: '2026/icsa-26-260-08.json', timestamp: '2026-09-16T00:00:00.000000Z' },
    ]);
  });

  it('parses the unquoted-second form (IT distribution)', () => {
    const rows = parseChangesCsv('2026/va-26-260-01.json,2026-09-17T06:00:00Z');
    expect(rows).toEqual([{ path: '2026/va-26-260-01.json', timestamp: '2026-09-17T06:00:00Z' }]);
  });

  it('skips blank lines and ignores a row with no comma', () => {
    const rows = parseChangesCsv(
      '\n"2026/icsa-26-001-01.json","2026-01-01T00:00:00Z"\n\nmalformed-line-no-comma\n',
    );
    expect(rows).toEqual([{ path: '2026/icsa-26-001-01.json', timestamp: '2026-01-01T00:00:00Z' }]);
  });

  it('returns an empty array for an empty manifest', () => {
    expect(parseChangesCsv('')).toEqual([]);
  });

  it('drops a manifest row whose path escapes the distribution directory', () => {
    const rows = parseChangesCsv(
      [
        '"../../../../.github/workflows/release.json","2026-01-01T00:00:00Z"',
        '"2026/../../../etc/passwd.json","2026-01-01T00:00:00Z"',
        '"2026/icsa-26-001-01.json","2026-01-01T00:00:00Z"',
      ].join('\n'),
    );
    expect(rows).toEqual([{ path: '2026/icsa-26-001-01.json', timestamp: '2026-01-01T00:00:00Z' }]);
  });

  it('drops a manifest row carrying a scheme, a query, or a fragment', () => {
    const rows = parseChangesCsv(
      [
        '"https://evil.example/payload.json","2026-01-01T00:00:00Z"',
        '"2026/icsa-26-001-01.json?token=leak","2026-01-01T00:00:00Z"',
        '"2026/icsa-26-001-01.json#frag","2026-01-01T00:00:00Z"',
      ].join('\n'),
    );
    expect(rows).toEqual([]);
  });
});

describe('isCsafSourcePath', () => {
  it('accepts the year/filename.json shape every distribution publishes', () => {
    expect(isCsafSourcePath('2026/icsa-26-260-07.json')).toBe(true);
    expect(isCsafSourcePath('2019/icsma-19-253-02.json')).toBe(true);
    expect(isCsafSourcePath('2026/va-26-260-01.json')).toBe(true);
  });

  it('rejects traversal, extra segments, and non-JSON names', () => {
    expect(isCsafSourcePath('../2026/icsa-26-260-07.json')).toBe(false);
    expect(isCsafSourcePath('2026/../icsa-26-260-07.json')).toBe(false);
    expect(isCsafSourcePath('2026/sub/icsa-26-260-07.json')).toBe(false);
    expect(isCsafSourcePath('icsa-26-260-07.json')).toBe(false);
    expect(isCsafSourcePath('2026/icsa-26-260-07.json.asc')).toBe(false);
    expect(isCsafSourcePath('')).toBe(false);
  });
});

describe('toFtsMatch', () => {
  it('AND-combines quoted tokens', () => {
    expect(toFtsMatch('acme widget')).toBe('"acme" AND "widget"');
  });

  it('neutralizes FTS5 operators embedded in caller input', () => {
    expect(toFtsMatch('acme* OR "widget" NEAR/2 evil')).toBe(
      '"acme*" AND "OR" AND "widget" AND "NEAR/2" AND "evil"',
    );
  });

  it.each([
    ['whitespace', '   '],
    ['bare quotes', '""'],
    ['quotes and whitespace', ' "" "" '],
    ['punctuation only', '-- !! /'],
  ])('throws empty_search_text when %s leaves no searchable token', (_label, input) => {
    let thrown: unknown;
    try {
      toFtsMatch(input);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({
      code: JsonRpcErrorCode.ValidationError,
      data: { reason: 'empty_search_text', field: 'q', recovery: { hint: expect.any(String) } },
    });
  });

  it('drops a token with no letter or digit instead of letting it zero out the AND', () => {
    /* FTS5's unicode61 tokenizer reads `--` as no token at all, and an empty
     * phrase in an AND chain matches nothing. */
    expect(toFtsMatch('siemens -- s7')).toBe('"siemens" AND "s7"');
    expect(toFtsMatch('s7-1500 «»')).toBe('"s7-1500"');
  });

  it('keeps non-ASCII letters and digits as searchable tokens', () => {
    expect(toFtsMatch('Schneider Électrique ２')).toBe('"Schneider" AND "Électrique" AND "２"');
  });

  it('rejects a query past the search-text ceiling rather than building the expression', () => {
    const oversized = 'siemens '.repeat(MAX_SEARCH_TEXT_LENGTH);
    expect(() => toFtsMatch(oversized)).toThrow(/characters/);
  });

  it('accepts a query exactly at the ceiling', () => {
    expect(() => toFtsMatch('a'.repeat(MAX_SEARCH_TEXT_LENGTH))).not.toThrow();
  });
});

describe('buildOversizedAdvisory fixture sanity', () => {
  it('normalizes to a document whose serialized size exceeds the 24 KB outline budget', () => {
    const raw = buildOversizedAdvisory('ICSA-26-001-01');
    const doc = normalizeAdvisory(raw, '2026/icsa-26-001-01.json');
    expect(doc).not.toBeNull();
    expect(JSON.stringify(doc).length).toBeGreaterThan(24_000);
  });
});

describe('normalizeAdvisory — republished vendor advisory', () => {
  it('normalizes publisher category other and a single-sector note', () => {
    const doc = normalizeAdvisory(REPUBLISHED_ADVISORY, '2025/icsa-25-100-02.json');
    expect(doc?.advisory.publisherCategory).toBe('other');
    expect(doc?.advisory.attribution).toContain('Republished by Contoso PLC Co.');
    expect(doc?.summary.sectors).toEqual(['Critical Manufacturing']);
  });
});
