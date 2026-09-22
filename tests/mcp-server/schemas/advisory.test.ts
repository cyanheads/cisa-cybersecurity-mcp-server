/**
 * @fileoverview Tests for the shared advisory output schema helpers and
 * markdown renderers — `isEmptySection`, `presentSections`, the shared outline
 * extractor and its CVE listing, and the section renderers `cisa_get_advisory`
 * and the resource both use.
 * @module tests/mcp-server/schemas/advisory.test
 */

import { z } from '@cyanheads/mcp-ts-core';
import { describe, expect, it } from 'vitest';
import {
  AdvisoryOutlineSectionSchema,
  advisoryCves,
  cvesNarrowingHint,
  extractAdvisorySections,
  isEmptySection,
  presentSections,
  renderAdvisoryAcknowledgments,
  renderAdvisoryHeader,
  renderAdvisoryProducts,
  renderAdvisoryReferences,
  renderAdvisoryRevisions,
  renderAdvisorySummary,
  renderAdvisoryVulnerabilities,
  renderOutlineCves,
} from '@/mcp-server/schemas/advisory.js';
import { normalizeAdvisory } from '@/services/csaf-mirror/normalize.js';
import { FULL_ADVISORY, SPARSE_ADVISORY } from '../../fixtures/csaf-documents.js';

describe('isEmptySection', () => {
  it('treats null and undefined as empty', () => {
    expect(isEmptySection(null)).toBe(true);
    expect(isEmptySection(undefined)).toBe(true);
  });

  it('treats an empty array or object as empty', () => {
    expect(isEmptySection([])).toBe(true);
    expect(isEmptySection({})).toBe(true);
  });

  it('treats a populated array or object as non-empty', () => {
    expect(isEmptySection([1])).toBe(false);
    expect(isEmptySection({ a: 1 })).toBe(false);
  });

  it('treats a non-array, non-object value as non-empty', () => {
    expect(isEmptySection('text')).toBe(false);
    expect(isEmptySection(0)).toBe(false);
  });
});

describe('presentSections', () => {
  it('lists only the sections a full advisory actually carries', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    expect(presentSections(doc)).toEqual([
      'advisory',
      'summary',
      'products',
      'vulnerabilities',
      'revisionHistory',
      'references',
      'acknowledgments',
    ]);
  });

  it('omits references and acknowledgments for the sparse advisory, which carries neither', () => {
    const doc = normalizeAdvisory(SPARSE_ADVISORY, '2014/icsa-14-035-01.json');
    if (!doc) throw new Error('expected a normalized document');
    const present = presentSections(doc);
    expect(present).not.toContain('references');
    expect(present).not.toContain('acknowledgments');
    expect(present).toContain('advisory');
    expect(present).toContain('vulnerabilities');
  });
});

describe('extractAdvisorySections / advisoryCves', () => {
  /* SPARSE_ADVISORY with its second vulnerability entry repeating the first CVE. */
  const repeated = {
    ...SPARSE_ADVISORY,
    vulnerabilities: [
      SPARSE_ADVISORY.vulnerabilities[1],
      SPARSE_ADVISORY.vulnerabilities[0],
      { ...SPARSE_ADVISORY.vulnerabilities[1], title: 'A second entry for the same CVE' },
    ],
  };

  it('sizes every carried section, lists CVE IDs on vulnerabilities only, and skips empty sections', () => {
    const doc = normalizeAdvisory(SPARSE_ADVISORY, '2014/icsa-14-035-01.json');
    if (!doc) throw new Error('expected a normalized document');
    const sections = extractAdvisorySections(doc);
    expect(sections.map((section) => section.name)).toEqual(presentSections(doc));
    for (const section of sections) {
      expect(section.bytes).toBe(JSON.stringify(doc[section.name as keyof typeof doc]).length);
      if (section.name === 'vulnerabilities') {
        expect(section.cves).toEqual(['CVE-2014-0001', 'CVE-2014-0002']);
      } else {
        expect(section).not.toHaveProperty('cves');
      }
    }
  });

  it('lists each CVE once, in first-appearance order, when entries repeat a CVE', () => {
    const doc = normalizeAdvisory(repeated, '2014/icsa-14-035-01.json');
    if (!doc) throw new Error('expected a normalized document');
    expect(doc.vulnerabilities).toHaveLength(3);
    expect(advisoryCves(doc)).toEqual(['CVE-2014-0002', 'CVE-2014-0001']);
  });

  it('survives the outline schema with its CVE list intact — the framework element alone would strip it', () => {
    const doc = normalizeAdvisory(SPARSE_ADVISORY, '2014/icsa-14-035-01.json');
    if (!doc) throw new Error('expected a normalized document');
    const parsed = z.array(AdvisoryOutlineSectionSchema).parse(extractAdvisorySections(doc));
    expect(parsed.find((section) => section.name === 'vulnerabilities')?.cves).toEqual([
      'CVE-2014-0001',
      'CVE-2014-0002',
    ]);
  });
});

describe('cvesNarrowingHint / renderOutlineCves', () => {
  const sections = [
    { name: 'vulnerabilities', bytes: 30_000, cves: ['CVE-2026-0001', 'CVE-2026-0002'] },
    { name: 'products', bytes: 900 },
  ];

  it('points at cves only when the vulnerabilities section alone overflows the budget', () => {
    expect(cvesNarrowingHint(sections, 24_000)).toContain('30000 bytes; pass cves');
    expect(cvesNarrowingHint(sections, 30_000)).toBe('');
    expect(cvesNarrowingHint([{ name: 'products', bytes: 90_000 }], 24_000)).toBe('');
  });

  it('renders the vulnerabilities CVE IDs, and nothing for an outline without them', () => {
    expect(renderOutlineCves(sections)).toEqual([
      '**CVE IDs in the vulnerabilities section (2):** CVE-2026-0001, CVE-2026-0002',
    ]);
    expect(renderOutlineCves([{ name: 'products', bytes: 900 }])).toEqual([]);
  });
});

describe('renderAdvisoryHeader', () => {
  it('renders identity, dates, and attribution', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    const lines = renderAdvisoryHeader(doc.advisory).join('\n');
    expect(lines).toContain('ICSA-26-260-07');
    expect(lines).toContain('Acme Widgets PLC Remote Code Execution');
    expect(lines).toContain('coordinator');
    expect(lines).toContain(doc.advisory.attribution);
  });
});

describe('renderAdvisorySummary', () => {
  it('renders sector text and the verbatim note', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    const lines = renderAdvisorySummary(doc.summary).join('\n');
    expect(lines).toContain('Energy');
    expect(lines).toContain('Sector note (verbatim):');
  });

  it('renders "no sector note" when the advisory carries none', () => {
    const doc = normalizeAdvisory(SPARSE_ADVISORY, '2014/icsa-14-035-01.json');
    if (!doc) throw new Error('expected a normalized document');
    const lines = renderAdvisorySummary(doc.summary).join('\n');
    expect(lines).toContain('no sector note');
  });
});

describe('renderAdvisoryProducts', () => {
  it('renders vendor/product/version rows with the CSAFPID token', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    const lines = renderAdvisoryProducts(doc.products).join('\n');
    expect(lines).toContain('Acme Industries');
    expect(lines).toContain('Widget Controller X200');
    expect(lines).toContain('CSAFPID-0001');
    expect(lines).toContain('Truncated:** no');
  });

  it('describes a capped document from an older index build as awaiting re-ingest, not as re-callable', () => {
    const lines = renderAdvisoryProducts({
      vendorCount: 1,
      productCount: 585,
      shownProducts: 200,
      truncated: true,
      vendors: [],
    }).join('\n');
    expect(lines).toContain('**Truncated:** yes');
    expect(lines).toContain('re-ingest');
    expect(lines).not.toContain('request the products section alone');
  });
});

describe('renderAdvisoryVulnerabilities', () => {
  it('renders CVE, CWE, scores, remediations, and product status', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    const lines = renderAdvisoryVulnerabilities(doc.vulnerabilities).join('\n');
    expect(lines).toContain('CVE-2026-12345');
    expect(lines).toContain('CWE-20');
    expect(lines).toContain('9.8 CRITICAL');
    expect(lines).toContain('vendor_fix');
    expect(lines).toContain('known_affected CSAFPID-0001');
  });

  it('renders "none published" for a vulnerability with no scores', () => {
    const doc = normalizeAdvisory(SPARSE_ADVISORY, '2014/icsa-14-035-01.json');
    if (!doc) throw new Error('expected a normalized document');
    const lines = renderAdvisoryVulnerabilities(doc.vulnerabilities).join('\n');
    expect(lines).toContain('none published for this entry');
  });
});

describe('renderAdvisoryRevisions / renderAdvisoryReferences / renderAdvisoryAcknowledgments', () => {
  it('renders revision history entries', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    const lines = renderAdvisoryRevisions(doc.revisionHistory).join('\n');
    expect(lines).toContain('1.0');
    expect(lines).toContain('1.1');
    expect(lines).toContain('Corrected CVSS vector.');
  });

  it('renders document references', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    const lines = renderAdvisoryReferences(doc.references).join('\n');
    expect(lines).toContain('Vendor advisory');
    expect(lines).toContain('https://acme.example/advisories/2026-01');
  });

  it('renders acknowledgments with organization and names', () => {
    const doc = normalizeAdvisory(FULL_ADVISORY, '2026/icsa-26-260-07.json');
    if (!doc) throw new Error('expected a normalized document');
    const lines = renderAdvisoryAcknowledgments(doc.acknowledgments).join('\n');
    expect(lines).toContain('Acme Security Team');
    expect(lines).toContain('Jane Researcher');
  });

  it('renders "Unattributed" when an acknowledgment has no organization', () => {
    const lines = renderAdvisoryAcknowledgments([{ names: ['Anonymous'], summary: 'thanks' }]).join(
      '\n',
    );
    expect(lines).toContain('Unattributed');
    expect(lines).toContain('Anonymous');
  });
});
