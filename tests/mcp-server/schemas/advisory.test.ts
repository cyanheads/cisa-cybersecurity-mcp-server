/**
 * @fileoverview Tests for the shared advisory output schema helpers and
 * markdown renderers — `isEmptySection`, `presentSections`, and the seven
 * section renderers `cisa_get_advisory` and the resource both use.
 * @module tests/mcp-server/schemas/advisory.test
 */

import { describe, expect, it } from 'vitest';
import {
  isEmptySection,
  presentSections,
  renderAdvisoryAcknowledgments,
  renderAdvisoryHeader,
  renderAdvisoryProducts,
  renderAdvisoryReferences,
  renderAdvisoryRevisions,
  renderAdvisorySummary,
  renderAdvisoryVulnerabilities,
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
