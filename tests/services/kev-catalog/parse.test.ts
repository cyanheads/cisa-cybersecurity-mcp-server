/**
 * @fileoverview Tests for pure KEV feed normalization — the `notes` parser,
 * the reference classifier, directive detection, and the raw-record mapper.
 * @module tests/services/kev-catalog/parse.test
 */

import { describe, expect, it } from 'vitest';
import {
  classifyReference,
  daysBetween,
  kevCatalogUrl,
  parseKevNotes,
  readDirective,
  toKevRecord,
} from '@/services/kev-catalog/parse.js';

describe('classifyReference', () => {
  it('classifies by recognized label first', () => {
    expect(classifyReference('https://www.cisa.gov/bod-26-04', 'BOD 26-04')).toBe('bod_guidance');
    expect(
      classifyReference('https://www.cisa.gov/forensics', 'Forensics Triage Requirements'),
    ).toBe('forensic_triage');
    expect(
      classifyReference('https://www.cisa.gov/mitigation', 'CISA Mitigation Instructions'),
    ).toBe('cisa');
  });

  it('falls back to host when no label is recognized', () => {
    expect(classifyReference('https://nvd.nist.gov/vuln/detail/CVE-2025-1')).toBe('nvd');
    expect(classifyReference('https://www.cisa.gov/some-page')).toBe('cisa');
    expect(classifyReference('https://sub.cisa.gov/some-page')).toBe('cisa');
    expect(classifyReference('https://vendor.example/advisory')).toBe('vendor');
  });

  it('returns other for a string that does not parse as a URL', () => {
    expect(classifyReference('not a url')).toBe('other');
  });
});

describe('parseKevNotes', () => {
  it('parses a labeled segment into a classified reference with its label', () => {
    const parsed = parseKevNotes('BOD 26-04: https://www.cisa.gov/bod-26-04');
    expect(parsed.references).toEqual([
      { kind: 'bod_guidance', label: 'BOD 26-04', url: 'https://www.cisa.gov/bod-26-04' },
    ]);
    expect(parsed.commentary).toBeUndefined();
  });

  it('parses a bare URL classified by host', () => {
    const parsed = parseKevNotes('https://nvd.nist.gov/vuln/detail/CVE-2025-39964');
    expect(parsed.references).toEqual([
      { kind: 'nvd', url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-39964' },
    ]);
  });

  it('handles the shape most of the 175 empty-cwes records carry: a single NVD URL, no prose', () => {
    const parsed = parseKevNotes('https://nvd.nist.gov/vuln/detail/CVE-2025-00001');
    expect(parsed.references).toHaveLength(1);
    expect(parsed.references[0]?.kind).toBe('nvd');
    expect(parsed.commentary).toBeUndefined();
  });

  it('splits multiple semicolon-delimited segments and keeps leading prose as commentary', () => {
    const parsed = parseKevNotes(
      'Apply mitigations per vendor instructions.; https://nvd.nist.gov/vuln/detail/CVE-2025-1; CISA Mitigation Instructions: https://www.cisa.gov/mitigations',
    );
    expect(parsed.commentary).toBe('Apply mitigations per vendor instructions.');
    expect(parsed.references).toEqual([
      { kind: 'nvd', url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-1' },
      {
        kind: 'cisa',
        label: 'CISA Mitigation Instructions',
        url: 'https://www.cisa.gov/mitigations',
      },
    ]);
  });

  it('returns no commentary and no references for an empty string', () => {
    const parsed = parseKevNotes('');
    expect(parsed).toEqual({ references: [] });
  });

  it('ignores blank segments from repeated delimiters', () => {
    const parsed = parseKevNotes(';; https://nvd.nist.gov/vuln/detail/CVE-2025-1 ;;');
    expect(parsed.references).toHaveLength(1);
  });
});

describe('readDirective', () => {
  it('reads BOD 26-04 when present', () => {
    expect(readDirective('Apply updates per BOD 26-04.', '')).toBe('BOD 26-04');
  });

  it('reads BOD 22-01 when present and 26-04 is absent', () => {
    expect(readDirective('', 'Cited under BOD 22-01.')).toBe('BOD 22-01');
  });

  it('prefers BOD 26-04 when both are cited', () => {
    expect(readDirective('BOD 22-01 superseded by BOD 26-04.', '')).toBe('BOD 26-04');
  });

  it('returns null when neither directive is cited — never inferred from age', () => {
    expect(
      readDirective(
        'Apply updates per vendor instructions.',
        'https://nvd.nist.gov/vuln/detail/CVE-2020-1',
      ),
    ).toBeNull();
  });
});

describe('toKevRecord', () => {
  it('maps a full raw record to the domain shape', () => {
    const record = toKevRecord({
      cveID: 'cve-2026-12345',
      vendorProject: ' Acme ',
      product: 'Widget',
      vulnerabilityName: 'Acme Widget RCE',
      dateAdded: '2026-09-10',
      shortDescription: 'Acme Widget contains a vulnerability.',
      requiredAction: 'Apply mitigations per BOD 26-04.',
      dueDate: '2026-09-13',
      knownRansomwareCampaignUse: 'Known',
      forensicTriage: 'Yes',
      cwes: ['CWE-20', 'CWE-89'],
      notes: 'https://nvd.nist.gov/vuln/detail/CVE-2026-12345',
    });
    expect(record).toMatchObject({
      cveId: 'CVE-2026-12345',
      vendorProject: 'Acme',
      product: 'Widget',
      dateAdded: '2026-09-10',
      dueDate: '2026-09-13',
      knownRansomwareCampaignUse: 'Known',
      forensicTriage: 'Yes',
      cwes: ['CWE-20', 'CWE-89'],
      directive: 'BOD 26-04',
    });
    expect(record?.kevUrl).toBe(kevCatalogUrl('CVE-2026-12345'));
    expect(record?.notesCommentary).toBeUndefined();
  });

  it('returns null when the record carries no CVE ID', () => {
    expect(toKevRecord({ vendorProject: 'Acme' })).toBeNull();
  });

  it('defaults knownRansomwareCampaignUse to Unknown and forensicTriage to No for any other value', () => {
    const record = toKevRecord({
      cveID: 'CVE-2026-1',
      knownRansomwareCampaignUse: '',
      forensicTriage: '',
    });
    expect(record?.knownRansomwareCampaignUse).toBe('Unknown');
    expect(record?.forensicTriage).toBe('No');
  });

  it('defaults cwes to an empty array when absent or malformed', () => {
    expect(toKevRecord({ cveID: 'CVE-2026-1' })?.cwes).toEqual([]);
    expect(toKevRecord({ cveID: 'CVE-2026-1', cwes: 'not-an-array' })?.cwes).toEqual([]);
  });

  it('carries notesCommentary when the notes field opens with prose', () => {
    const record = toKevRecord({
      cveID: 'CVE-2026-1',
      notes: 'Exploited in the wild.; https://nvd.nist.gov/vuln/detail/CVE-2026-1',
    });
    expect(record?.notesCommentary).toBe('Exploited in the wild.');
  });
});

describe('daysBetween', () => {
  it('computes whole calendar days forward and backward', () => {
    expect(daysBetween('2026-09-10', '2026-09-13')).toBe(3);
    expect(daysBetween('2026-09-13', '2026-09-10')).toBe(-3);
    expect(daysBetween('2026-09-10', '2026-09-10')).toBe(0);
  });

  it('returns 0 for unparseable dates rather than throwing', () => {
    expect(daysBetween('not-a-date', '2026-09-10')).toBe(0);
  });
});
