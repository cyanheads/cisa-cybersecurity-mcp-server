/**
 * @fileoverview Tests for the shared KEV record projection and markdown
 * renderer — the one shape `cisa_check_cve_status`, `cisa_search_kev`, and the
 * `cisa://kev/{cveId}` resource all return.
 * @module tests/mcp-server/schemas/kev-record.test
 */

import { describe, expect, it } from 'vitest';
import {
  KevRecordSchema,
  renderKevRecord,
  toKevRecordOutput,
  toMissingKevOutput,
} from '@/mcp-server/schemas/kev-record.js';
import type { KevRecord } from '@/services/kev-catalog/types.js';

const RECORD: KevRecord = {
  cveId: 'CVE-2026-12345',
  vendorProject: 'Acme',
  product: 'Widget',
  vulnerabilityName: 'Acme Widget RCE',
  dateAdded: '2026-09-10',
  shortDescription: 'Acme Widget contains a vulnerability.',
  requiredAction: 'Apply mitigations per BOD 26-04.',
  dueDate: '2026-09-13',
  knownRansomwareCampaignUse: 'Known',
  forensicTriage: 'Yes',
  cwes: ['CWE-20'],
  references: [{ kind: 'nvd', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-12345' }],
  directive: 'BOD 26-04',
  kevUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-12345',
};

describe('toKevRecordOutput', () => {
  it('computes daysUntilDue and overdue from the supplied asOf date', () => {
    const output = toKevRecordOutput(RECORD, '2026-09-10');
    expect(output.inKev).toBe(true);
    expect(output.daysUntilDue).toBe(3);
    expect(output.overdue).toBe(false);
  });

  it('marks overdue: true and a negative daysUntilDue once asOf passes dueDate', () => {
    const output = toKevRecordOutput(RECORD, '2026-09-20');
    expect(output.overdue).toBe(true);
    expect(output.daysUntilDue).toBe(-7);
  });

  it('carries notesCommentary only when the record has it', () => {
    expect(toKevRecordOutput(RECORD, '2026-09-10').notesCommentary).toBeUndefined();
    const withCommentary = { ...RECORD, notesCommentary: 'Exploited in the wild.' };
    expect(toKevRecordOutput(withCommentary, '2026-09-10').notesCommentary).toBe(
      'Exploited in the wild.',
    );
  });

  it('validates against KevRecordSchema', () => {
    const output = toKevRecordOutput(RECORD, '2026-09-10');
    expect(() => KevRecordSchema.parse(output)).not.toThrow();
  });
});

describe('toMissingKevOutput', () => {
  it('returns a minimal not-in-KEV result', () => {
    expect(toMissingKevOutput('CVE-2099-00001')).toEqual({ cveId: 'CVE-2099-00001', inKev: false });
  });

  it('validates against KevRecordSchema', () => {
    expect(() => KevRecordSchema.parse(toMissingKevOutput('CVE-2099-00001'))).not.toThrow();
  });
});

describe('renderKevRecord', () => {
  it('renders every field the structured output carries', () => {
    const output = toKevRecordOutput(RECORD, '2026-09-10');
    const lines = renderKevRecord(output).join('\n');
    expect(lines).toContain('CVE-2026-12345');
    expect(lines).toContain('Acme Widget RCE');
    expect(lines).toContain('Acme');
    expect(lines).toContain('Widget');
    expect(lines).toContain('2026-09-10');
    expect(lines).toContain('2026-09-13');
    expect(lines).toContain('3 day(s) remaining');
    expect(lines).toContain('BOD 26-04');
    expect(lines).toContain('Known');
    expect(lines).toContain('Yes');
    expect(lines).toContain(RECORD.shortDescription);
    expect(lines).toContain(RECORD.requiredAction);
    expect(lines).toContain('CWE-20');
    expect(lines).toContain('nvd');
    expect(lines).toContain(RECORD.kevUrl);
  });

  it('renders overdue status distinctly', () => {
    const output = toKevRecordOutput(RECORD, '2026-09-20');
    const lines = renderKevRecord(output).join('\n');
    expect(lines).toContain('overdue by 7 day(s)');
    expect(lines).toContain('overdue: yes');
  });

  it('renders directive: none for a null directive', () => {
    const output = toKevRecordOutput({ ...RECORD, directive: null }, '2026-09-10');
    const lines = renderKevRecord(output).join('\n');
    expect(lines).toContain('Directive cited:** none');
  });

  it('renders an empty CWE list as "none listed"', () => {
    const output = toKevRecordOutput({ ...RECORD, cwes: [] }, '2026-09-10');
    const lines = renderKevRecord(output).join('\n');
    expect(lines).toContain('none listed');
  });

  it('renders a short, distinct block for a not-in-KEV result', () => {
    const lines = renderKevRecord(toMissingKevOutput('CVE-2099-00001'));
    expect(lines).toEqual([
      '### CVE-2099-00001',
      '**In KEV:** no — CISA has not confirmed exploitation in the wild for this CVE.',
    ]);
  });
});
