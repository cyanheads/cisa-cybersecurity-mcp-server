/**
 * @fileoverview Tests for the BOD 26-04 Table 1 resolver — all sixteen rows,
 * covering every combination of the four decision points.
 * @module tests/reference/bod-2604.test
 */

import { describe, expect, it } from 'vitest';
import { BOD_2604_TABLE_1, resolveBod2604Timeline } from '@/reference/bod-2604.js';

describe('resolveBod2604Timeline', () => {
  it('resolves all sixteen Table 1 rows from their own decision-point combination', () => {
    for (const row of BOD_2604_TABLE_1) {
      const resolved = resolveBod2604Timeline({
        publiclyExposed: row.publiclyExposed,
        inKev: row.inKev,
        automatable: row.automatable,
        technicalImpact: row.technicalImpact,
      });
      expect(resolved).toEqual(row);
    }
  });

  it('row 1: publicly exposed, in KEV, automatable, total impact — 3 days & forensic triage', () => {
    const row = resolveBod2604Timeline({
      publiclyExposed: true,
      inKev: true,
      automatable: true,
      technicalImpact: 'total',
    });
    expect(row.row).toBe(1);
    expect(row.remediationTimelineDays).toBe(3);
    expect(row.forensicTriageRequired).toBe(true);
  });

  it('rows 15 and 16 carry remediationTimelineDays: null for "Fix on system upgrade"', () => {
    const row15 = resolveBod2604Timeline({
      publiclyExposed: false,
      inKev: false,
      automatable: false,
      technicalImpact: 'total',
    });
    const row16 = resolveBod2604Timeline({
      publiclyExposed: false,
      inKev: false,
      automatable: false,
      technicalImpact: 'partial',
    });
    expect(row15.remediationTimelineDays).toBeNull();
    expect(row15.timelineLabel).toBe('Fix on system upgrade');
    expect(row16.remediationTimelineDays).toBeNull();
  });

  it('is a total function over the 2x2x2x2 input space — every combination resolves', () => {
    for (const publiclyExposed of [true, false]) {
      for (const inKev of [true, false]) {
        for (const automatable of [true, false]) {
          for (const technicalImpact of ['partial', 'total'] as const) {
            expect(() =>
              resolveBod2604Timeline({ publiclyExposed, inKev, automatable, technicalImpact }),
            ).not.toThrow();
          }
        }
      }
    }
  });
});
