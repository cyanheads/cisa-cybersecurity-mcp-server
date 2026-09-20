/**
 * @fileoverview Tests for CVSS severity-band derivation — the v2/v3 scale
 * boundaries, including the v2 scale's missing NONE and CRITICAL bands.
 * @module tests/reference/cvss.test
 */

import { describe, expect, it } from 'vitest';
import { deriveCvssV2Severity, deriveCvssV3Severity } from '@/reference/cvss.js';

describe('deriveCvssV3Severity', () => {
  it.each([
    [0, 'NONE'],
    [0.1, 'LOW'],
    [3.9, 'LOW'],
    [4.0, 'MEDIUM'],
    [6.9, 'MEDIUM'],
    [7.0, 'HIGH'],
    [8.9, 'HIGH'],
    [9.0, 'CRITICAL'],
    [10.0, 'CRITICAL'],
  ] as const)('%f -> %s', (score, band) => {
    expect(deriveCvssV3Severity(score)).toBe(band);
  });
});

describe('deriveCvssV2Severity', () => {
  it('has no CRITICAL band — a 10.0 v2 score is HIGH', () => {
    expect(deriveCvssV2Severity(10.0)).toBe('HIGH');
  });

  it.each([
    [0, 'LOW'],
    [3.9, 'LOW'],
    [4.0, 'MEDIUM'],
    [6.9, 'MEDIUM'],
    [7.0, 'HIGH'],
  ] as const)('%f -> %s', (score, band) => {
    expect(deriveCvssV2Severity(score)).toBe(band);
  });
});
