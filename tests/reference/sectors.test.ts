/**
 * @fileoverview Tests for the critical-infrastructure sector extractor —
 * comma-and-"and" sector names, alias resolution, upstream typos, and the
 * `Multiple` sentinel.
 * @module tests/reference/sectors.test
 */

import { describe, expect, it } from 'vitest';
import { extractSectors } from '@/reference/sectors.js';

describe('extractSectors', () => {
  it('resolves a single canonical name', () => {
    expect(extractSectors('Energy')).toEqual(['Energy']);
  });

  it('resolves names containing "and" without producing garbage tokens', () => {
    expect(extractSectors('Healthcare and Public Health')).toEqual([
      'Healthcare and Public Health',
    ]);
    expect(extractSectors('Water and Wastewater Systems')).toEqual([
      'Water and Wastewater Systems',
    ]);
  });

  it('resolves the comma-and-"and" sector name Nuclear Reactors, Materials, and Waste', () => {
    expect(extractSectors('Nuclear Reactors, Materials, and Waste')).toEqual([
      'Nuclear Reactors, Materials, and Waste',
    ]);
  });

  it('resolves multiple sectors joined by commas and "and", in canonical order regardless of input order', () => {
    expect(
      extractSectors('Water and Wastewater Systems, Energy, and Healthcare and Public Health'),
    ).toEqual(['Energy', 'Healthcare and Public Health', 'Water and Wastewater Systems']);
  });

  it('resolves the alias "Health Care and Public Health" to the canonical name', () => {
    expect(extractSectors('Health Care and Public Health')).toEqual([
      'Healthcare and Public Health',
    ]);
  });

  it('resolves the alias "Water and Wastewater" (without "Systems") to the canonical name', () => {
    expect(extractSectors('Water and Wastewater')).toEqual(['Water and Wastewater Systems']);
  });

  it('resolves known upstream typos for Critical Manufacturing', () => {
    expect(extractSectors('Critical Manuacturing')).toEqual(['Critical Manufacturing']);
    expect(extractSectors('Critical Manufacturer')).toEqual(['Critical Manufacturing']);
  });

  it('resolves "Multiple Sectors" and bare "Multiple" to the Multiple sentinel, ordered last', () => {
    expect(extractSectors('Multiple Sectors')).toEqual(['Multiple']);
    expect(extractSectors('Energy, Multiple')).toEqual(['Energy', 'Multiple']);
  });

  it('is case- and whitespace-insensitive', () => {
    /* Canonical order wins regardless of input order — Defense Industrial Base
     * precedes Energy in CANONICAL_SECTORS. */
    expect(extractSectors('  eNeRgY   and   defense industrial base ')).toEqual([
      'Defense Industrial Base',
      'Energy',
    ]);
  });

  it('does not let a shorter name re-match inside an already-consumed longer one', () => {
    /* "Government Facilities" must not also register a spurious separate hit
     * once "Government Services and Facilities" (an alias) has been consumed. */
    expect(extractSectors('Government Services and Facilities')).toEqual(['Government Facilities']);
  });

  it('returns an empty array when nothing in the note resolves to a canonical name', () => {
    expect(extractSectors('Some Completely Unrelated Text')).toEqual([]);
  });
});
