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

  describe('short-form sector notes', () => {
    it.each([
      ['Transportation', 'Transportation Systems'],
      ['Water', 'Water and Wastewater Systems'],
      ['Healthcare', 'Healthcare and Public Health'],
      ['Healthcare, Public Health', 'Healthcare and Public Health'],
      ['Health, Public Health', 'Healthcare and Public Health'],
    ] as const)('resolves "%s" to %s', (note, canonical) => {
      expect(extractSectors(note)).toEqual([canonical]);
    });

    it('leaves the ambiguous "Critical Facilities" unresolved', () => {
      expect(extractSectors('Critical Facilities')).toEqual([]);
    });

    it('does not double-match a short form inside a longer canonical name already consumed', () => {
      expect(extractSectors('Transportation Systems')).toEqual(['Transportation Systems']);
      expect(extractSectors('Water and Wastewater Systems, Transportation Systems')).toEqual([
        'Transportation Systems',
        'Water and Wastewater Systems',
      ]);
      expect(
        extractSectors('Healthcare and Public Health, Water and Wastewater Systems, Energy'),
      ).toEqual(['Energy', 'Healthcare and Public Health', 'Water and Wastewater Systems']);
    });

    it('resolves short forms mixed with canonical names in one note', () => {
      expect(extractSectors('Energy, Water, Transportation')).toEqual([
        'Energy',
        'Transportation Systems',
        'Water and Wastewater Systems',
      ]);
    });
  });
});
