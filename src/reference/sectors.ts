/**
 * @fileoverview Critical-infrastructure sector vocabulary and the extractor that
 * normalizes an advisory's free-form sector note against it.
 *
 * The note is prose, not an enum, and separator splitting is definitively wrong:
 * two canonical names contain the word "and" (`Healthcare and Public Health`,
 * `Water and Wastewater Systems`) and one contains commas (`Nuclear Reactors,
 * Materials, and Waste`), so splitting on `,` or `and` produces tokens like
 * `and Water` and `Facilities`. The extractor instead matches canonical names and
 * a small alias table longest-first, consuming each hit so a shorter name cannot
 * re-match inside a longer one already claimed.
 *
 * Callers keep the verbatim note alongside the normalized set, so nothing a
 * caller might need is lost to normalization.
 * @module reference/sectors
 */

/** The sixteen canonical sector names, in CISA's own order. */
export const CANONICAL_SECTORS = [
  'Chemical',
  'Commercial Facilities',
  'Communications',
  'Critical Manufacturing',
  'Dams',
  'Defense Industrial Base',
  'Emergency Services',
  'Energy',
  'Financial Services',
  'Food and Agriculture',
  'Government Facilities',
  'Healthcare and Public Health',
  'Information Technology',
  'Nuclear Reactors, Materials, and Waste',
  'Transportation Systems',
  'Water and Wastewater Systems',
] as const;

/** A canonical sector name, or the `Multiple` sentinel the corpus uses for "all of them". */
export type SectorName = (typeof CANONICAL_SECTORS)[number] | 'Multiple';

/** Every value the `sector` filter accepts. */
export const SECTOR_FILTER_VALUES: readonly SectorName[] = [...CANONICAL_SECTORS, 'Multiple'];

/**
 * Surface spellings that resolve to a canonical name — generator-version drift,
 * punctuation variants, the upstream typos observed across the corpus, and the
 * one-to-one short forms (`Water`, `Transportation`, `Healthcare`). A short form
 * cannot steal a match inside the longer canonical name it abbreviates, because
 * matching runs longest-first and consumes each hit. `Critical Facilities` is
 * deliberately absent: it could mean Commercial, Government, or Critical
 * Manufacturing, and no one-to-one reading exists.
 */
const SECTOR_ALIASES: ReadonlyArray<readonly [string, SectorName]> = [
  ['Government Services and Facilities', 'Government Facilities'],
  ['Nuclear Reactors, Materials and Waste', 'Nuclear Reactors, Materials, and Waste'],
  ['Nuclear Reactors Materials and Waste', 'Nuclear Reactors, Materials, and Waste'],
  ['Health Care and Public Health', 'Healthcare and Public Health'],
  ['Healthcare and Public Heath', 'Healthcare and Public Health'],
  ['Food & Agriculture', 'Food and Agriculture'],
  ['Water and Wastewater', 'Water and Wastewater Systems'],
  ['Critical Manuacturing', 'Critical Manufacturing'],
  ['Critical Manufacturer', 'Critical Manufacturing'],
  ['Critical Manufaturing', 'Critical Manufacturing'],
  ['Healthcare, Public Health', 'Healthcare and Public Health'],
  ['Health, Public Health', 'Healthcare and Public Health'],
  ['Healthcare', 'Healthcare and Public Health'],
  ['Transportation', 'Transportation Systems'],
  ['Water', 'Water and Wastewater Systems'],
  ['Multiple Sectors', 'Multiple'],
  ['Multiple', 'Multiple'],
];

/** Match patterns, longest surface form first so a substring cannot steal a longer match. */
const MATCHERS: ReadonlyArray<readonly [string, SectorName]> = [
  ...CANONICAL_SECTORS.map((name) => [name, name] as const),
  ...SECTOR_ALIASES,
].sort((a, b) => b[0].length - a[0].length);

/** Collapse whitespace and lowercase, so matching ignores case and line wrapping. */
function fold(value: string): string {
  return value.toLowerCase().replace(/\s+/g, ' ');
}

/**
 * Extract the canonical sector set from an advisory's sector note. Returns the
 * names in canonical order (with `Multiple` last when present) and an empty array
 * when nothing in the note resolves — one note (`Critical Facilities`, 1 of the
 * 3,197 documents carrying a note at the 2026-09-17 index checkpoint) resolves to
 * nothing, and an empty set is the honest answer for it.
 */
export function extractSectors(raw: string): SectorName[] {
  let remaining = fold(raw);
  const found = new Set<SectorName>();

  for (const [surface, canonical] of MATCHERS) {
    const needle = fold(surface);
    if (!remaining.includes(needle)) continue;
    found.add(canonical);
    remaining = remaining.split(needle).join(' ');
  }

  const ordered = CANONICAL_SECTORS.filter((name) => found.has(name)) as SectorName[];
  if (found.has('Multiple')) ordered.push('Multiple');
  return ordered;
}

/** The note title an advisory carries its sector list under, folded for comparison. */
export const SECTOR_NOTE_TITLE = 'critical infrastructure sectors';
