/**
 * @fileoverview Tests for the streaming tar/gzip reader over the CSAF archive
 * shape — ustar regular files, filtering by name, and size-based skipping of
 * non-matching entries.
 * @module tests/services/csaf-mirror/tar.test
 */

import { describe, expect, it } from 'vitest';
import { iterateTarGz } from '@/services/csaf-mirror/tar.js';
import { buildTarGzResponse } from '../../fixtures/tar.js';

async function collect(response: Response, include: (name: string) => boolean) {
  const entries: Array<{ name: string; text: string }> = [];
  if (!response.body) throw new Error('fixture response carries no body');
  for await (const entry of iterateTarGz(response.body, include)) {
    entries.push({ name: entry.name, text: new TextDecoder().decode(entry.data) });
  }
  return entries;
}

describe('iterateTarGz', () => {
  it('yields every entry whose name satisfies the include predicate', async () => {
    const response = buildTarGzResponse([
      { name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json', data: '{"a":1}' },
      { name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json.asc', data: 'SIGNATURE' },
      { name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json.sha512', data: 'HASH' },
      { name: 'CSAF-develop/README.md', data: '# readme' },
    ]);

    const include = (name: string): boolean =>
      name.includes('csaf_files/OT/white/') && name.endsWith('.json');
    const entries = await collect(response, include);

    expect(entries).toHaveLength(1);
    expect(entries[0]?.name).toBe('CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json');
    expect(entries[0]?.text).toBe('{"a":1}');
  });

  it('skips non-matching entries without corrupting the stream position', async () => {
    const response = buildTarGzResponse([
      { name: 'skip-me.txt', data: 'x'.repeat(1000) /* spans multiple 512-byte blocks */ },
      { name: 'keep-me.json', data: '{"kept":true}' },
    ]);

    const entries = await collect(response, (name) => name.endsWith('.json'));
    expect(entries).toEqual([{ name: 'keep-me.json', text: '{"kept":true}' }]);
  });

  it('yields nothing for an archive with no matching entries', async () => {
    const response = buildTarGzResponse([{ name: 'only.txt', data: 'irrelevant' }]);
    const entries = await collect(response, (name) => name.endsWith('.json'));
    expect(entries).toEqual([]);
  });

  it('handles an entry whose content is exactly one tar block', async () => {
    const response = buildTarGzResponse([{ name: 'exact.json', data: 'x'.repeat(512) }]);
    const entries = await collect(response, (name) => name.endsWith('.json'));
    expect(entries[0]?.text).toBe('x'.repeat(512));
  });
});
