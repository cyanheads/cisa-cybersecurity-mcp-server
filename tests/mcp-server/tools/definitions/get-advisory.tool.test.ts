/**
 * @fileoverview Tests for `cisa_get_advisory` — found: false guidance,
 * unknown_section, a named-section selection, the outline-on-overflow arm for
 * an oversized advisory, and the products cap/truncated disclosure.
 * @module tests/mcp-server/tools/definitions/get-advisory.tool.test
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getAdvisoryTool } from '@/mcp-server/tools/definitions/get-advisory.tool.js';
import {
  getCsafMirror,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL } from '@/services/csaf-mirror/ingest.js';
import { buildOversizedAdvisory, FULL_ADVISORY } from '../../../fixtures/csaf-documents.js';
import { buildTarGzResponse } from '../../../fixtures/tar.js';
import { firstText } from '../../../helpers/format-text.js';

async function seedMirror(entries: Array<{ name: string; data: string }>) {
  const http = createFetchMock([
    { match: CSAF_ARCHIVE_URL, respond: () => buildTarGzResponse(entries) },
  ]);
  http.install();
  try {
    await getCsafMirror().mirrorInstance.runSync({
      mode: 'init',
      signal: AbortSignal.timeout(30_000),
    });
  } finally {
    http.restore();
  }
}

describe('cisa_get_advisory', () => {
  let dir: string;

  beforeEach(() => {
    resetCsafMirror();
    dir = mkdtempSync(join(tmpdir(), 'get-advisory-'));
    initCsafMirror({ mirrorPath: join(dir, 'csaf.sqlite3'), timeoutMs: 5000 });
  });

  afterEach(() => {
    resetCsafMirror();
    rmSync(dir, { recursive: true, force: true });
  });

  it('throws mirror_not_ready before the first sync completes', async () => {
    const ctx = createMockContext({ errors: getAdvisoryTool.errors });
    const input = getAdvisoryTool.input.parse({ advisoryId: 'ICSA-26-260-07' });
    await expect(getAdvisoryTool.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'mirror_not_ready' },
    });
  });

  describe('once seeded with a normal advisory', () => {
    beforeEach(async () => {
      await seedMirror([
        {
          name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json',
          data: JSON.stringify(FULL_ADVISORY),
        },
      ]);
    }, 30000);

    it('returns found: false with guidance for an unknown advisoryId', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({ advisoryId: 'ICSA-99-999-99' });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.found).toBe(false);
      expect(result.guidance).toContain('cisa_search_ics_advisories');

      const text = firstText(getAdvisoryTool.format?.(result));
      expect(text).toContain('not found');
      expect(text).toContain(result.guidance as string);
    });

    it('normalizes ID case before lookup', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({ advisoryId: 'icsa-26-260-07' });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.found).toBe(true);
      expect(result.advisory?.advisoryId).toBe('ICSA-26-260-07');
    });

    it('accepts an advisoryId with a trailing .json, per the documented normalization', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({ advisoryId: 'icsa-26-260-07.json' });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.found).toBe(true);
      expect(result.advisory?.advisoryId).toBe('ICSA-26-260-07');
    });

    it('returns the full document with kind: full when under budget', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({ advisoryId: 'ICSA-26-260-07' });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.kind).toBe('full');
      expect(result.advisory).toBeDefined();
      expect(result.products).toBeDefined();
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.products?.truncated).toBeUndefined();

      const text = firstText(getAdvisoryTool.format?.(result));
      expect(text).toContain(result.advisory?.advisoryId as string);
      expect(text).toContain(result.vulnerabilities?.[0]?.cve as string);
    });

    it('a sections request for names the advisory genuinely carries succeeds', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({
        advisoryId: 'ICSA-26-260-07',
        sections: ['advisory', 'references'],
      });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.found).toBe(true);
      expect(result.references).toBeDefined();
    });

    it('selects only named sections, always keeping advisory', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({
        advisoryId: 'ICSA-26-260-07',
        sections: ['vulnerabilities'],
      });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.kind).toBe('full');
      expect(result.advisory).toBeDefined();
      expect(result.vulnerabilities).toBeDefined();
      expect(result.products).toBeUndefined();
      expect(result.summary).toBeUndefined();
    });
  });

  describe('an advisory sized to overflow the outline budget', () => {
    beforeEach(async () => {
      const raw = buildOversizedAdvisory('ICSA-26-001-01');
      await seedMirror([
        {
          name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-001-01.json',
          data: JSON.stringify(raw),
        },
      ]);
    }, 30000);

    it('returns a section outline instead of the whole document', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({ advisoryId: 'ICSA-26-001-01' });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.kind).toBe('outline');
      expect(result.sections).toBeDefined();
      expect(result.sections?.length).toBeGreaterThan(0);
      expect(result.outlineNotice).toBeDefined();
      expect(result.vulnerabilities).toBeUndefined();

      const blocks = getAdvisoryTool.format?.(result) ?? [];
      const combined = blocks.map((b) => (b as { text: string }).text).join('\n');
      expect(combined).toContain('outline');
      expect(combined).toContain(result.outlineNotice as string);
      for (const section of result.sections ?? []) {
        expect(combined).toContain(section.name);
      }
    });

    it('a follow-up call with sections returns exactly the requested arm', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({
        advisoryId: 'ICSA-26-001-01',
        sections: ['vulnerabilities'],
      });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.kind).toBe('full');
      expect(result.vulnerabilities).toBeDefined();
      expect(result.vulnerabilities?.length).toBeGreaterThan(0);
      expect(result.sections).toBeUndefined();
    });

    it('throws unknown_section for a section name the advisory does not carry (no acknowledgments)', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({
        advisoryId: 'ICSA-26-001-01',
        sections: ['acknowledgments'],
      });
      await expect(getAdvisoryTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'unknown_section' },
      });
    });
  });

  describe('an advisory with more products than the 200-row cap', () => {
    beforeEach(async () => {
      const branches = Array.from({ length: 205 }, (_, index) => ({
        category: 'product_name',
        name: `Product ${index}`,
        product: { name: `Product ${index}`, product_id: `CSAFPID-${index}` },
      }));
      const raw = {
        document: {
          title: 'Many Products Advisory',
          csaf_version: '2.0',
          publisher: { name: 'CISA', category: 'coordinator' },
          tracking: {
            id: 'ICSA-26-002-01',
            status: 'final',
            version: '1.0',
            initial_release_date: '2026-01-01T00:00:00Z',
            current_release_date: '2026-01-01T00:00:00Z',
            revision_history: [
              { number: '1.0', date: '2026-01-01T00:00:00Z', summary: 'Initial.' },
            ],
          },
          notes: [],
          references: [],
        },
        product_tree: { branches: [{ category: 'vendor', name: 'BigVendor', branches }] },
        vulnerabilities: [
          {
            cve: 'CVE-2026-90000',
            product_status: {
              known_affected: [],
              fixed: [],
              known_not_affected: [],
              recommended: [],
            },
            scores: [],
            remediations: [],
          },
        ],
      };
      await seedMirror([
        {
          name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-002-01.json',
          data: JSON.stringify(raw),
        },
      ]);
    }, 30000);

    it('caps the products arm at 200 rows and discloses truncation', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({
        advisoryId: 'ICSA-26-002-01',
        sections: ['products'],
      });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.products?.shownProducts).toBe(200);
      expect(result.products?.truncated).toBe(true);
      expect(result.products?.productCount).toBe(205);

      const text = firstText(getAdvisoryTool.format?.(result));
      expect(text).toContain('Truncated:** yes');
    });
  });

  it('rejects an advisoryId that does not match the ICSA/ICSMA pattern', () => {
    expect(() => getAdvisoryTool.input.parse({ advisoryId: 'NOT-AN-ID' })).toThrow();
  });

  it('rejects an unknown value in sections', () => {
    expect(() =>
      getAdvisoryTool.input.parse({
        advisoryId: 'ICSA-26-260-07',
        sections: ['not-a-real-section'],
      }),
    ).toThrow();
  });
});
