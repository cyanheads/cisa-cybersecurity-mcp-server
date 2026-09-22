/**
 * @fileoverview Tests for `cisa_get_advisory` — found: false guidance,
 * unknown_section, a named-section selection, the outline-on-overflow arm for
 * an oversized advisory with its CVE listing, `cves` narrowing and its two
 * errors, and a 585-product advisory served whole.
 * @module tests/mcp-server/tools/definitions/get-advisory.tool.test
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createFetchMock,
  createMockContext,
  runToolContract,
} from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ADVISORY_OUTLINE_BUDGET } from '@/mcp-server/schemas/advisory.js';
import { getAdvisoryTool } from '@/mcp-server/tools/definitions/get-advisory.tool.js';
import {
  getCsafMirror,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL } from '@/services/csaf-mirror/ingest.js';
import {
  buildOversizedAdvisory,
  FULL_ADVISORY,
  SPARSE_ADVISORY,
} from '../../../fixtures/csaf-documents.js';
import { buildTarGzResponse } from '../../../fixtures/tar.js';
import { contentText, firstText } from '../../../helpers/format-text.js';

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

    it('through the contract, the outline lists every section with its byte size on both surfaces', async () => {
      const result = await runToolContract(getAdvisoryTool, { advisoryId: 'ICSA-26-001-01' });
      expect(result.isError).toBeFalsy();
      const structured = result.structuredContent as {
        kind: string;
        sections: Array<Record<string, unknown>>;
      };
      expect(structured.kind).toBe('outline');
      const doc = await getCsafMirror().getAdvisory('ICSA-26-001-01');
      const vulnerabilities = structured.sections.find(
        (section) => section.name === 'vulnerabilities',
      );
      expect(vulnerabilities?.bytes).toBe(JSON.stringify(doc?.vulnerabilities).length);
      const text = contentText(result);
      for (const section of structured.sections) {
        expect(text).toContain(`- \`${String(section.name)}\` — ${String(section.bytes)} bytes`);
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

    describe('cves', () => {
      type Structured = {
        advisory?: unknown;
        kind: string;
        outlineNotice?: string;
        products?: unknown;
        sections?: Array<{ name: string; bytes: number; cves?: string[] }>;
        summary?: unknown;
        vulnerabilities?: Array<{ cve: string }>;
      };
      const ALL_CVES = Array.from({ length: 40 }, (_, index) => `CVE-2026-${10000 + index}`);

      it('the outline lists the vulnerabilities section’s CVE IDs beside its byte size, on both surfaces', async () => {
        const result = await runToolContract(getAdvisoryTool, { advisoryId: 'ICSA-26-001-01' });
        const structured = result.structuredContent as Structured;
        const vulnerabilities = structured.sections?.find((s) => s.name === 'vulnerabilities');
        expect(vulnerabilities?.cves).toEqual(ALL_CVES);
        for (const section of structured.sections ?? []) {
          if (section.name !== 'vulnerabilities') expect(section).not.toHaveProperty('cves');
        }
        expect(structured.outlineNotice).toContain('pass cves with IDs from its listed CVEs');
        const text = contentText(result);
        expect(text).toContain(
          `**CVE IDs in the vulnerabilities section (40):** ${ALL_CVES.join(', ')}`,
        );
        expect(text).toContain(structured.outlineNotice as string);
      });

      it('alone, selects the vulnerabilities section narrowed to the named entries', async () => {
        const result = await runToolContract(getAdvisoryTool, {
          advisoryId: 'ICSA-26-001-01',
          cves: ['CVE-2026-10035'],
        });
        expect(result.isError).toBeFalsy();
        const structured = result.structuredContent as Structured;
        expect(structured.kind).toBe('full');
        expect(structured.advisory).toBeDefined();
        expect(structured.vulnerabilities?.map((entry) => entry.cve)).toEqual(['CVE-2026-10035']);
        expect(structured.products).toBeUndefined();
        expect(structured.summary).toBeUndefined();
        expect(structured.sections).toBeUndefined();
        const text = contentText(result);
        expect(text).toContain('### CVE-2026-10035');
        expect(text).not.toContain('### CVE-2026-10000');
        expect(JSON.stringify(structured).length).toBeLessThan(ADVISORY_OUTLINE_BUDGET);
      });

      it('keeps document order, drops duplicates, and normalizes case and whitespace', async () => {
        const result = await runToolContract(getAdvisoryTool, {
          advisoryId: 'ICSA-26-001-01',
          cves: [' cve-2026-10039 ', 'CVE-2026-10001', 'CVE-2026-10039'],
        });
        const structured = result.structuredContent as Structured;
        expect(structured.vulnerabilities?.map((entry) => entry.cve)).toEqual([
          'CVE-2026-10001',
          'CVE-2026-10039',
        ]);
      });

      it('with sections including vulnerabilities, narrows that section and returns the others whole', async () => {
        const result = await runToolContract(getAdvisoryTool, {
          advisoryId: 'ICSA-26-001-01',
          sections: ['summary', 'vulnerabilities'],
          cves: ['CVE-2026-10000'],
        });
        const structured = result.structuredContent as Structured;
        expect(structured.summary).toBeDefined();
        expect(structured.vulnerabilities?.map((entry) => entry.cve)).toEqual(['CVE-2026-10000']);
        expect(structured.products).toBeUndefined();
      });

      it('every CVE requested returns the whole section', async () => {
        const result = await runToolContract(getAdvisoryTool, {
          advisoryId: 'ICSA-26-001-01',
          cves: ALL_CVES,
        });
        expect((result.structuredContent as Structured).vulnerabilities).toHaveLength(40);
      });

      it('an empty cves list behaves as if cves were omitted', async () => {
        const result = await runToolContract(getAdvisoryTool, {
          advisoryId: 'ICSA-26-001-01',
          cves: [],
        });
        expect((result.structuredContent as Structured).kind).toBe('outline');
      });

      it('with sections lacking vulnerabilities, fails as cves_need_vulnerabilities_section with its recovery hint', async () => {
        const result = await runToolContract(getAdvisoryTool, {
          advisoryId: 'ICSA-26-001-01',
          sections: ['products'],
          cves: ['CVE-2026-10000'],
        });
        expect(result.isError).toBe(true);
        const text = contentText(result);
        expect(text).toContain('cves narrows the vulnerabilities section');
        expect(text).toContain('Add "vulnerabilities" to sections');
        expect(JSON.stringify(result.structuredContent)).toContain(
          'cves_need_vulnerabilities_section',
        );
      });

      it('a CVE the advisory does not cover fails as unknown_cve naming only the unknown IDs', async () => {
        const result = await runToolContract(getAdvisoryTool, {
          advisoryId: 'ICSA-26-001-01',
          cves: ['CVE-2026-10000', 'CVE-1999-0001', 'CVE-2026-99999'],
        });
        expect(result.isError).toBe(true);
        const text = contentText(result);
        expect(text).toContain('does not cover CVE-1999-0001, CVE-2026-99999');
        expect(text).not.toContain('does not cover CVE-2026-10000');
        expect(text).toContain('the outline lists them');
        expect(JSON.stringify(result.structuredContent)).toContain('unknown_cve');
      });

      it('rejects a malformed CVE ID at the schema', () => {
        expect(() =>
          getAdvisoryTool.input.parse({ advisoryId: 'ICSA-26-001-01', cves: ['2026-10000'] }),
        ).toThrow();
      });
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

  describe('an advisory under budget whose vulnerability entries repeat a CVE', () => {
    beforeEach(async () => {
      const repeated = {
        ...SPARSE_ADVISORY,
        vulnerabilities: [
          SPARSE_ADVISORY.vulnerabilities[0],
          SPARSE_ADVISORY.vulnerabilities[1],
          { ...SPARSE_ADVISORY.vulnerabilities[0], title: 'A second entry for the same CVE' },
        ],
      };
      await seedMirror([
        {
          name: 'CSAF-develop/csaf_files/OT/white/2014/icsa-14-035-01.json',
          data: JSON.stringify(repeated),
        },
      ]);
    }, 30000);

    it('omitting cves still returns the whole document, not an outline', async () => {
      const result = await runToolContract(getAdvisoryTool, { advisoryId: 'ICSA-14-035-01' });
      const structured = result.structuredContent as { kind: string; vulnerabilities: unknown[] };
      expect(structured.kind).toBe('full');
      expect(structured.vulnerabilities).toHaveLength(3);
    });

    it('cves returns every entry carrying a named CVE, in document order', async () => {
      const result = await runToolContract(getAdvisoryTool, {
        advisoryId: 'ICSA-14-035-01',
        cves: ['CVE-2014-0001'],
      });
      const structured = result.structuredContent as {
        vulnerabilities: Array<{ cve: string; title?: string }>;
      };
      expect(structured.vulnerabilities.map((entry) => [entry.cve, entry.title])).toEqual([
        ['CVE-2014-0001', undefined],
        ['CVE-2014-0001', 'A second entry for the same CVE'],
      ]);
      expect(contentText(result)).toContain('### CVE-2014-0001 — A second entry for the same CVE');
    });
  });

  describe('an advisory with 585 products (the largest in the corpus)', () => {
    beforeEach(async () => {
      const branches = Array.from({ length: 585 }, (_, index) => ({
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

    it('the products re-call returns every row, with no truncation claim', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({
        advisoryId: 'ICSA-26-002-01',
        sections: ['products'],
      });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.products?.productCount).toBe(585);
      expect(result.products?.shownProducts).toBe(585);
      expect(result.products?.truncated).toBeUndefined();
      const versions = result.products?.vendors[0]?.products.flatMap((p) => p.versions) ?? [];
      expect(versions).toHaveLength(585);
      expect(versions.at(-1)).toEqual({
        kind: 'product_name',
        value: 'Product 584',
        productId: 'CSAFPID-584',
      });

      const text = firstText(getAdvisoryTool.format?.(result));
      expect(text).toContain('**Products:** 585 · **Shown:** 585');
      expect(text).toContain('**Truncated:** no');
      expect(text).toContain('`CSAFPID-584`');
      expect(text).not.toContain('request the products section alone');
    });

    it('the no-sections call still returns the outline, sizing products at every row', async () => {
      const ctx = createMockContext({ errors: getAdvisoryTool.errors });
      const input = getAdvisoryTool.input.parse({ advisoryId: 'ICSA-26-002-01' });
      const result = await getAdvisoryTool.handler(input, ctx);
      expect(result.kind).toBe('outline');
      const products = result.sections?.find((section) => section.name === 'products');
      const doc = await getCsafMirror().getAdvisory('ICSA-26-002-01');
      expect(products?.bytes).toBe(JSON.stringify(doc?.products).length);
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
