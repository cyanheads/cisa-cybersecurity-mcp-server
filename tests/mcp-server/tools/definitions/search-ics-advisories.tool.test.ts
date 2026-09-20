/**
 * @fileoverview Tests for `cisa_search_ics_advisories` — mirror_not_ready,
 * invalid_cvss_range, invalid_date_range, relevance_sort_without_query, every
 * zero-hit fragment, and the sector/CVSS coverage notices, against a mirror
 * seeded through the real ingest path.
 * @module tests/mcp-server/tools/definitions/search-ics-advisories.tool.test
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFetchMock, createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { searchIcsAdvisoriesTool } from '@/mcp-server/tools/definitions/search-ics-advisories.tool.js';
import {
  getCsafMirror,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL } from '@/services/csaf-mirror/ingest.js';
import {
  FULL_ADVISORY,
  REPUBLISHED_ADVISORY,
  SPARSE_ADVISORY,
} from '../../../fixtures/csaf-documents.js';
import { buildTarGzResponse } from '../../../fixtures/tar.js';
import { firstText } from '../../../helpers/format-text.js';

async function seedMirror() {
  const http = createFetchMock([
    {
      match: CSAF_ARCHIVE_URL,
      respond: () =>
        buildTarGzResponse([
          {
            name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json',
            data: JSON.stringify(FULL_ADVISORY),
          },
          {
            name: 'CSAF-develop/csaf_files/OT/white/2014/icsa-14-035-01.json',
            data: JSON.stringify(SPARSE_ADVISORY),
          },
          {
            name: 'CSAF-develop/csaf_files/OT/white/2025/icsa-25-100-02.json',
            data: JSON.stringify(REPUBLISHED_ADVISORY),
          },
        ]),
    },
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

describe('cisa_search_ics_advisories', () => {
  let dir: string;

  beforeEach(() => {
    resetCsafMirror();
    dir = mkdtempSync(join(tmpdir(), 'search-ics-'));
    initCsafMirror({ mirrorPath: join(dir, 'csaf.sqlite3'), timeoutMs: 5000 });
  });

  afterEach(() => {
    resetCsafMirror();
    rmSync(dir, { recursive: true, force: true });
  });

  it('throws mirror_not_ready before the first sync completes', async () => {
    const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
    const input = searchIcsAdvisoriesTool.input.parse({});
    await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'mirror_not_ready' },
    });
  });

  describe('once seeded', () => {
    beforeEach(async () => {
      await seedMirror();
    }, 30000);

    it('full-text search finds the matching advisory and content[]/structuredContent match', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({
        q: 'Remote Code Execution',
        sortBy: 'relevance',
      });
      const result = await searchIcsAdvisoriesTool.handler(input, ctx);
      expect(result.results).toHaveLength(1);
      const text = firstText(searchIcsAdvisoriesTool.format?.(result));
      const advisory = result.results[0];
      expect(text).toContain(advisory?.advisoryId as string);
      expect(text).toContain(advisory?.title as string);
      expect(text).toContain(advisory?.attribution as string);
      expect(text).toContain(advisory?.url as string);
      expect(text).toContain(advisory?.csafUrl as string);
    });

    it('caps results at limit and discloses truncated/shown/cap', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ limit: 1, sortBy: 'revised' });
      const result = await searchIcsAdvisoriesTool.handler(input, ctx);
      expect(result.results).toHaveLength(1);
      expect(result.hasMore).toBe(true);
      const enrichment = getEnrichment(ctx);
      expect(enrichment.totalCount).toBe(3);
      expect(enrichment.truncated).toBe(true);
      expect(enrichment.shown).toBe(1);
      expect(enrichment.cap).toBe(1);
    });

    it('emits sectorCoverage when a sector filter is applied', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ sector: 'Energy' });
      await searchIcsAdvisoriesTool.handler(input, ctx);
      expect(getEnrichment(ctx).sectorCoverage).toContain('carry no sector note');
    });

    it('emits cvssCoverage when a score filter is applied', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ severity: 'CRITICAL' });
      await searchIcsAdvisoriesTool.handler(input, ctx);
      expect(getEnrichment(ctx).cvssCoverage).toContain('score only in CVSS v2');
    });

    it('throws invalid_cvss_range when cvssMin exceeds cvssMax', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ cvssMin: 9, cvssMax: 1 });
      await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'invalid_cvss_range' },
      });
    });

    it('throws invalid_date_range for publishedFrom after publishedTo', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({
        publishedFrom: '2026-09-10',
        publishedTo: '2026-01-01',
      });
      await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'invalid_date_range' },
      });
    });

    it('throws invalid_date_range for revisedFrom after revisedTo', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({
        revisedFrom: '2026-09-10',
        revisedTo: '2026-01-01',
      });
      await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'invalid_date_range' },
      });
    });

    it('throws relevance_sort_without_query when sortBy is relevance and q is absent', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const input = searchIcsAdvisoriesTool.input.parse({ sortBy: 'relevance' });
      await expect(searchIcsAdvisoriesTool.handler(input, ctx)).rejects.toMatchObject({
        data: { reason: 'relevance_sort_without_query' },
      });
    });

    it('a cursor walked past the end of the matches returns an empty page with hasMore: false', async () => {
      const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const page1 = await searchIcsAdvisoriesTool.handler(
        searchIcsAdvisoriesTool.input.parse({ limit: 2, sortBy: 'revised' }),
        ctx,
      );
      expect(page1.hasMore).toBe(true);
      expect(page1.cursor).toBeDefined();

      const ctx2 = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
      const page2 = await searchIcsAdvisoriesTool.handler(
        searchIcsAdvisoriesTool.input.parse({ limit: 2, sortBy: 'revised', cursor: page1.cursor }),
        ctx2,
      );
      expect(page2.results).toHaveLength(1); /* 3 total, 2 shown on page 1, 1 remains */
      expect(page2.hasMore).toBe(false);
      expect(page2.cursor).toBeUndefined();
    });

    it('rejects a limit above the 50-item schema cap', () => {
      expect(() => searchIcsAdvisoriesTool.input.parse({ limit: 51 })).toThrow();
    });

    it('rejects a malformed cve filter', () => {
      expect(() => searchIcsAdvisoriesTool.input.parse({ cve: 'not-a-cve' })).toThrow();
    });

    it('rejects a severity value outside the declared band enum', () => {
      expect(() => searchIcsAdvisoriesTool.input.parse({ severity: 'ULTRA' })).toThrow();
    });

    describe('zero-hit notice fragments', () => {
      it('vendor set: notes vendor names are unnormalized', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ vendor: 'NoSuchVendorXYZ' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('not normalized');
      });

      it('sector set: notes the 2017 coverage boundary', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ sector: 'Dams' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('Sector coverage begins in 2017');
      });

      it('series ICSMA: notes the 188-of-3,926 scope', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ series: 'ICSMA' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('ICSMA covers medical devices');
      });

      it('cve set: routes to cisa_check_cve_status', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ cve: 'CVE-2099-00001' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('cisa_check_cve_status');
      });

      it('no filter explains it: falls back to the generic miss message', async () => {
        const ctx = createMockContext({ errors: searchIcsAdvisoriesTool.errors });
        const input = searchIcsAdvisoriesTool.input.parse({ q: 'nonexistentquerytoken' });
        await searchIcsAdvisoriesTool.handler(input, ctx);
        expect(getEnrichment(ctx).notice).toContain('Relax the narrowest filter');
      });
    });
  });
});
