/**
 * @fileoverview Integration test for the CSAF mirror — seeds a real SQLite
 * index through the actual ingest path (a hand-built gzip tar archive fake
 * standing in for the GitHub codeload response), then exercises search, the
 * raw-handle junction tables, incremental refresh (changed / unchanged /
 * tombstoned), and the mirror_not_ready gate. Every mirror instance points at
 * a fresh temp-directory SQLite file, never the repo's `.mirror/csaf.sqlite3`.
 * @module tests/integration/csaf-mirror.test
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  getCsafMirror,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL, CSAF_CHANGES_URL } from '@/services/csaf-mirror/ingest.js';
import { CSAF_OT_BASE } from '@/services/csaf-mirror/normalize.js';
import {
  FULL_ADVISORY,
  REPUBLISHED_ADVISORY,
  SPARSE_ADVISORY,
} from '../fixtures/csaf-documents.js';
import { buildTarGzResponse } from '../fixtures/tar.js';

const FULL_PATH = '2026/icsa-26-260-07.json';
const SPARSE_PATH = '2014/icsa-14-035-01.json';
const REPUBLISHED_PATH = '2025/icsa-25-100-02.json';

function seedArchiveResponse(): Response {
  return buildTarGzResponse([
    { name: `CSAF-develop/csaf_files/OT/white/${FULL_PATH}`, data: JSON.stringify(FULL_ADVISORY) },
    {
      name: `CSAF-develop/csaf_files/OT/white/${SPARSE_PATH}`,
      data: JSON.stringify(SPARSE_ADVISORY),
    },
    {
      name: `CSAF-develop/csaf_files/OT/white/${REPUBLISHED_PATH}`,
      data: JSON.stringify(REPUBLISHED_ADVISORY),
    },
    /* Sidecars that must NOT be ingested. */
    { name: `CSAF-develop/csaf_files/OT/white/${FULL_PATH}.asc`, data: 'SIGNATURE' },
    { name: `CSAF-develop/csaf_files/OT/white/${FULL_PATH}.sha512`, data: 'HASH' },
    /* The manifest itself lives alongside the documents; the ingester's include
     * predicate excludes only the OT index.json, so exercise that exclusion too. */
    { name: 'CSAF-develop/csaf_files/OT/white/index.json', data: '{}' },
  ]);
}

describe('CsafMirrorService — real ingest path', () => {
  let dir: string;

  beforeEach(() => {
    resetCsafMirror();
    dir = mkdtempSync(join(tmpdir(), 'csaf-mirror-'));
    initCsafMirror({ mirrorPath: join(dir, 'csaf.sqlite3'), timeoutMs: 5000 });
  });

  afterEach(() => {
    resetCsafMirror();
    rmSync(dir, { recursive: true, force: true });
  });

  it('seeds 3 advisories from the archive, excluding sidecars and the OT index.json', async () => {
    const http = createFetchMock([
      { match: CSAF_ARCHIVE_URL, respond: () => seedArchiveResponse() },
    ]);
    http.install();
    try {
      const mirror = getCsafMirror();
      await mirror.mirrorInstance.runSync({ mode: 'init', signal: AbortSignal.timeout(30_000) });
      expect(await mirror.ready()).toBe(true);
      const state = await mirror.state();
      expect(state.documentCount).toBe(3);
      expect(state.syncStatus).toBe('complete');
    } finally {
      http.restore();
    }
  }, 30000);

  describe('after a completed init', () => {
    beforeEach(async () => {
      const http = createFetchMock([
        { match: CSAF_ARCHIVE_URL, respond: () => seedArchiveResponse() },
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
    }, 30000);

    it('full-text search matches the advisory title via FTS5', async () => {
      const ctx = createMockContext();
      const page = await getCsafMirror().search(
        {
          q: 'Remote Code Execution',
          sortBy: 'relevance',
          order: 'desc',
          limit: 20,
          offset: 0,
        },
        ctx,
      );
      expect(page.total).toBe(1);
      expect(page.items[0]?.advisoryId).toBe('ICSA-26-260-07');
    });

    it('cve filter matches exact membership via the junction table', async () => {
      const ctx = createMockContext();
      const page = await getCsafMirror().search(
        { cve: 'CVE-2026-12345', sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
        ctx,
      );
      expect(page.items.map((item) => item.advisoryId)).toEqual(['ICSA-26-260-07']);
    });

    it('sector filter matches exact membership, one advisory per queried sector', async () => {
      const ctx = createMockContext();
      const energy = await getCsafMirror().search(
        { sector: 'Energy', sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
        ctx,
      );
      expect(energy.items.map((item) => item.advisoryId)).toEqual(['ICSA-26-260-07']);

      const manufacturing = await getCsafMirror().search(
        {
          sector: 'Critical Manufacturing',
          sortBy: 'revised',
          order: 'desc',
          limit: 20,
          offset: 0,
        },
        ctx,
      );
      expect(manufacturing.items.map((item) => item.advisoryId)).toEqual(['ICSA-25-100-02']);
    });

    it('severity and CVSS range filters read the computed maxCvss column', async () => {
      const ctx = createMockContext();
      const critical = await getCsafMirror().search(
        { severity: 'CRITICAL', sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
        ctx,
      );
      expect(critical.items.map((item) => item.advisoryId)).toEqual(['ICSA-26-260-07']);

      const highBand = await getCsafMirror().search(
        { cvssMin: 7.0, cvssMax: 8.0, sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
        ctx,
      );
      /* SPARSE_ADVISORY's max is a derived-band v2 score of 7.8. */
      expect(highBand.items.map((item) => item.advisoryId)).toEqual(['ICSA-14-035-01']);
      expect(highBand.items[0]?.maxCvss?.severityDerived).toBe(true);
    });

    it('publisher filter separates coordinator from republished advisories', async () => {
      const ctx = createMockContext();
      const other = await getCsafMirror().search(
        { publisher: 'other', sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
        ctx,
      );
      expect(other.items.map((item) => item.advisoryId)).toEqual(['ICSA-25-100-02']);
    });

    it('getAdvisory returns the full normalized document by ID', async () => {
      const doc = await getCsafMirror().getAdvisory('ICSA-26-260-07');
      expect(doc?.advisory.title).toBe('Acme Widgets PLC Remote Code Execution');
      expect(doc?.vulnerabilities[0]?.cve).toBe('CVE-2026-12345');
    });

    it('getAdvisory returns undefined for an ID not in the index', async () => {
      expect(await getCsafMirror().getAdvisory('ICSA-99-999-99')).toBeUndefined();
    });

    it('recentlyRevised returns advisories newest-first, capped at the limit', async () => {
      const recent = await getCsafMirror().recentlyRevised(2);
      expect(recent).toHaveLength(2);
      expect(recent[0]?.advisoryId).toBe('ICSA-26-260-07');
    });

    it('completeAdvisoryIds matches by prefix', async () => {
      const matches = await getCsafMirror().completeAdvisoryIds('ICSA-26', 10);
      expect(matches).toEqual(['ICSA-26-260-07']);
    });

    it('coverageCounts reports noSector, v2Only, and noCvss against the whole corpus', async () => {
      const coverage = await getCsafMirror().coverageCounts();
      expect(coverage.total).toBe(3);
      expect(coverage.noSector).toBe(1); /* SPARSE_ADVISORY carries no sector note. */
      expect(coverage.v2Only).toBe(1); /* SPARSE_ADVISORY's max score is CVSS v2. */
      expect(coverage.noCvss).toBe(1); /* REPUBLISHED_ADVISORY carries no CVSS at all. */
    });

    describe('refresh', () => {
      it('fetches only the changed document, leaves the unchanged one alone, and tombstones the dropped one', async () => {
        const updatedFull = {
          ...FULL_ADVISORY,
          document: {
            ...FULL_ADVISORY.document,
            tracking: {
              ...FULL_ADVISORY.document.tracking,
              current_release_date: '2026-09-19T00:00:00.000000Z',
              version: '1.2',
            },
          },
        };

        const manifest = [
          `"${FULL_PATH}","2026-09-19T00:00:00.000000Z"`,
          `"${SPARSE_PATH}","2014-02-04T00:00:00.000000Z"`,
          /* REPUBLISHED_PATH intentionally omitted — manifest no longer lists it. */
        ].join('\n');

        const http = createFetchMock([
          {
            match: CSAF_CHANGES_URL,
            respond: new Response(manifest, {
              status: 200,
              headers: { etag: '"v2"', 'content-type': 'text/csv' },
            }),
          },
          {
            match: `${CSAF_OT_BASE}/${FULL_PATH}`,
            respond: Response.json(updatedFull, {
              headers: { 'content-type': 'application/json' },
            }),
          },
        ]);
        http.install();
        try {
          await getCsafMirror().mirrorInstance.runSync({
            mode: 'refresh',
            signal: AbortSignal.timeout(30_000),
          });
        } finally {
          http.restore();
        }

        const updated = await getCsafMirror().getAdvisory('ICSA-26-260-07');
        expect(updated?.advisory.revision).toBe('1.2');

        const dropped = await getCsafMirror().getAdvisory('ICSA-25-100-02');
        expect(dropped).toBeUndefined();

        const state = await getCsafMirror().state();
        expect(state.documentCount).toBe(2);

        const ctx = createMockContext();
        const manufacturing = await getCsafMirror().search(
          {
            sector: 'Critical Manufacturing',
            sortBy: 'revised',
            order: 'desc',
            limit: 20,
            offset: 0,
          },
          ctx,
        );
        expect(manufacturing.items).toEqual([]);
      }, 30000);

      it('a 304 on the manifest leaves the index untouched', async () => {
        const http = createFetchMock([
          { match: CSAF_CHANGES_URL, respond: new Response(null, { status: 304 }) },
        ]);
        http.install();
        try {
          await getCsafMirror().mirrorInstance.runSync({
            mode: 'refresh',
            signal: AbortSignal.timeout(30_000),
          });
        } finally {
          http.restore();
        }
        const state = await getCsafMirror().state();
        expect(state.documentCount).toBe(3);
      });

      it('refuses to tombstone the whole index when the manifest parses to zero rows', async () => {
        const http = createFetchMock([
          {
            match: CSAF_CHANGES_URL,
            respond: new Response('', { status: 200, headers: { etag: '"empty"' } }),
          },
        ]);
        http.install();
        try {
          await expect(
            getCsafMirror().mirrorInstance.runSync({
              mode: 'refresh',
              signal: AbortSignal.timeout(30_000),
            }),
          ).rejects.toThrow(/refusing to tombstone/);
        } finally {
          http.restore();
        }
        const state = await getCsafMirror().state();
        expect(state.documentCount).toBe(3);
      });
    });
  });

  it('a never-seeded mirror reports ready: false and getAdvisory serves nothing', async () => {
    const mirror = getCsafMirror();
    expect(await mirror.ready()).toBe(false);
    const state = await mirror.state();
    expect(state.ready).toBe(false);
    expect(state.documentCount).toBeNull();
  });
});
