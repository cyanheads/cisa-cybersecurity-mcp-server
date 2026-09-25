/**
 * @fileoverview Integration test for the CSAF mirror — seeds a real SQLite
 * index through the actual ingest path (a hand-built gzip tar archive fake
 * standing in for the GitHub codeload response), then exercises search — the
 * literal LIKE and empty-`q` handling, the cwe filter, and KEV membership
 * (`inKev` paging, full-membership `kevCves`) — the raw-handle junction tables,
 * incremental refresh (changed / unchanged / tombstoned), the ingest-content
 * version, and the mirror_not_ready gate. Every mirror instance points at
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
import {
  CSAF_ARCHIVE_URL,
  CSAF_CHANGES_URL,
  INGEST_CONTENT_VERSION,
} from '@/services/csaf-mirror/ingest.js';
import { CSAF_OT_BASE } from '@/services/csaf-mirror/normalize.js';
import {
  buildOversizedAdvisory,
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

    it('vendor, product, and q keep matching the result sets they match today', async () => {
      const ids = async (filters: Record<string, unknown>) =>
        (
          await getCsafMirror().search(
            { ...filters, sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
            createMockContext(),
          )
        ).items.map((item) => item.advisoryId);

      expect(await ids({ vendor: 'acme' })).toEqual(['ICSA-26-260-07']);
      expect(await ids({ vendor: 'CORP' })).toEqual(['ICSA-14-035-01']);
      expect(await ids({ vendor: 'e' })).toEqual(['ICSA-26-260-07', 'ICSA-14-035-01']);
      expect(await ids({ product: 'x200' })).toEqual(['ICSA-26-260-07']);
      expect(await ids({ product: 'HMI-9000' })).toEqual(['ICSA-14-035-01']);
      expect(await ids({ q: 'Widget Controller' })).toEqual(['ICSA-26-260-07']);
      expect(await ids({ q: 'hmi-9000' })).toEqual(['ICSA-14-035-01']);
    });

    it('a search result lists at most the first twenty CVEs, alphabetically', async () => {
      const page = await getCsafMirror().search(
        { cve: 'CVE-2026-12345', sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
        createMockContext(),
      );
      expect(page.items[0]?.cves).toEqual(['CVE-2026-12345']);
      expect(page.items[0]?.cveCount).toBe(1);
      expect(Object.keys(page.items[0] ?? {}).sort()).toEqual(
        [
          'advisoryId',
          'attribution',
          'csafUrl',
          'cveCount',
          'cves',
          'maxCvss',
          'productCount',
          'published',
          'publisherCategory',
          'revised',
          'revision',
          'sectors',
          'sectorsRaw',
          'series',
          'title',
          'url',
          'vendorCount',
          'vendors',
        ].sort(),
      );
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

  describe('advisory_cwes junction and the cwe filter', () => {
    /* REPUBLISHED_ADVISORY carries no CWE; this variant carries two, one repeated. */
    const republishedWithCwes = {
      ...REPUBLISHED_ADVISORY,
      vulnerabilities: [
        {
          ...REPUBLISHED_ADVISORY.vulnerabilities[0],
          cwe: { id: 'CWE-787', name: 'Out-of-bounds Write' },
        },
        {
          ...REPUBLISHED_ADVISORY.vulnerabilities[0],
          cve: 'CVE-2025-5556',
          cwe: { id: 'CWE-20', name: 'Improper Input Validation' },
        },
        {
          ...REPUBLISHED_ADVISORY.vulnerabilities[0],
          cve: 'CVE-2025-5557',
          cwe: { id: 'CWE-787', name: 'Out-of-bounds Write' },
        },
      ],
    };

    const cweRows = async (): Promise<Array<{ advisoryId: string; cweId: string }>> => {
      const handle = await getCsafMirror().mirrorInstance.raw();
      return handle
        .prepare<{ advisoryId: string; cweId: string }>(
          'SELECT advisoryId, cweId FROM advisory_cwes ORDER BY advisoryId, cweId',
        )
        .all();
    };

    const searchCwe = (cwe: string, extra: Record<string, unknown> = {}) =>
      getCsafMirror().search(
        { cwe, ...extra, sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
        createMockContext(),
      );

    beforeEach(async () => {
      const http = createFetchMock([
        {
          match: CSAF_ARCHIVE_URL,
          respond: () =>
            buildTarGzResponse([
              {
                name: `CSAF-develop/csaf_files/OT/white/${FULL_PATH}`,
                data: JSON.stringify(FULL_ADVISORY),
              },
              {
                name: `CSAF-develop/csaf_files/OT/white/${SPARSE_PATH}`,
                data: JSON.stringify(SPARSE_ADVISORY),
              },
              {
                name: `CSAF-develop/csaf_files/OT/white/${REPUBLISHED_PATH}`,
                data: JSON.stringify(republishedWithCwes),
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
    }, 30000);

    it('writes one distinct row per advisory and CWE at ingest', async () => {
      expect(await cweRows()).toEqual([
        { advisoryId: 'ICSA-25-100-02', cweId: 'CWE-20' },
        { advisoryId: 'ICSA-25-100-02', cweId: 'CWE-787' },
        { advisoryId: 'ICSA-26-260-07', cweId: 'CWE-20' },
      ]);
    });

    it('matches exact CWE membership in canonical form and AND-combines with other filters', async () => {
      /* Case and whitespace are normalized by the tool's input schema, upstream of here. */
      expect((await searchCwe('CWE-20')).items.map((item) => item.advisoryId)).toEqual([
        'ICSA-26-260-07',
        'ICSA-25-100-02',
      ]);
      expect((await searchCwe('CWE-787')).items.map((item) => item.advisoryId)).toEqual([
        'ICSA-25-100-02',
      ]);
      const anded = await searchCwe('CWE-20', { publisher: 'coordinator' });
      expect(anded.items.map((item) => item.advisoryId)).toEqual(['ICSA-26-260-07']);
      expect((await searchCwe('CWE-787', { publisher: 'coordinator' })).total).toBe(0);
    });

    it('returns an empty page for a CWE no advisory carries, and for an offset past the end', async () => {
      expect(await searchCwe('CWE-99999')).toEqual({ total: 0, items: [] });
      const past = await getCsafMirror().search(
        { cwe: 'CWE-20', sortBy: 'revised', order: 'desc', limit: 20, offset: 5 },
        createMockContext(),
      );
      expect(past).toEqual({ total: 2, items: [] });
    });

    it('a refresh replaces a changed advisory’s CWE rows and a tombstone removes them', async () => {
      const retagged = {
        ...FULL_ADVISORY,
        document: {
          ...FULL_ADVISORY.document,
          tracking: {
            ...FULL_ADVISORY.document.tracking,
            current_release_date: '2026-09-19T00:00:00.000000Z',
          },
        },
        vulnerabilities: [
          {
            ...FULL_ADVISORY.vulnerabilities[0],
            cwe: { id: 'CWE-125', name: 'Out-of-bounds Read' },
          },
        ],
      };
      const manifest = [
        `"${FULL_PATH}","2026-09-19T00:00:00.000000Z"`,
        `"${SPARSE_PATH}","2014-02-04T00:00:00.000000Z"`,
      ].join('\n');
      const http = createFetchMock([
        {
          match: CSAF_CHANGES_URL,
          respond: new Response(manifest, { status: 200, headers: { etag: '"v3"' } }),
        },
        {
          match: `${CSAF_OT_BASE}/${FULL_PATH}`,
          respond: Response.json(retagged, { headers: { 'content-type': 'application/json' } }),
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
      expect(await cweRows()).toEqual([{ advisoryId: 'ICSA-26-260-07', cweId: 'CWE-125' }]);
      expect((await searchCwe('CWE-20')).total).toBe(0);
    }, 30000);
  });

  describe('text filters match what the caller typed', () => {
    /** FULL_ADVISORY under a different ID, path, and vendor label. */
    const withVendor = (advisoryId: string, vendor: string) => ({
      ...FULL_ADVISORY,
      document: {
        ...FULL_ADVISORY.document,
        tracking: { ...FULL_ADVISORY.document.tracking, id: advisoryId },
      },
      product_tree: {
        branches: [{ ...FULL_ADVISORY.product_tree.branches[0], name: vendor }],
      },
    });

    const ids = async (filters: Record<string, unknown>) =>
      (
        await getCsafMirror().search(
          { ...filters, sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
          createMockContext(),
        )
      ).items
        .map((item) => item.advisoryId)
        .sort();

    beforeEach(async () => {
      const http = createFetchMock([
        {
          match: CSAF_ARCHIVE_URL,
          respond: () =>
            buildTarGzResponse(
              [
                ['ICSA-25-345-10', 'OpenPLC_V3'],
                ['ICSA-25-345-11', 'OpenPLCxV3'],
                ['ICSA-25-345-12', 'Siemens'],
                ['ICSA-25-345-13', 'Sensus 100% Metering'],
              ].map(([id, vendor]) => ({
                name: `CSAF-develop/csaf_files/OT/white/2025/${(id as string).toLowerCase()}.json`,
                data: JSON.stringify(withVendor(id as string, vendor as string)),
              })),
            ),
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
    }, 30000);

    it('an underscore in vendor matches only a literal underscore', async () => {
      expect(await ids({ vendor: 'OpenPLC_V3' })).toEqual(['ICSA-25-345-10']);
      expect(await ids({ vendor: 'Siem_ns' })).toEqual([]);
      expect(await ids({ vendor: 'openplc' })).toEqual(['ICSA-25-345-10', 'ICSA-25-345-11']);
    });

    it('a percent sign in vendor matches only a literal percent sign', async () => {
      expect(await ids({ vendor: 'S%s' })).toEqual([]);
      expect(await ids({ vendor: '100% m' })).toEqual(['ICSA-25-345-13']);
    });

    it('a backslash in vendor or product is a literal character, not an escape', async () => {
      expect(await ids({ vendor: 'OpenPLC\\_V3' })).toEqual([]);
      expect(await ids({ product: 'Controller\\%' })).toEqual([]);
    });

    it('an underscore or percent sign in product matches literally', async () => {
      expect(await ids({ product: 'Widget_Controller' })).toEqual([]);
      expect(await ids({ product: 'W%X200' })).toEqual([]);
      expect(await ids({ product: 'widget controller' })).toHaveLength(4);
    });

    it('a q with no searchable token throws empty_search_text instead of returning everything', async () => {
      for (const q of ['   ', '""', '-- !!']) {
        await expect(ids({ q })).rejects.toMatchObject({
          data: { reason: 'empty_search_text' },
        });
      }
    });

    it('an unsearchable token inside q is dropped rather than zeroing the match', async () => {
      expect(await ids({ q: 'OpenPLC_V3 --' })).toEqual(['ICSA-25-345-10']);
    });

    it('completeAdvisoryIds treats an underscore in the prefix literally', async () => {
      expect(await getCsafMirror().completeAdvisoryIds('ICSA_25', 10)).toEqual([]);
      expect(await getCsafMirror().completeAdvisoryIds('icsa-25-345-1', 10)).toHaveLength(4);
    });
  });

  describe('KEV membership: the inKev filter and per-result kevCves', () => {
    const BIG_PATH = '2026/icsa-26-001-01.json';
    /* The oversized fixture covers CVE-2026-10000 … CVE-2026-10039; 10035 sorts
     * 36th, past the twenty-CVE preview. CVE-2099-00001 is in no advisory. */
    const KEV = new Set(['CVE-2026-10035', 'CVE-2026-12345', 'CVE-2099-00001']);

    /** `kev: null` searches with no KEV set at all. */
    const page = (
      filters: Record<string, unknown>,
      kev: ReadonlySet<string> | null = KEV,
      window: { limit?: number; offset?: number } = {},
    ) =>
      getCsafMirror().search(
        {
          ...filters,
          sortBy: 'revised',
          order: 'desc',
          limit: window.limit ?? 20,
          offset: window.offset ?? 0,
        },
        createMockContext(),
        kev ?? undefined,
      );

    beforeEach(async () => {
      const http = createFetchMock([
        {
          match: CSAF_ARCHIVE_URL,
          respond: () =>
            buildTarGzResponse([
              {
                name: `CSAF-develop/csaf_files/OT/white/${FULL_PATH}`,
                data: JSON.stringify(FULL_ADVISORY),
              },
              {
                name: `CSAF-develop/csaf_files/OT/white/${SPARSE_PATH}`,
                data: JSON.stringify(SPARSE_ADVISORY),
              },
              {
                name: `CSAF-develop/csaf_files/OT/white/${REPUBLISHED_PATH}`,
                data: JSON.stringify(REPUBLISHED_ADVISORY),
              },
              {
                name: `CSAF-develop/csaf_files/OT/white/${BIG_PATH}`,
                data: JSON.stringify(buildOversizedAdvisory('ICSA-26-001-01')),
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
    }, 30000);

    it('inKev: true keeps advisories covering any KEV CVE, false keeps the rest', async () => {
      const inKev = await page({ inKev: true });
      expect(inKev.total).toBe(2);
      expect(inKev.items.map((item) => item.advisoryId)).toEqual([
        'ICSA-26-260-07',
        'ICSA-26-001-01',
      ]);
      const notInKev = await page({ inKev: false });
      expect(notInKev.total).toBe(2);
      expect(notInKev.items.map((item) => item.advisoryId)).toEqual([
        'ICSA-25-100-02',
        'ICSA-14-035-01',
      ]);
    });

    it('inKev is evaluated before paging: the total holds on every page and the pages partition it', async () => {
      const seen: string[] = [];
      for (const offset of [0, 1]) {
        const one = await page({ inKev: true }, KEV, { limit: 1, offset });
        expect(one.total).toBe(2);
        expect(one.items).toHaveLength(1);
        seen.push(one.items[0]?.advisoryId as string);
      }
      expect(seen).toEqual(['ICSA-26-260-07', 'ICSA-26-001-01']);
      expect(await page({ inKev: true }, KEV, { limit: 1, offset: 2 })).toEqual({
        total: 2,
        items: [],
      });
    });

    it('inKev AND-combines with the other filters', async () => {
      expect((await page({ inKev: true, cve: 'CVE-2026-12345' })).total).toBe(1);
      expect((await page({ inKev: false, cve: 'CVE-2026-12345' })).total).toBe(0);
      expect((await page({ inKev: true, publisher: 'other' })).total).toBe(0);
      expect((await page({ inKev: true, vendor: 'BigVendor' })).total).toBe(1);
    });

    it('kevCves reads full membership: a KEV CVE past the twenty-CVE preview is still reported', async () => {
      const [big] = (await page({ cve: 'CVE-2026-10035' })).items;
      expect(big?.cveCount).toBe(40);
      expect(big?.cves).toHaveLength(20);
      expect(big?.cves).not.toContain('CVE-2026-10035');
      expect(big?.cves.at(-1)).toBe('CVE-2026-10019');
      expect(big?.kevCves).toEqual(['CVE-2026-10035']);
    });

    it('kevCves is [] for an advisory covering no KEV CVE, and absent when no KEV set is given', async () => {
      const withKev = await page({});
      const byId = new Map(withKev.items.map((item) => [item.advisoryId, item.kevCves]));
      expect(Object.fromEntries(byId)).toEqual({
        'ICSA-26-260-07': ['CVE-2026-12345'],
        'ICSA-26-001-01': ['CVE-2026-10035'],
        'ICSA-25-100-02': [],
        'ICSA-14-035-01': [],
      });
      const withoutKev = await page({}, null);
      expect(withoutKev.total).toBe(4);
      for (const item of withoutKev.items) expect(item).not.toHaveProperty('kevCves');
    });

    it('an empty KEV set matches nothing under inKev: true and everything under inKev: false', async () => {
      const none = new Set<string>();
      expect((await page({ inKev: true }, none)).total).toBe(0);
      expect((await page({ inKev: false }, none)).total).toBe(4);
    });

    it('inKev without a KEV set is a programmer error, not an empty page', async () => {
      await expect(page({ inKev: true }, null)).rejects.toThrow(/KEV CVE set/);
    });
  });

  describe('store migration', () => {
    it('adds advisory_cwes to an index built at store version 1', async () => {
      const path = join(dir, 'upgrade.sqlite3');
      resetCsafMirror();
      initCsafMirror({ mirrorPath: path, timeoutMs: 5000 });
      /* Reproduce a version-1 database: the same declarative shape and auxiliary
       * tables, minus advisory_cwes, stamped at version 1. */
      const legacy = await getCsafMirror().mirrorInstance.raw();
      legacy.exec('DROP TABLE IF EXISTS advisory_cwes; DELETE FROM schema_version;');
      legacy.prepare('INSERT INTO schema_version(version, applied_at) VALUES (1, ?)').run('x');
      await getCsafMirror().mirrorInstance.close();

      resetCsafMirror();
      initCsafMirror({ mirrorPath: path, timeoutMs: 5000 });
      const handle = await getCsafMirror().mirrorInstance.raw();
      const objects = handle
        .prepare<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE name IN ('advisory_cwes', 'advisory_cwes_cwe_idx') ORDER BY name",
        )
        .all();
      expect(objects.map((object) => object.name)).toEqual([
        'advisory_cwes',
        'advisory_cwes_cwe_idx',
      ]);
      const version = handle
        .prepare<{ version: number }>('SELECT MAX(version) AS version FROM schema_version')
        .get();
      expect(version?.version).toBe(2);
    });
  });

  describe('ingest-content version', () => {
    const archiveRoute = (respond?: () => Promise<Response> | Response) => ({
      match: CSAF_ARCHIVE_URL,
      respond: respond ?? (() => seedArchiveResponse()),
    });

    /** Seed, then rewind the index to what an older build would have left behind. */
    async function seedAsOlderBuild(): Promise<void> {
      const http = createFetchMock([archiveRoute()]);
      http.install();
      try {
        await getCsafMirror().mirrorInstance.runSync({
          mode: 'init',
          signal: AbortSignal.timeout(30_000),
        });
      } finally {
        http.restore();
      }
      const handle = await getCsafMirror().mirrorInstance.raw();
      handle.exec(
        "DELETE FROM mirror_meta WHERE key = 'ingest_content_version'; DELETE FROM advisory_cwes;",
      );
    }

    it('a completed init records the current content version', async () => {
      const http = createFetchMock([archiveRoute()]);
      http.install();
      try {
        await getCsafMirror().autoInit();
      } finally {
        http.restore();
      }
      expect(await getCsafMirror().contentState()).toEqual({
        current: INGEST_CONTENT_VERSION,
        stored: INGEST_CONTENT_VERSION,
        stale: false,
      });
    }, 30000);

    it('an index with no recorded version is stale, and autoInit re-ingests it in place without a readiness gap', async () => {
      await seedAsOlderBuild();
      expect(await getCsafMirror().contentState()).toEqual({
        current: INGEST_CONTENT_VERSION,
        stored: null,
        stale: true,
      });

      const during: Array<{ ready: boolean; total: number; stale: boolean; status: string }> = [];
      const http = createFetchMock([
        archiveRoute(async () => {
          /* The runner has already marked the run in progress by the time it fetches. */
          const mirror = getCsafMirror();
          const page = await mirror.search(
            { sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
            createMockContext(),
          );
          during.push({
            ready: await mirror.ready(),
            total: page.total,
            stale: (await mirror.contentState()).stale,
            status: (await mirror.state()).syncStatus,
          });
          return seedArchiveResponse();
        }),
      ]);
      http.install();
      try {
        await getCsafMirror().autoInit();
      } finally {
        http.restore();
      }

      expect(during).toEqual([{ ready: true, total: 3, stale: true, status: 'in_progress' }]);
      expect(await getCsafMirror().contentState()).toMatchObject({
        stored: INGEST_CONTENT_VERSION,
        stale: false,
      });
      const cwe = await getCsafMirror().search(
        { cwe: 'CWE-20', sortBy: 'revised', order: 'desc', limit: 20, offset: 0 },
        createMockContext(),
      );
      expect(cwe.items.map((item) => item.advisoryId)).toEqual(['ICSA-26-260-07']);
      expect((await getCsafMirror().state()).documentCount).toBe(3);
    }, 30000);

    it('a failed re-ingest keeps serving the existing rows and leaves the version stale for the next boot', async () => {
      await seedAsOlderBuild();
      const failing = createFetchMock([
        archiveRoute(() => new Response('unavailable', { status: 404 })),
      ]);
      failing.install();
      try {
        await expect(getCsafMirror().autoInit()).rejects.toThrow();
      } finally {
        failing.restore();
      }
      expect(await getCsafMirror().ready()).toBe(true);
      expect((await getCsafMirror().state()).documentCount).toBe(3);
      expect((await getCsafMirror().contentState()).stale).toBe(true);

      const retry = createFetchMock([archiveRoute()]);
      retry.install();
      try {
        await getCsafMirror().autoInit();
      } finally {
        retry.restore();
      }
      expect((await getCsafMirror().contentState()).stale).toBe(false);
    }, 60000);

    it('an archive that yields no OT documents, or is cut off mid-stream, leaves the version stale', async () => {
      await seedAsOlderBuild();
      const full = new Uint8Array(await seedArchiveResponse().arrayBuffer());
      const bodies: Array<() => Response> = [
        () =>
          buildTarGzResponse([
            { name: 'CSAF-develop/csaf_files/IT/white/2026/x.json', data: '{}' },
          ]),
        () => new Response(full.subarray(0, full.length - 64)),
      ];
      for (const body of bodies) {
        const http = createFetchMock([archiveRoute(body)]);
        http.install();
        try {
          await expect(getCsafMirror().autoInit()).rejects.toThrow();
        } finally {
          http.restore();
        }
        expect((await getCsafMirror().contentState()).stale).toBe(true);
        expect(await getCsafMirror().ready()).toBe(true);
      }
    }, 60000);

    it('an incremental refresh on a stale index does not record the version', async () => {
      await seedAsOlderBuild();
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
      expect((await getCsafMirror().contentState()).stale).toBe(true);
    }, 30000);

    it('autoInit on a current index makes no upstream request', async () => {
      const seed = createFetchMock([archiveRoute()]);
      seed.install();
      try {
        await getCsafMirror().autoInit();
      } finally {
        seed.restore();
      }
      const idle = createFetchMock([archiveRoute()]);
      idle.install();
      try {
        await getCsafMirror().autoInit();
      } finally {
        idle.restore();
      }
      expect(idle.calls).toHaveLength(0);
    }, 30000);
  });

  it('a never-seeded mirror reports ready: false and getAdvisory serves nothing', async () => {
    const mirror = getCsafMirror();
    expect(await mirror.ready()).toBe(false);
    const state = await mirror.state();
    expect(state.ready).toBe(false);
    expect(state.documentCount).toBeNull();
  });
});
