/**
 * @fileoverview Fuzz coverage for all seven tool definitions — schema-derived
 * valid and adversarial inputs, asserting no crashes, no prototype pollution,
 * and no stack-trace leaks. Every upstream boundary is faked (KEV feed, CSAF
 * archive, RSS feeds, and every Vulnrichment path under one prefix match) so
 * the run needs no live network.
 * @module tests/fuzz/tools.fuzz.test
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { fuzzTool } from '@cyanheads/mcp-ts-core/testing/fuzz';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { allToolDefinitions } from '@/mcp-server/tools/definitions/index.js';
import {
  FEED_URLS,
  initCisaFeeds,
  resetCisaFeeds,
} from '@/services/cisa-feeds/cisa-feeds-service.js';
import {
  getCsafMirror,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL } from '@/services/csaf-mirror/ingest.js';
import {
  getKevCatalog,
  initKevCatalog,
  KEV_FEED_URL,
  resetKevCatalog,
} from '@/services/kev-catalog/kev-catalog-service.js';
import { VULNRICHMENT_BASE } from '@/services/vulnrichment/paths.js';
import {
  initVulnrichment,
  resetVulnrichment,
} from '@/services/vulnrichment/vulnrichment-service.js';
import { FULL_ADVISORY } from '../fixtures/csaf-documents.js';
import { buildKevFeedBody } from '../fixtures/kev-feed.js';
import { buildAdvisoriesFeed } from '../fixtures/rss-feeds.js';
import { buildTarGzResponse } from '../fixtures/tar.js';

let dir: string;
let http: ReturnType<typeof createFetchMock>;

beforeAll(async () => {
  resetKevCatalog();
  resetCsafMirror();
  resetVulnrichment();
  resetCisaFeeds();
  dir = mkdtempSync(join(tmpdir(), 'fuzz-'));
  initKevCatalog({ refreshCron: '*/30 * * * *', timeoutMs: 5000 });
  initCsafMirror({ mirrorPath: join(dir, 'csaf.sqlite3'), timeoutMs: 5000 });
  initVulnrichment({ cacheTtlSeconds: 21_600, timeoutMs: 5000 });
  initCisaFeeds({ cacheTtlSeconds: 900, timeoutMs: 5000 });

  http = createFetchMock([
    {
      match: KEV_FEED_URL,
      respond: () =>
        new Response(buildKevFeedBody(), { headers: { 'content-type': 'application/json' } }),
    },
    {
      match: CSAF_ARCHIVE_URL,
      respond: () =>
        buildTarGzResponse([
          {
            name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json',
            data: JSON.stringify(FULL_ADVISORY),
          },
        ]),
    },
    {
      match: FEED_URLS.advisories,
      respond: () =>
        new Response(buildAdvisoriesFeed(), { headers: { 'content-type': 'application/xml' } }),
    },
    {
      match: FEED_URLS.alerts,
      respond: () =>
        new Response(buildAdvisoriesFeed(), { headers: { 'content-type': 'application/xml' } }),
    },
    {
      match: FEED_URLS.ics,
      respond: () =>
        new Response(buildAdvisoriesFeed(), { headers: { 'content-type': 'application/xml' } }),
    },
    {
      /* Every Vulnrichment path lands under one prefix — a fast, deterministic
       * 404 for whatever CVE fuzzing generates, never live network. */
      match: (request: Request) => request.url.startsWith(VULNRICHMENT_BASE),
      respond: () =>
        new Response('404: Not Found', { status: 404, headers: { 'content-type': 'text/plain' } }),
    },
  ]);
  http.install();

  /* Pre-load the KEV snapshot and seed the CSAF mirror so fuzz runs mostly
   * exercise real result-building logic instead of only the not-ready paths. */
  const ctx = createMockContext();
  await getKevCatalog().snapshot(ctx);
  await getCsafMirror().mirrorInstance.runSync({
    mode: 'init',
    signal: AbortSignal.timeout(30_000),
  });
}, 30000);

afterAll(() => {
  http.restore();
  resetKevCatalog();
  resetCsafMirror();
  resetVulnrichment();
  resetCisaFeeds();
  rmSync(dir, { recursive: true, force: true });
});

describe.each(allToolDefinitions.map((def) => [def.name, def] as const))(
  '%s fuzz',
  (_name, def) => {
    it('survives fuzzing: no crashes, no prototype pollution, no stack-trace leaks', async () => {
      const report = await fuzzTool(def, { numRuns: 40, numAdversarial: 20, timeout: 8000 });
      expect(report.crashes).toEqual([]);
      expect(report.leaks).toEqual([]);
      expect(report.prototypePollution).toBe(false);
    }, 30000);
  },
);
