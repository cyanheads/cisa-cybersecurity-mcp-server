/**
 * @fileoverview Tests for `cisa_list_reference` — every topic, plus the
 * `sources` topic reading live in-process state (cold and warm) with no
 * network call.
 * @module tests/mcp-server/tools/definitions/list-reference.tool.test
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { listReferenceTool } from '@/mcp-server/tools/definitions/list-reference.tool.js';
import { REFERENCE_TOPICS } from '@/reference/tables.js';
import {
  getCisaFeeds,
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
import {
  getVulnrichment,
  initVulnrichment,
  resetVulnrichment,
} from '@/services/vulnrichment/vulnrichment-service.js';
import { FULL_ADVISORY } from '../../../fixtures/csaf-documents.js';
import { buildKevFeedBody } from '../../../fixtures/kev-feed.js';
import { buildTarGzResponse } from '../../../fixtures/tar.js';
import { DRIFTING_CATALOG_COUNT } from '../../../helpers/catalog-counts.js';
import { firstText } from '../../../helpers/format-text.js';

describe('cisa_list_reference', () => {
  let dir: string;

  beforeEach(() => {
    resetKevCatalog();
    resetCsafMirror();
    resetVulnrichment();
    resetCisaFeeds();
    dir = mkdtempSync(join(tmpdir(), 'list-reference-'));
    initKevCatalog({ refreshCron: '*/30 * * * *', timeoutMs: 5000 });
    initCsafMirror({ mirrorPath: join(dir, 'csaf.sqlite3'), timeoutMs: 5000 });
    initVulnrichment({ cacheTtlSeconds: 21_600, timeoutMs: 5000 });
    initCisaFeeds({ cacheTtlSeconds: 900, timeoutMs: 5000 });
  });

  afterEach(() => {
    resetKevCatalog();
    resetCsafMirror();
    resetVulnrichment();
    resetCisaFeeds();
    rmSync(dir, { recursive: true, force: true });
  });

  it('every non-sources topic returns entries and renders as markdown', async () => {
    const ctx = createMockContext();
    for (const topic of REFERENCE_TOPICS) {
      if (topic === 'sources') continue;
      const input = listReferenceTool.input.parse({ topic });
      const result = await listReferenceTool.handler(input, ctx);
      expect(result.topic).toBe(topic);
      expect(result.entries.length).toBeGreaterThan(0);
      const blocks = listReferenceTool.format?.(result) ?? [];
      const text = (blocks[0] as { text: string }).text;
      expect(text).toContain(result.title);
      for (const entry of result.entries) {
        expect(text).toContain(entry.label);
      }
    }
  });

  it('topic kev_fields states no KEV catalog count that drifts with each release', async () => {
    const ctx = createMockContext();
    const result = await listReferenceTool.handler(
      listReferenceTool.input.parse({ topic: 'kev_fields' }),
      ctx,
    );
    const text = firstText(listReferenceTool.format?.(result));
    expect(text).toContain('forensic-triage tier');
    expect(text).not.toMatch(DRIFTING_CATALOG_COUNT);
    expect(JSON.stringify(result)).not.toMatch(DRIFTING_CATALOG_COUNT);
  });

  it.each([
    ['sectors', 'Coverage begins in 2017'],
    ['advisory_id_formats', 'Revision suffix'],
    ['severity_bands', 'How maxCvss is computed'],
  ])(
    'topic %s states no advisory-corpus count that drifts with each index refresh',
    async (topic, anchor) => {
      const result = await listReferenceTool.handler(
        listReferenceTool.input.parse({ topic }),
        createMockContext(),
      );
      const text = firstText(listReferenceTool.format?.(result));
      expect(text).toContain(anchor);
      expect(text).not.toMatch(DRIFTING_CATALOG_COUNT);
      expect(JSON.stringify(result)).not.toMatch(DRIFTING_CATALOG_COUNT);
    },
  );

  it('topic directives returns the full 16-row Table 1, definitions, and supersedes', async () => {
    const ctx = createMockContext();
    const input = listReferenceTool.input.parse({ topic: 'directives' });
    const result = await listReferenceTool.handler(input, ctx);
    expect(result.timelineTable).toHaveLength(16);
    expect(result.definitions?.length).toBeGreaterThan(0);
    expect(result.supersedes).toEqual([
      expect.objectContaining({ directive: 'BOD 22-01' }),
      expect.objectContaining({ directive: 'BOD 19-02' }),
    ]);

    const text = firstText(listReferenceTool.format?.(result));
    expect(text).toContain('BOD 26-04 Appendix A, Table 1');
    expect(text).toContain('Fix on system upgrade');
    expect(text).toContain('Supersedes');
  });

  it('topic sources reports a cold state: KEV not loaded, mirror not ready, no cached feeds', async () => {
    const ctx = createMockContext();
    const input = listReferenceTool.input.parse({ topic: 'sources' });
    const result = await listReferenceTool.handler(input, ctx);
    expect(result.sources?.kev.catalogVersion).toBeNull();
    expect(result.sources?.kev.count).toBeNull();
    expect(result.sources?.csafMirror.ready).toBe(false);
    expect(result.sources?.csafMirror.documentCount).toBeNull();
    expect(result.sources?.vulnrichment.mode).toBe('on_demand');
    expect(result.sources?.feeds.cached).toEqual([]);

    const text = firstText(listReferenceTool.format?.(result));
    expect(text).toContain('not loaded');
    expect(text).toContain('ready: no');
    expect(text).toContain('No feed window is cached yet.');
  });

  it('topic sources reports a warm state once every tier has loaded', async () => {
    const httpKev = createFetchMock([
      {
        match: KEV_FEED_URL,
        respond: new Response(buildKevFeedBody(), {
          headers: { 'content-type': 'application/json' },
        }),
      },
    ]);
    httpKev.install();
    try {
      await getKevCatalog().snapshot(createMockContext());
    } finally {
      httpKev.restore();
    }

    const httpMirror = createFetchMock([
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
    ]);
    httpMirror.install();
    try {
      await getCsafMirror().mirrorInstance.runSync({
        mode: 'init',
        signal: AbortSignal.timeout(30_000),
      });
    } finally {
      httpMirror.restore();
    }

    const ctx = createMockContext();
    const input = listReferenceTool.input.parse({ topic: 'sources' });
    const result = await listReferenceTool.handler(input, ctx);
    expect(result.sources?.kev.catalogVersion).toBe('2026.09.18');
    expect(result.sources?.kev.count).toBe(5);
    expect(result.sources?.csafMirror.ready).toBe(true);
    expect(result.sources?.csafMirror.documentCount).toBe(1);

    /* getVulnrichment / getCisaFeeds are read via their in-process state() only —
     * this asserts the tool actually calls them without throwing. */
    expect(getVulnrichment().state().mode).toBe('on_demand');
    expect(getCisaFeeds().state().windowItems).toBe(30);

    /* The ready-index arm keeps exactly these fields and this rendered line. */
    const mirror = result.sources?.csafMirror;
    expect(Object.keys(mirror ?? {}).sort()).toEqual(
      ['checkpoint', 'documentCount', 'lastCompletedAt', 'ready', 'syncStatus'].sort(),
    );
    expect(mirror?.syncStatus).toBe('complete');
    const text = firstText(listReferenceTool.format?.(result));
    expect(text).toContain(
      `- **ICS advisory index** — ready: yes, 1 documents, sync status complete, checkpoint ${mirror?.checkpoint}, last completed ${mirror?.lastCompletedAt}.`,
    );
    expect(text).toContain('refresh cron `*/30 * * * *`.');
  }, 20000);
});
