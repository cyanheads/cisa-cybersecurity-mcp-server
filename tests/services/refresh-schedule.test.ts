/**
 * @fileoverview Tests for the background refresh wiring — which cron jobs
 * register for which values, and what the boot pass and the scheduled advisory
 * job do to the index. The index is a real SQLite file in a
 * temp directory; upstream is a fetch mock, so every assertion reads the
 * requests actually made.
 * @module tests/services/refresh-schedule.test
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFetchMock } from '@cyanheads/mcp-ts-core/testing';
import { logger, schedulerService } from '@cyanheads/mcp-ts-core/utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getCsafMirror,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL, CSAF_CHANGES_URL } from '@/services/csaf-mirror/ingest.js';
import {
  type BackgroundRefreshOptions,
  startBackgroundRefresh,
} from '@/services/refresh-schedule.js';
import { FULL_ADVISORY } from '../fixtures/csaf-documents.js';
import { buildTarGzResponse } from '../fixtures/tar.js';

const archive = () =>
  buildTarGzResponse([
    {
      name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json',
      data: JSON.stringify(FULL_ADVISORY),
    },
  ]);

describe('startBackgroundRefresh', () => {
  let dir: string;
  const kev = { refresh: vi.fn(async () => {}) };

  beforeEach(() => {
    resetCsafMirror();
    dir = mkdtempSync(join(tmpdir(), 'refresh-schedule-'));
    initCsafMirror({ mirrorPath: join(dir, 'csaf.sqlite3'), timeoutMs: 5000 });
  });

  afterEach(async () => {
    schedulerService.destroyAll();
    vi.restoreAllMocks();
    await getCsafMirror().close();
    resetCsafMirror();
    rmSync(dir, { recursive: true, force: true });
    kev.refresh.mockClear();
  });

  const options = (
    overrides: Partial<BackgroundRefreshOptions> = {},
  ): BackgroundRefreshOptions => ({
    csafMirrorAutoInit: false,
    csafRefreshCron: '17 */6 * * *',
    kevRefreshCron: '*/30 * * * *',
    kev,
    mirror: getCsafMirror(),
    ...overrides,
  });

  const jobs = () =>
    schedulerService
      .listJobs()
      .map((job) => ({ id: job.id, schedule: job.schedule }))
      .sort((a, b) => a.id.localeCompare(b.id));

  const job = (id: string) => {
    const found = schedulerService.listJobs().find((entry) => entry.id === id);
    if (!found) throw new Error(`job ${id} is not registered`);
    return found;
  };

  /** Seed the index through the framework runner, outside any code under test. */
  async function seed(): Promise<void> {
    const http = createFetchMock([{ match: CSAF_ARCHIVE_URL, respond: () => archive() }]);
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

  /** Run `fn` with every upstream route answering, and return the URLs requested. */
  async function requestsDuring(fn: () => Promise<unknown>): Promise<string[]> {
    const http = createFetchMock([
      { match: CSAF_ARCHIVE_URL, respond: () => archive() },
      { match: CSAF_CHANGES_URL, respond: () => new Response(null, { status: 304 }) },
    ]);
    http.install();
    try {
      await fn();
    } finally {
      http.restore();
    }
    return http.calls.map((call) => call.request.url);
  }

  describe('cron jobs', () => {
    /* The wiring takes no transport, so stdio registers exactly what HTTP does;
     * the live stdio run is covered by the field test. */
    it('valid expressions register both jobs on those expressions', async () => {
      await startBackgroundRefresh(options());
      expect(jobs()).toEqual([
        { id: 'csaf-mirror-refresh', schedule: '17 */6 * * *' },
        { id: 'kev-catalog-refresh', schedule: '*/30 * * * *' },
      ]);
    });

    it('off registers no job for that variable and logs no warning', async () => {
      const warning = vi.spyOn(logger, 'warning');
      await startBackgroundRefresh(options({ kevRefreshCron: 'off' }));
      expect(jobs()).toEqual([{ id: 'csaf-mirror-refresh', schedule: '17 */6 * * *' }]);
      schedulerService.destroyAll();

      await startBackgroundRefresh(options({ csafRefreshCron: 'off' }));
      expect(jobs()).toEqual([{ id: 'kev-catalog-refresh', schedule: '*/30 * * * *' }]);
      schedulerService.destroyAll();

      await startBackgroundRefresh(options({ kevRefreshCron: 'off', csafRefreshCron: 'off' }));
      expect(jobs()).toEqual([]);
      expect(warning).not.toHaveBeenCalled();
    });

    it('the KEV job runs the conditional KEV refresh', async () => {
      await startBackgroundRefresh(options());
      await job('kev-catalog-refresh').task.execute();
      expect(kev.refresh).toHaveBeenCalledTimes(1);
    });

    it('the advisory job refreshes a synced index with one manifest request', async () => {
      await seed();
      /* The boot pass refreshes too; this test is about the scheduled run after it. */
      await requestsDuring(() => startBackgroundRefresh(options()));
      const urls = await requestsDuring(() => job('csaf-mirror-refresh').task.execute());
      expect(urls).toEqual([CSAF_CHANGES_URL]);
    });

    it('the advisory job never refreshes an index that has never completed a sync', async () => {
      await startBackgroundRefresh(options());
      const urls = await requestsDuring(() => job('csaf-mirror-refresh').task.execute());
      expect(urls).toEqual([]);
      expect(await getCsafMirror().ready()).toBe(false);
    });
  });

  describe('boot pass', () => {
    it('a synced, content-current index runs one background refresh', async () => {
      await seed();
      const before = (await getCsafMirror().state()).lastCompletedAt;
      const urls = await requestsDuring(() => startBackgroundRefresh(options()));
      expect(urls).toEqual([CSAF_CHANGES_URL]);
      expect((await getCsafMirror().state()).lastCompletedAt).not.toBe(before);
    });

    it('sends the stored manifest ETag, so an unchanged manifest is one conditional request', async () => {
      await seed();
      const handle = await getCsafMirror().mirrorInstance.raw();
      handle
        .prepare("INSERT INTO mirror_meta (key, value) VALUES ('changes_csv_etag', ?)")
        .run('"abc"');
      const http = createFetchMock([
        { match: CSAF_CHANGES_URL, respond: () => new Response(null, { status: 304 }) },
      ]);
      http.install();
      try {
        await startBackgroundRefresh(options());
      } finally {
        http.restore();
      }
      expect(http.calls).toHaveLength(1);
      expect(http.calls[0]?.request.headers.get('if-none-match')).toBe('"abc"');
    });

    it('the refresh cron set to off also disables the boot refresh', async () => {
      await seed();
      const urls = await requestsDuring(() =>
        startBackgroundRefresh(options({ csafRefreshCron: 'off' })),
      );
      expect(urls).toEqual([]);
    });

    it('with auto-init off and no index, boot makes no CSAF request', async () => {
      const urls = await requestsDuring(() => startBackgroundRefresh(options()));
      expect(urls).toEqual([]);
      expect(await getCsafMirror().ready()).toBe(false);
    });

    it('a never-synced index seeds at boot and does not also refresh or log a sync conflict', async () => {
      const warning = vi.spyOn(logger, 'warning');
      const error = vi.spyOn(logger, 'error');
      const urls = await requestsDuring(() =>
        startBackgroundRefresh(options({ csafMirrorAutoInit: true })),
      );
      expect(urls).toEqual([CSAF_ARCHIVE_URL]);
      expect(await getCsafMirror().ready()).toBe(true);
      const logged = [...warning.mock.calls, ...error.mock.calls].map((call) => String(call[0]));
      expect(logged.filter((line) => /already in progress/.test(line))).toEqual([]);
    });

    it('a content-stale index re-ingests at boot instead of refreshing', async () => {
      await seed();
      const handle = await getCsafMirror().mirrorInstance.raw();
      handle.exec("DELETE FROM mirror_meta WHERE key = 'ingest_content_version'");
      const urls = await requestsDuring(() =>
        startBackgroundRefresh(options({ csafMirrorAutoInit: true })),
      );
      expect(urls).toEqual([CSAF_ARCHIVE_URL]);
      expect((await getCsafMirror().contentState()).stale).toBe(false);
    });

    it('with auto-init off, a content-stale index is neither re-ingested nor refreshed at boot', async () => {
      await seed();
      const handle = await getCsafMirror().mirrorInstance.raw();
      handle.exec("DELETE FROM mirror_meta WHERE key = 'ingest_content_version'");
      const urls = await requestsDuring(() => startBackgroundRefresh(options()));
      expect(urls).toEqual([]);
    });
  });
});
