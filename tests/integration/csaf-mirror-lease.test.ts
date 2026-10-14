/**
 * @fileoverview The cross-process sync lease. Two `CsafMirrorService` instances
 * on one temp SQLite file stand in for two server processes sharing an index:
 * each owns its own store handle, so nothing in-process connects them and only
 * the lease row can keep them from syncing at once. Upstream is a fetch mock
 * whose archive route can be held open, so a sync is observably in flight while
 * the other instance tries to start one.
 * @module tests/integration/csaf-mirror-lease.test
 */

import { spawnSync } from 'node:child_process';
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFetchMock } from '@cyanheads/mcp-ts-core/testing';
import { logger } from '@cyanheads/mcp-ts-core/utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CsafMirrorService } from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL, CSAF_CHANGES_URL } from '@/services/csaf-mirror/ingest.js';
import { SYNC_LEASE_TTL_MS } from '@/services/csaf-mirror/sync-lease.js';
import { FULL_ADVISORY } from '../fixtures/csaf-documents.js';
import { buildTarGzResponse } from '../fixtures/tar.js';

const archive = () =>
  buildTarGzResponse([
    {
      name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json',
      data: JSON.stringify(FULL_ADVISORY),
    },
  ]);

/** A promise the test resolves by hand, to hold an upstream response open. */
function gate(): { open: () => void; wait: Promise<void> } {
  let open = () => {};
  const wait = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { open, wait };
}

describe('cross-process sync lease', () => {
  let dir: string;
  let path: string;
  let first: CsafMirrorService;
  let second: CsafMirrorService;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'csaf-lease-'));
    path = join(dir, 'csaf.sqlite3');
    first = new CsafMirrorService({ mirrorPath: path, timeoutMs: 5000 });
    second = new CsafMirrorService({ mirrorPath: path, timeoutMs: 5000 });
  });

  afterEach(async () => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    await first.close();
    await second.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const leaseRow = async (service: CsafMirrorService) =>
    (await service.mirrorInstance.raw())
      .prepare<{ value: string }>("SELECT value FROM mirror_meta WHERE key = 'sync_lease'")
      .get();

  /**
   * Start a seed on `first` whose archive response is held until `release()`,
   * and resolve once its request is in flight.
   */
  async function holdFirstSeed(http: ReturnType<typeof createFetchMock>) {
    const held = gate();
    const requested = gate();
    http.route({
      match: CSAF_ARCHIVE_URL,
      respond: async () => {
        requested.open();
        await held.wait;
        return archive();
      },
    });
    const running = first.autoInit();
    await requested.wait;
    return { running, release: held.open };
  }

  it('a second process finds the first seeding, skips its own seed with a log line, and makes no request', async () => {
    const info = vi.spyOn(logger, 'info');
    const http = createFetchMock();
    http.install();
    try {
      const { running, release } = await holdFirstSeed(http);
      const skipped = await second.autoInit();
      expect(skipped).toMatchObject({ ran: false, reason: 'lease_held' });
      expect(http.calls.map((call) => call.request.url)).toEqual([CSAF_ARCHIVE_URL]);
      expect(info.mock.calls.map((call) => String(call[0]))).toContainEqual(
        expect.stringMatching(/another process holds the ICS advisory index sync lease/),
      );

      /* The skipping process keeps serving reads of the shared index. */
      expect(await second.ready()).toBe(false);
      release();
      expect(await running).toMatchObject({ ran: true });
      expect(await second.ready()).toBe(true);
    } finally {
      http.restore();
    }
    expect(await leaseRow(first)).toBeUndefined();
  }, 30000);

  it('the same process never runs two syncs at once and never surfaces a sync conflict', async () => {
    const http = createFetchMock();
    http.install();
    try {
      const { running, release } = await holdFirstSeed(http);
      await expect(first.autoInit()).resolves.toMatchObject({ ran: false, reason: 'in_progress' });
      release();
      await running;
      expect(http.calls).toHaveLength(1);
    } finally {
      http.restore();
    }
  }, 30000);

  it('a refresh skips the same way while another process refreshes', async () => {
    const seed = createFetchMock([{ match: CSAF_ARCHIVE_URL, respond: () => archive() }]);
    seed.install();
    try {
      await first.autoInit();
    } finally {
      seed.restore();
    }

    const held = gate();
    const requested = gate();
    const http = createFetchMock([
      {
        match: CSAF_CHANGES_URL,
        respond: async () => {
          requested.open();
          await held.wait;
          return new Response(null, { status: 304 });
        },
      },
    ]);
    http.install();
    try {
      const running = first.maintain({ autoInit: true, refresh: true });
      await requested.wait;
      expect(await second.maintain({ autoInit: true, refresh: true })).toMatchObject({
        ran: false,
        reason: 'lease_held',
      });
      held.open();
      expect(await running).toMatchObject({ ran: true, mode: 'refresh' });
      expect(http.calls).toHaveLength(1);
    } finally {
      http.restore();
    }
  }, 30000);

  it('a lease left by a crashed process is taken over once it expires, and not before', async () => {
    const handle = await second.mirrorInstance.raw();
    const write = (expiresAt: number) =>
      handle
        .prepare(
          `INSERT INTO mirror_meta (key, value) VALUES ('sync_lease', ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
        )
        .run(JSON.stringify({ owner: 'crashed-host/4242/deadbeef', mode: 'init', expiresAt }));

    write(Date.now() + 60_000);
    const blocked = createFetchMock([{ match: CSAF_ARCHIVE_URL, respond: () => archive() }]);
    blocked.install();
    try {
      expect(await second.autoInit()).toMatchObject({ ran: false, reason: 'lease_held' });
    } finally {
      blocked.restore();
    }
    expect(blocked.calls).toHaveLength(0);

    write(Date.now() - 1);
    const http = createFetchMock([{ match: CSAF_ARCHIVE_URL, respond: () => archive() }]);
    http.install();
    try {
      expect(await second.autoInit()).toMatchObject({ ran: true });
    } finally {
      http.restore();
    }
    expect(await second.ready()).toBe(true);
    expect(await leaseRow(second)).toBeUndefined();
  }, 30000);

  it('the holder renews its lease while it syncs, so a long sync is never taken over', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    const http = createFetchMock();
    http.install();
    try {
      const { running, release } = await holdFirstSeed(http);
      const initial = JSON.parse((await leaseRow(first))?.value ?? '{}') as { expiresAt: number };

      vi.advanceTimersByTime(SYNC_LEASE_TTL_MS * 3);
      const renewed = JSON.parse((await leaseRow(first))?.value ?? '{}') as { expiresAt: number };
      expect(renewed.expiresAt).toBeGreaterThan(initial.expiresAt + SYNC_LEASE_TTL_MS);
      expect(await second.autoInit()).toMatchObject({ ran: false, reason: 'lease_held' });

      release();
      await running;
    } finally {
      http.restore();
    }
  }, 30000);

  it('a holder that finds its lease taken over aborts its own sync rather than writing alongside', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    const http = createFetchMock();
    http.install();
    try {
      const { running, release } = await holdFirstSeed(http);
      (await second.mirrorInstance.raw())
        .prepare("UPDATE mirror_meta SET value = ? WHERE key = 'sync_lease'")
        .run(
          JSON.stringify({ owner: 'usurper/1/cafe', mode: 'init', expiresAt: Date.now() + 1e6 }),
        );
      vi.advanceTimersByTime(SYNC_LEASE_TTL_MS);
      release();
      await expect(running).rejects.toThrow(/lease/);
      /* The usurper's lease is left alone. */
      expect(JSON.parse((await leaseRow(first))?.value ?? '{}')).toMatchObject({
        owner: 'usurper/1/cafe',
      });
    } finally {
      http.restore();
    }
  }, 30000);

  it('close() aborts an in-flight sync and releases the lease', async () => {
    const http = createFetchMock();
    http.install();
    try {
      const { running, release } = await holdFirstSeed(http);
      const settled = running.then(
        () => 'resolved',
        () => 'rejected',
      );
      const closing = first.close();
      release();
      await closing;
      expect(await settled).toBe('rejected');
    } finally {
      http.restore();
    }
    expect(await leaseRow(second)).toBeUndefined();
  }, 30000);

  it('refresh refuses a never-completed index before upstream I/O', async () => {
    const http = createFetchMock();
    http.install();
    try {
      await expect(first.sync('refresh', AbortSignal.timeout(5000))).rejects.toThrow(/mirror:init/);
      expect(http.calls).toHaveLength(0);
      expect(await leaseRow(second)).toBeUndefined();
    } finally {
      http.restore();
    }
  });

  it('close before automatic preflight finishes prevents a later seed', async () => {
    const http = createFetchMock([{ match: CSAF_ARCHIVE_URL, respond: () => archive() }]);
    http.install();
    try {
      const boot = first.autoInit();
      await first.close();
      await boot;
      expect(http.calls).toHaveLength(0);
      expect(await leaseRow(second)).toBeUndefined();
      await expect(first.autoInit()).resolves.toBeUndefined();
      expect(http.calls).toHaveLength(0);
    } finally {
      http.restore();
    }
  });

  it('close during direct sync store-open preflight cannot claim a lease', async () => {
    const held = gate();
    const requested = gate();
    const store = first.mirrorInstance.store;
    const raw = store.raw.bind(store);
    vi.spyOn(store, 'raw').mockImplementationOnce(async () => {
      requested.open();
      await held.wait;
      return raw();
    });
    const http = createFetchMock();
    http.install();
    try {
      const running = first.sync('init', AbortSignal.timeout(5000));
      const failed = expect(running).rejects.toThrow(/closing/);
      await requested.wait;
      const closing = first.close();
      held.open();
      await closing;
      await failed;
      expect(await leaseRow(second)).toBeUndefined();
      expect(http.calls).toHaveLength(0);
      await expect(first.sync('init', AbortSignal.timeout(5000))).rejects.toThrow(/closing/);
    } finally {
      http.restore();
    }
  });

  it('refresh rejects an interrupted first seed, but skips a live seed lease', async () => {
    const handle = await first.mirrorInstance.raw();
    await first.mirrorInstance.store.writeState({
      status: 'error',
      checkpoint: '2026-09-18',
      error: 'interrupted seed',
    });
    const http = createFetchMock();
    http.install();
    try {
      await expect(first.sync('refresh', AbortSignal.timeout(5000))).rejects.toThrow(/mirror:init/);
      handle
        .prepare("INSERT INTO mirror_meta (key, value) VALUES ('sync_lease', ?)")
        .run(
          JSON.stringify({ owner: 'other/123/test', mode: 'init', expiresAt: Date.now() + 60_000 }),
        );
      await expect(first.sync('refresh', AbortSignal.timeout(5000))).resolves.toMatchObject({
        ran: false,
        reason: 'lease_held',
      });
      expect(http.calls).toHaveLength(0);
      expect(JSON.parse((await leaseRow(second))?.value ?? '{}').owner).toBe('other/123/test');
    } finally {
      http.restore();
    }
  });
});

describe('mirror lifecycle command resolution', () => {
  it.each(['source', 'published'] as const)(
    'runs all three commands from the %s layout',
    (layout) => {
      const root = fileURLToPath(new URL('../../', import.meta.url));
      const directory = mkdtempSync(join(tmpdir(), 'csaf-cli-layout-'));
      const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
        files: string[];
        scripts: Record<string, string>;
      };
      try {
        mkdirSync(join(directory, 'scripts'));
        writeFileSync(
          join(directory, 'package.json'),
          JSON.stringify({ type: 'module', scripts: manifest.scripts }),
        );
        symlinkSync(join(root, 'node_modules'), join(directory, 'node_modules'), 'dir');
        for (const path of manifest.files.filter(
          (path) => path.startsWith('scripts/') || path === 'tsconfig.mirror.json',
        )) {
          cpSync(join(root, path), join(directory, path));
        }
        if (layout === 'source')
          cpSync(join(root, 'tsconfig.json'), join(directory, 'tsconfig.json'));

        // Service fakes isolate command/module resolution; the real lease behavior is covered above.
        for (const tree of layout === 'source' ? ['src', 'dist'] : ['dist']) {
          const extension = tree === 'src' ? 'ts' : 'js';
          mkdirSync(join(directory, tree, 'config'), { recursive: true });
          mkdirSync(join(directory, tree, 'services/csaf-mirror'), { recursive: true });
          writeFileSync(
            join(directory, tree, `config/server-config.${extension}`),
            `
          export function getServerConfig() {
            console.log('CONFIG_${tree}');
            return { csafMirrorPath: 'fixture', httpTimeoutMs: 1 };
          }
        `,
          );
          writeFileSync(
            join(directory, tree, `services/csaf-mirror/csaf-mirror-service.${extension}`),
            `
          export function initCsafMirror() {
            return {
              sync: async (mode) => { console.log('SYNC_${tree}:' + mode); return { ran: true, mode, result: { recordsApplied: 1, pagesFetched: 1, total: 1, tombstonesApplied: 0 } }; },
              close: async () => {},
              state: async () => ({ ready: false, syncStatus: 'pending', documentCount: null, checkpoint: null, lastSuccessfulCheckpoint: null, failedDocumentCount: 0, lastCompletedAt: null }),
              mirrorInstance: { status: async () => { console.log('STATUS_${tree}'); return { ready: false }; }, raw: async () => ({}), close: async () => {} }
            };
          }
        `,
          );
          writeFileSync(
            join(directory, tree, `services/csaf-mirror/ingest.${extension}`),
            `
          export const INGEST_CONTENT_VERSION = 2;
          export const readIngestContentVersion = () => null;
        `,
          );
        }
        for (const command of ['init', 'refresh', 'verify']) {
          const result = spawnSync('bun', ['run', `mirror:${command}`], {
            cwd: directory,
            env: { ...process.env, LOGS_DIR: join(directory, 'logs') },
            encoding: 'utf8',
            timeout: 10_000,
          });
          const output = `${result.stdout}\n${result.stderr}`;
          expect(result.error).toBeUndefined();
          expect(result.status, output).toBe(command === 'verify' ? 1 : 0);
          expect(output).toContain(`CONFIG_${layout === 'source' ? 'src' : 'dist'}`);
          const selected = layout === 'source' ? 'src' : 'dist';
          expect(output).toContain(
            command === 'verify' ? `STATUS_${selected}` : `SYNC_${selected}:${command}`,
          );
          expect(output).not.toContain('Cannot find module');
        }
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    },
  );
});
