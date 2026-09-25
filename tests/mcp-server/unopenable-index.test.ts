/**
 * @fileoverview An advisory index path the server cannot open — a directory it
 * may not write, a path running through a regular file, a read-only database —
 * across every surface that reads the index: both ICS tools and the advisory
 * resource fail with one declared, non-retryable reason whose text names
 * `CISA_CSAF_MIRROR_PATH` and never the path; resource listing and completion
 * stay alive; `cisa_list_reference` topic `sources` says why. The KEV surface
 * keeps working throughout. Every store is a real SQLite path under a temp
 * directory.
 * @module tests/mcp-server/unopenable-index.test
 */

import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { sqliteMirrorStore } from '@cyanheads/mcp-ts-core/mirror';
import {
  createFetchMock,
  createMockContext,
  runToolContract,
} from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { icsAdvisoryResource } from '@/mcp-server/resources/definitions/ics-advisory.resource.js';
import { kevEntryResource } from '@/mcp-server/resources/definitions/kev-entry.resource.js';
import { getAdvisoryTool } from '@/mcp-server/tools/definitions/get-advisory.tool.js';
import { listReferenceTool } from '@/mcp-server/tools/definitions/list-reference.tool.js';
import { searchIcsAdvisoriesTool } from '@/mcp-server/tools/definitions/search-ics-advisories.tool.js';
import { initCisaFeeds, resetCisaFeeds } from '@/services/cisa-feeds/cisa-feeds-service.js';
import {
  classifyStoreOpenFailure,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import {
  getKevCatalog,
  initKevCatalog,
  KEV_FEED_URL,
  resetKevCatalog,
} from '@/services/kev-catalog/kev-catalog-service.js';
import {
  initVulnrichment,
  resetVulnrichment,
} from '@/services/vulnrichment/vulnrichment-service.js';
import { buildKevFeedBody } from '../fixtures/kev-feed.js';
import { contentText, firstText } from '../helpers/format-text.js';

const listExtra = {} as Parameters<NonNullable<typeof icsAdvisoryResource.list>>[0];
const advisoryParams = icsAdvisoryResource.params as NonNullable<typeof icsAdvisoryResource.params>;

/** Builds an unopenable index path under `base` and returns it with its expected reason. */
const CASES: Array<{
  label: string;
  reason: string;
  build: (base: string) => string;
}> = [
  {
    label: 'a directory the server may not write',
    reason: 'not_writable',
    build: (base) => {
      const locked = join(base, 'locked');
      mkdirSync(locked);
      chmodSync(locked, 0o555);
      return join(locked, 'sub', 'csaf.sqlite3');
    },
  },
  {
    label: 'an existing directory that refuses a new database file',
    reason: 'not_writable',
    build: (base) => {
      const locked = join(base, 'locked');
      mkdirSync(locked);
      chmodSync(locked, 0o555);
      return join(locked, 'csaf.sqlite3');
    },
  },
  {
    label: 'a path running through a regular file',
    reason: 'not_a_directory',
    build: (base) => {
      const file = join(base, 'a-file');
      writeFileSync(file, 'not a directory');
      return join(file, 'csaf.sqlite3');
    },
  },
  {
    label: 'a read-only database in a read-only directory',
    reason: 'read_only',
    build: (base) => base /* replaced in beforeEach, which needs an async seed */,
  },
  {
    label: 'a file that is not a SQLite database',
    reason: 'not_a_database',
    build: (base) => {
      const file = join(base, 'csaf.sqlite3');
      writeFileSync(file, 'plain text, not a SQLite database. '.repeat(200));
      return file;
    },
  },
];

async function readOnlyDatabase(base: string): Promise<string> {
  const dir = join(base, 'frozen');
  mkdirSync(dir);
  const path = join(dir, 'csaf.sqlite3');
  const store = sqliteMirrorStore({
    path,
    table: 'placeholder',
    primaryKey: 'id',
    columns: { id: 'TEXT' },
  });
  await store.raw();
  await store.close();
  chmodSync(path, 0o444);
  chmodSync(dir, 0o555);
  return path;
}

describe.each(CASES)('an unopenable advisory index: $label', ({ reason, build, label }) => {
  let base: string;
  let path: string;

  beforeEach(async () => {
    resetKevCatalog();
    resetCsafMirror();
    resetVulnrichment();
    resetCisaFeeds();
    base = mkdtempSync(join(tmpdir(), 'unopenable-index-'));
    path = label.startsWith('a read-only database') ? await readOnlyDatabase(base) : build(base);
    initKevCatalog({ refreshCron: '*/30 * * * *', timeoutMs: 5000 });
    initCsafMirror({ mirrorPath: path, timeoutMs: 5000 });
    initVulnrichment({ cacheTtlSeconds: 21_600, timeoutMs: 5000 });
    initCisaFeeds({ cacheTtlSeconds: 900, timeoutMs: 5000 });
  });

  afterEach(() => {
    resetKevCatalog();
    resetCsafMirror();
    resetVulnrichment();
    resetCisaFeeds();
    for (const dir of ['locked', 'frozen']) {
      try {
        chmodSync(join(base, dir), 0o755);
      } catch {
        /* Only the case that created it has it. */
      }
    }
    rmSync(base, { recursive: true, force: true });
  });

  /** The declared failure, as a caller sees it on both surfaces. */
  function expectDeclaredFailure(result: Awaited<ReturnType<typeof runToolContract>>): void {
    expect(result.isError).toBe(true);
    const structured = result.structuredContent as {
      error: { code: number; data?: { reason?: string; retryable?: boolean } };
    };
    expect(structured.error.code).toBe(JsonRpcErrorCode.ConfigurationError);
    expect(structured.error.data?.reason).toBe('mirror_unavailable');
    expect(structured.error.data?.retryable).not.toBe(true);
    const text = contentText(result);
    expect(text).toContain('CISA_CSAF_MIRROR_PATH');
    expect(text).toContain('cisa_check_cve_status');
    expect(text).not.toContain(base);
    expect(JSON.stringify(structured)).not.toContain(base);
  }

  it('cisa_search_ics_advisories fails with the declared mirror_unavailable reason', async () => {
    expectDeclaredFailure(await runToolContract(searchIcsAdvisoriesTool, { vendor: 'Siemens' }));
  });

  it('cisa_get_advisory fails with the declared mirror_unavailable reason', async () => {
    expectDeclaredFailure(await runToolContract(getAdvisoryTool, { advisoryId: 'ICSA-26-260-07' }));
  });

  it('a cisa://advisory read fails with the same reason, non-retryable, without the path', async () => {
    const params = advisoryParams.parse({ advisoryId: 'ICSA-26-260-07' });
    const error = await Promise.resolve(
      icsAdvisoryResource.handler(params, createMockContext()),
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(McpError);
    expect((error as McpError).code).toBe(JsonRpcErrorCode.ConfigurationError);
    expect((error as McpError).data).toMatchObject({ reason: 'mirror_unavailable' });
    expect((error as McpError).data?.retryable).not.toBe(true);
    expect(JSON.stringify((error as McpError).data)).toContain('CISA_CSAF_MIRROR_PATH');
    expect((error as McpError).message).not.toContain(base);
    expect(JSON.stringify((error as McpError).data)).not.toContain(base);
  });

  it('advisory listing and completion return nothing, and the KEV listing still works', async () => {
    const listing = (await icsAdvisoryResource.list?.(listExtra)) as { resources: unknown[] };
    expect(listing.resources).toEqual([]);
    expect(await icsAdvisoryResource.complete?.advisoryId?.('ICSA-26')).toEqual([]);

    const http = createFetchMock([
      {
        match: KEV_FEED_URL,
        respond: new Response(buildKevFeedBody(), {
          headers: { 'content-type': 'application/json' },
        }),
      },
    ]);
    http.install();
    try {
      await getKevCatalog().snapshot(createMockContext());
    } finally {
      http.restore();
    }
    const kevListing = (await kevEntryResource.list?.(listExtra)) as { resources: unknown[] };
    expect(kevListing.resources.length).toBeGreaterThan(0);
  });

  it(`topic sources reports the index unavailable (${reason}) without the path`, async () => {
    const result = await listReferenceTool.handler(
      listReferenceTool.input.parse({ topic: 'sources' }),
      createMockContext(),
    );
    expect(result.sources?.csafMirror).toMatchObject({
      ready: false,
      syncStatus: 'unavailable',
      unavailableReason: reason,
    });
    const text = firstText(listReferenceTool.format?.(result));
    expect(text).toContain(`unavailable: ${reason.replaceAll('_', ' ')}`);
    expect(text).toContain('CISA_CSAF_MIRROR_PATH');
    expect(text).not.toContain(base);
  });
});

describe('classifyStoreOpenFailure', () => {
  const errno = (code: string) => Object.assign(new Error(`${code}: some message`), { code });

  it('maps each filesystem and SQLite open failure to a reason, wherever the code sits', () => {
    expect(classifyStoreOpenFailure(errno('EROFS'))).toBe('read_only');
    expect(classifyStoreOpenFailure(errno('SQLITE_READONLY'))).toBe('read_only');
    expect(classifyStoreOpenFailure(errno('SQLITE_READONLY_DIRECTORY'))).toBe('read_only');
    expect(classifyStoreOpenFailure(errno('EACCES'))).toBe('not_writable');
    expect(classifyStoreOpenFailure(errno('EPERM'))).toBe('not_writable');
    expect(classifyStoreOpenFailure(errno('SQLITE_CANTOPEN'))).toBe('not_writable');
    expect(classifyStoreOpenFailure(errno('ENOENT'))).toBe('missing_directory');
    expect(classifyStoreOpenFailure(errno('ENOTDIR'))).toBe('not_a_directory');
    expect(classifyStoreOpenFailure(errno('EEXIST'))).toBe('not_a_directory');
    expect(classifyStoreOpenFailure(errno('SQLITE_NOTADB'))).toBe('not_a_database');
    /* The framework wraps a driver open failure in an McpError whose cause carries the code. */
    const wrapped = new McpError(
      JsonRpcErrorCode.DatabaseError,
      'Failed to open mirror store',
      {},
      {
        cause: errno('EROFS'),
      },
    );
    expect(classifyStoreOpenFailure(wrapped)).toBe('read_only');
  });

  it('leaves anything else unclassified, so a transient lock is never reported as misconfiguration', () => {
    expect(classifyStoreOpenFailure(errno('SQLITE_BUSY'))).toBeUndefined();
    expect(classifyStoreOpenFailure(new Error('boom'))).toBeUndefined();
    expect(classifyStoreOpenFailure('a string')).toBeUndefined();
    const aborted = new DOMException('The operation was aborted.', 'AbortError');
    expect(classifyStoreOpenFailure(aborted)).toBeUndefined();
  });
});
