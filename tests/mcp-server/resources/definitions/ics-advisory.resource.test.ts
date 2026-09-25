/**
 * @fileoverview Tests for the `cisa://advisory/{advisoryId}` resource — the
 * mirror_not_ready ServiceUnavailable throw, notFound for a missing ID, the
 * outline-arm rename to `outlineNotice`, the outline's vulnerabilities CVE
 * listing through the output schema, `list()`, and `complete()`.
 * @module tests/mcp-server/resources/definitions/ics-advisory.resource.test
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { icsAdvisoryResource } from '@/mcp-server/resources/definitions/ics-advisory.resource.js';
import {
  getCsafMirror,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL } from '@/services/csaf-mirror/ingest.js';
import {
  buildOversizedAdvisory,
  FULL_ADVISORY,
  sparseAdvisoryAs,
} from '../../../fixtures/csaf-documents.js';
import { buildTarGzResponse } from '../../../fixtures/tar.js';

/* `resource()`'s ResourceDefinition types `params` and `output` as optional (the
 * generic interface fields), even though this definition always supplies both;
 * and `list()`'s declared signature takes a `ListExtra` the implementation
 * ignores. All are compile-time-only frictions, not runtime behavior. */
const advisoryParams = icsAdvisoryResource.params as NonNullable<typeof icsAdvisoryResource.params>;
const listExtra = {} as Parameters<NonNullable<typeof icsAdvisoryResource.list>>[0];
const advisoryOutput = icsAdvisoryResource.output as NonNullable<typeof icsAdvisoryResource.output>;

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

describe('cisa://advisory/{advisoryId} resource', () => {
  let dir: string;

  beforeEach(() => {
    resetCsafMirror();
    dir = mkdtempSync(join(tmpdir(), 'ics-advisory-resource-'));
    initCsafMirror({ mirrorPath: join(dir, 'csaf.sqlite3'), timeoutMs: 5000 });
  });

  afterEach(() => {
    resetCsafMirror();
    rmSync(dir, { recursive: true, force: true });
  });

  it('throws a retryable ServiceUnavailable before the first sync completes', async () => {
    const ctx = createMockContext();
    const params = advisoryParams.parse({ advisoryId: 'ICSA-26-260-07' });
    const error = await Promise.resolve(icsAdvisoryResource.handler(params, ctx)).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(McpError);
    expect((error as McpError).data).toMatchObject({ reason: 'mirror_not_ready', retryable: true });
  });

  it('list() returns an empty array before the mirror is ready', async () => {
    const listing = (await icsAdvisoryResource.list?.(listExtra)) as { resources: unknown[] };
    expect(listing.resources).toEqual([]);
  });

  it('complete() returns an empty array before the mirror is ready', async () => {
    const matches = await icsAdvisoryResource.complete?.advisoryId?.('ICSA-26');
    expect(matches).toEqual([]);
  });

  describe('once seeded', () => {
    beforeEach(async () => {
      await seedMirror([
        {
          name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-260-07.json',
          data: JSON.stringify(FULL_ADVISORY),
        },
      ]);
    }, 30000);

    it('returns the full normalized advisory', async () => {
      const ctx = createMockContext();
      const params = advisoryParams.parse({ advisoryId: 'ICSA-26-260-07' });
      const result = await icsAdvisoryResource.handler(params, ctx);
      expect(result.advisory?.advisoryId).toBe('ICSA-26-260-07');
      expect(result.vulnerabilities?.[0]?.cve).toBe('CVE-2026-12345');
    });

    it('throws notFound for an advisoryId not in the index', async () => {
      const ctx = createMockContext();
      const params = advisoryParams.parse({ advisoryId: 'ICSA-99-999-99' });
      const error = await Promise.resolve(icsAdvisoryResource.handler(params, ctx)).catch(
        (e: unknown) => e,
      );
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).message).toContain('cisa_search_ics_advisories');
    });

    it('a not-found names the checkpoint and last sync, with the may-be-newer note only for an ID dated after that sync', async () => {
      (await getCsafMirror().mirrorInstance.raw())
        .prepare('UPDATE mirror_sync_state SET checkpoint = ?, completed_at = ? WHERE id = 1')
        .run('2026-09-17T06:00:00.000000Z', '2026-09-19T22:30:29.000Z');
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(new Date('2026-09-25T12:00:00Z'));
      try {
        const read = async (advisoryId: string) =>
          (await Promise.resolve(
            icsAdvisoryResource.handler(advisoryParams.parse({ advisoryId }), createMockContext()),
          ).catch((e: unknown) => e)) as McpError;

        const newer = await read('ICSA-26-265-09');
        expect(newer.code).toBe(JsonRpcErrorCode.NotFound);
        expect(newer.message).toContain('2026-09-17T06:00:00.000000Z');
        expect(newer.message).toContain('2026-09-19T22:30:29.000Z');
        expect(newer.message).toContain('may be newer than the index');
        expect(newer.data).toMatchObject({
          advisoryId: 'ICSA-26-265-09',
          indexCheckpoint: '2026-09-17T06:00:00.000000Z',
          indexLastSyncedAt: '2026-09-19T22:30:29.000Z',
        });

        const older = await read('ICSA-26-260-99');
        expect(older.code).toBe(JsonRpcErrorCode.NotFound);
        expect(older.message).toContain('2026-09-19T22:30:29.000Z');
        expect(older.message).not.toContain('may be newer');
      } finally {
        vi.useRealTimers();
      }
    });

    it('list() returns the most recently revised advisories', async () => {
      const listing = (await icsAdvisoryResource.list?.(listExtra)) as {
        resources: Array<{ uri: string; name: string }>;
      };
      expect(listing.resources).toEqual([
        {
          uri: 'cisa://advisory/ICSA-26-260-07',
          name: 'ICSA-26-260-07 — Acme Widgets PLC Remote Code Execution',
          mimeType: 'application/json',
        },
      ]);
    });

    it('complete() matches advisory IDs by prefix', async () => {
      const matches = await icsAdvisoryResource.complete?.advisoryId?.('ICSA-26');
      expect(matches).toEqual(['ICSA-26-260-07']);
    });
  });

  describe('a revision-suffixed advisory', () => {
    beforeEach(async () => {
      await seedMirror([
        {
          name: 'CSAF-develop/csaf_files/OT/white/2010/icsa-10-316-01a.json',
          data: JSON.stringify(sparseAdvisoryAs('ICSA-10-316-01A', '2010-11-12T00:00:00.000000Z')),
        },
      ]);
    }, 30000);

    it.each([
      'ICSA-10-316-01A',
      'icsa-10-316-01a',
      'ICSA-10-316-01a',
      'icsa-10-316-01A.json',
      ' ICSA-10-316-01A.JSON\t',
    ])('%j resolves to ICSA-10-316-01A through the params schema', async (advisoryId) => {
      const params = advisoryParams.parse({ advisoryId });
      const result = await icsAdvisoryResource.handler(params, createMockContext());
      expect(advisoryOutput.parse(result)).toMatchObject({
        advisory: { advisoryId: 'ICSA-10-316-01A' },
      });
    });

    it('rejects a malformed advisoryId at the params schema', () => {
      expect(advisoryParams.safeParse({ advisoryId: 'ICSA-10-316-01AB' }).success).toBe(false);
      expect(advisoryParams.safeParse({ advisoryId: 'ICSA-10-316-01A.json.json' }).success).toBe(
        false,
      );
    });
  });

  describe('an oversized advisory', () => {
    beforeEach(async () => {
      const raw = buildOversizedAdvisory('ICSA-26-003-01');
      await seedMirror([
        {
          name: 'CSAF-develop/csaf_files/OT/white/2026/icsa-26-003-01.json',
          data: JSON.stringify(raw),
        },
      ]);
    }, 30000);

    it('returns the outline arm, renaming the outline notice to outlineNotice', async () => {
      const ctx = createMockContext();
      const params = advisoryParams.parse({ advisoryId: 'ICSA-26-003-01' });
      const result = await icsAdvisoryResource.handler(params, ctx);
      expect(result.kind).toBe('outline');
      expect(result.sections).toBeDefined();
      expect(result.sections?.length).toBeGreaterThan(0);
      expect(result.outlineNotice).toBeDefined();
      expect((result as Record<string, unknown>).notice).toBeUndefined();
      expect(result.vulnerabilities).toBeUndefined();
      expect(result.outlineNotice).toContain('cisa_get_advisory');
    });

    it('through the declared output schema, each outline section keeps its name and byte size', async () => {
      const ctx = createMockContext();
      const params = advisoryParams.parse({ advisoryId: 'ICSA-26-003-01' });
      const parsed = advisoryOutput.parse(await icsAdvisoryResource.handler(params, ctx)) as {
        sections: Array<Record<string, unknown>>;
      };
      const doc = await getCsafMirror().getAdvisory('ICSA-26-003-01');
      const vulnerabilities = parsed.sections.find((section) => section.name === 'vulnerabilities');
      expect(vulnerabilities?.bytes).toBe(JSON.stringify(doc?.vulnerabilities).length);
      for (const section of parsed.sections) {
        expect(typeof section.name).toBe('string');
        expect(typeof section.bytes).toBe('number');
      }
    });

    it('lists the vulnerabilities section’s CVE IDs through the output schema and points at cves', async () => {
      const ctx = createMockContext();
      const params = advisoryParams.parse({ advisoryId: 'ICSA-26-003-01' });
      const parsed = advisoryOutput.parse(await icsAdvisoryResource.handler(params, ctx)) as {
        outlineNotice: string;
        sections: Array<{ name: string; cves?: string[] }>;
      };
      const vulnerabilities = parsed.sections.find((section) => section.name === 'vulnerabilities');
      expect(vulnerabilities?.cves).toEqual(
        Array.from({ length: 40 }, (_, index) => `CVE-2026-${10000 + index}`),
      );
      expect(parsed.sections.filter((section) => section.cves)).toHaveLength(1);
      expect(parsed.outlineNotice).toContain('pass cves with IDs from its listed CVEs');
    });
  });
});
