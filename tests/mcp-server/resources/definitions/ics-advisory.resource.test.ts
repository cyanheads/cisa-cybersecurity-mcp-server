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
import { McpError } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { icsAdvisoryResource } from '@/mcp-server/resources/definitions/ics-advisory.resource.js';
import {
  getCsafMirror,
  initCsafMirror,
  resetCsafMirror,
} from '@/services/csaf-mirror/csaf-mirror-service.js';
import { CSAF_ARCHIVE_URL } from '@/services/csaf-mirror/ingest.js';
import { buildOversizedAdvisory, FULL_ADVISORY } from '../../../fixtures/csaf-documents.js';
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
