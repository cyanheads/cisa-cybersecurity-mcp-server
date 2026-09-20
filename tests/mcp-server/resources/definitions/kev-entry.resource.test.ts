/**
 * @fileoverview Tests for the `cisa://kev/{cveId}` resource — found/not-found
 * handling, `list()` before and after the catalog loads, and prefix
 * completion.
 * @module tests/mcp-server/resources/definitions/kev-entry.resource.test
 */

import { McpError } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { kevEntryResource } from '@/mcp-server/resources/definitions/kev-entry.resource.js';
import {
  getKevCatalog,
  initKevCatalog,
  KEV_FEED_URL,
  resetKevCatalog,
} from '@/services/kev-catalog/kev-catalog-service.js';
import { buildKevFeedBody } from '../../../fixtures/kev-feed.js';

/* `resource()`'s ResourceDefinition types `params` as optional (the generic
 * interface field), even though these definitions always supply one; and
 * `list()`'s declared signature takes a `ListExtra` the implementation
 * ignores. Both are compile-time-only frictions, not runtime behavior. */
const kevParams = kevEntryResource.params as NonNullable<typeof kevEntryResource.params>;
const listExtra = {} as Parameters<NonNullable<typeof kevEntryResource.list>>[0];

async function loadCatalog() {
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
}

describe('cisa://kev/{cveId} resource', () => {
  beforeEach(() => {
    resetKevCatalog();
    initKevCatalog({
      refreshCron: '*/30 * * * *',
      timeoutMs: 5000,
      now: () => new Date('2026-09-10T00:00:00Z'),
    });
  });

  afterEach(() => {
    resetKevCatalog();
  });

  it('returns a KEV record, the same shape cisa_check_cve_status returns', async () => {
    await loadCatalog();
    const ctx = createMockContext({ uri: new URL('cisa://kev/CVE-2026-00001') });
    const params = kevParams.parse({ cveId: 'CVE-2026-00001' });
    const result = await kevEntryResource.handler(params, ctx);
    expect(result.inKev).toBe(true);
    expect(result.vendorProject).toBe('Acme Corp');
  });

  it('normalizes case and whitespace before lookup', async () => {
    await loadCatalog();
    const ctx = createMockContext();
    const params = kevParams.parse({ cveId: ' cve-2026-00001 ' });
    const result = await kevEntryResource.handler(params, ctx);
    expect(result.inKev).toBe(true);
  });

  it('throws notFound for a CVE not in the catalog', async () => {
    await loadCatalog();
    const ctx = createMockContext();
    const params = kevParams.parse({ cveId: 'CVE-2099-00000' });
    const error = await Promise.resolve(kevEntryResource.handler(params, ctx)).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(McpError);
    expect((error as McpError).message).toContain('Absence is not a statement about severity');
  });

  it('list() returns an empty array before any snapshot has loaded', () => {
    const listing = kevEntryResource.list?.(listExtra) as { resources: unknown[] };
    expect(listing.resources).toEqual([]);
  });

  it('list() returns the most recently added entries, newest first', async () => {
    await loadCatalog();
    const listing = kevEntryResource.list?.(listExtra) as {
      resources: Array<{ uri: string; name: string; mimeType: string }>;
    };
    expect(listing.resources.length).toBeGreaterThan(0);
    expect(listing.resources[0]?.uri).toBe(
      'cisa://kev/CVE-2026-00002',
    ); /* dateAdded 2026-09-05, newest of the batch */
    expect(listing.resources[0]?.mimeType).toBe('application/json');
  });

  it('complete() matches CVE IDs by prefix, capped, before any snapshot has loaded returns []', () => {
    const matches = kevEntryResource.complete?.cveId?.('CVE-2026') as string[] | undefined;
    expect(matches).toEqual([]);
  });

  it('complete() matches CVE IDs by prefix once loaded', async () => {
    await loadCatalog();
    const matches = kevEntryResource.complete?.cveId?.('CVE-2026') as string[] | undefined;
    expect(matches).toBeDefined();
    expect(matches?.every((id) => id.startsWith('CVE-2026'))).toBe(true);
    expect(matches).toContain('CVE-2026-00001');
  });
});
