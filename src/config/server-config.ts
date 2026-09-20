/**
 * @fileoverview Server-specific configuration for cisa-cybersecurity-mcp-server.
 * Every variable is optional — the server runs correctly with none of them set,
 * because every upstream source is keyless and every tunable has a working
 * default. Lazy-parsed via `parseEnvConfig` so a Workers-style request-time env
 * injection would still resolve (the SQLite mirror rules Workers out, but the
 * lazy shape costs nothing).
 * @module config/server-config
 */

import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';

const ServerConfigSchema = z.object({
  kevRefreshCron: z
    .string()
    .default('*/30 * * * *')
    .describe('Cron for the KEV conditional-refresh poll; empty disables the in-process schedule.'),
  csafMirrorPath: z
    .string()
    .default('.mirror/csaf.sqlite3')
    .describe('Filesystem path to the ICS advisory SQLite index.'),
  csafMirrorAutoInit: z
    .stringbool()
    .default(true)
    .describe('Seed the advisory mirror in the background at startup when it has never synced.'),
  csafRefreshCron: z
    .string()
    .default('17 */6 * * *')
    .describe('Cron for the incremental advisory refresh; empty disables it.'),
  vulnrichmentCacheTtlSeconds: z.coerce
    .number()
    .int()
    .positive()
    .default(21_600)
    .describe('TTL for a cached SSVC record. Negative results use one sixth of this.'),
  feedCacheTtlSeconds: z.coerce
    .number()
    .int()
    .positive()
    .default(900)
    .describe('TTL for a parsed RSS feed window.'),
  httpTimeoutMs: z.coerce
    .number()
    .int()
    .positive()
    .default(30_000)
    .describe('Per-request timeout for every upstream fetch, in milliseconds.'),
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;

let _config: ServerConfig | undefined;

/** Parse (once) and return the server-specific configuration. */
export function getServerConfig(): ServerConfig {
  _config ??= parseEnvConfig(ServerConfigSchema, {
    kevRefreshCron: 'CISA_KEV_REFRESH_CRON',
    csafMirrorPath: 'CISA_CSAF_MIRROR_PATH',
    csafMirrorAutoInit: 'CISA_CSAF_MIRROR_AUTO_INIT',
    csafRefreshCron: 'CISA_CSAF_REFRESH_CRON',
    vulnrichmentCacheTtlSeconds: 'CISA_VULNRICHMENT_CACHE_TTL_SECONDS',
    feedCacheTtlSeconds: 'CISA_FEED_CACHE_TTL_SECONDS',
    httpTimeoutMs: 'CISA_HTTP_TIMEOUT_MS',
  });
  return _config;
}

/** Reset the memoized config — test-only. */
export function resetServerConfig(): void {
  _config = undefined;
}
