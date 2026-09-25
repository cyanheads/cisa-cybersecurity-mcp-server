/**
 * @fileoverview Server-specific configuration for cisa-cybersecurity-mcp-server.
 * Every variable is optional — the server runs correctly with none of them set,
 * because every upstream source is keyless and every tunable has a working
 * default. Lazy-parsed via `parseEnvConfig` so a Workers-style request-time env
 * injection would still resolve (the SQLite mirror rules Workers out, but the
 * lazy shape costs nothing).
 * @module config/server-config
 */

import { homedir } from 'node:os';
import { posix, win32 } from 'node:path';
import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';
import { validate as isValidCron } from 'node-cron';

/** The refresh-cron value that disables a schedule. */
export const CRON_OFF = 'off';

/** Directory under the per-user cache dir that holds the advisory index. */
const CACHE_SUBDIR = 'cisa-cybersecurity-mcp-server';

/** The host facts the default index path is resolved from. */
export interface CacheHost {
  env: Readonly<Record<string, string | undefined>>;
  homedir: string;
  platform: NodeJS.Platform;
}

/**
 * The default advisory index path: `csaf.sqlite3` in this server's directory
 * under the per-user cache dir — `~/Library/Caches` on macOS, `%LOCALAPPDATA%`
 * on Windows, and `$XDG_CACHE_HOME` (only when absolute, per the XDG spec) else
 * `~/.cache` everywhere else. Never relative to the working directory, which a
 * client may set to one the server cannot write.
 */
export function defaultCsafMirrorPath(host: CacheHost): string {
  if (host.platform === 'win32') {
    const base = host.env.LOCALAPPDATA || win32.join(host.homedir, 'AppData', 'Local');
    return win32.join(base, CACHE_SUBDIR, 'csaf.sqlite3');
  }
  const xdg = host.env.XDG_CACHE_HOME;
  const base =
    host.platform === 'darwin'
      ? posix.join(host.homedir, 'Library', 'Caches')
      : xdg && posix.isAbsolute(xdg)
        ? xdg
        : posix.join(host.homedir, '.cache');
  return posix.join(base, CACHE_SUBDIR, 'csaf.sqlite3');
}

/**
 * A refresh cron: `off` in any case disables the schedule; anything else must be
 * an expression `node-cron` accepts, so a typo fails startup instead of leaving
 * the server running without the job. Unset and blank values never reach this
 * schema — `parseEnvConfig` reads them as absent, so the default applies.
 */
const refreshCron = (fallback: string) =>
  z
    .string()
    .trim()
    .default(fallback)
    .transform((value) => (value.toLowerCase() === CRON_OFF ? CRON_OFF : value))
    .refine((value) => value === CRON_OFF || isValidCron(value), {
      message: `Not a valid cron expression. Use a five- or six-field expression such as "${fallback}", or "${CRON_OFF}" to disable the schedule.`,
    });

const ServerConfigSchema = z.object({
  kevRefreshCron: refreshCron('*/30 * * * *').describe(
    'Cron for the KEV conditional-refresh poll, on every transport; "off" disables it.',
  ),
  csafMirrorPath: z
    .string()
    .optional()
    .describe(
      'Filesystem path to the ICS advisory SQLite index; unset, the per-user cache directory.',
    ),
  csafMirrorAutoInit: z
    .stringbool()
    .default(true)
    .describe(
      'Seed the advisory mirror in the background when it has never synced, and re-ingest it when an older ingest-content version built it.',
    ),
  csafRefreshCron: refreshCron('17 */6 * * *').describe(
    'Cron for the advisory index refresh, on every transport, also run once at startup; "off" disables both.',
  ),
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

export type ServerConfig = Omit<z.infer<typeof ServerConfigSchema>, 'csafMirrorPath'> & {
  csafMirrorPath: string;
};

let _config: ServerConfig | undefined;

/** Parse (once) and return the server-specific configuration. */
export function getServerConfig(): ServerConfig {
  if (_config) return _config;
  const parsed = parseEnvConfig(ServerConfigSchema, {
    kevRefreshCron: 'CISA_KEV_REFRESH_CRON',
    csafMirrorPath: 'CISA_CSAF_MIRROR_PATH',
    csafMirrorAutoInit: 'CISA_CSAF_MIRROR_AUTO_INIT',
    csafRefreshCron: 'CISA_CSAF_REFRESH_CRON',
    vulnrichmentCacheTtlSeconds: 'CISA_VULNRICHMENT_CACHE_TTL_SECONDS',
    feedCacheTtlSeconds: 'CISA_FEED_CACHE_TTL_SECONDS',
    httpTimeoutMs: 'CISA_HTTP_TIMEOUT_MS',
  });
  _config = {
    ...parsed,
    csafMirrorPath:
      parsed.csafMirrorPath ??
      defaultCsafMirrorPath({ env: process.env, homedir: homedir(), platform: process.platform }),
  };
  return _config;
}

/** Reset the memoized config — test-only. */
export function resetServerConfig(): void {
  _config = undefined;
}
