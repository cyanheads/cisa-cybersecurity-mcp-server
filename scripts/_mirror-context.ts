/**
 * @fileoverview Shared bootstrap for the ICS advisory mirror lifecycle CLI
 * scripts (csaf-mirror-init / csaf-mirror-refresh / csaf-mirror-verify). Builds
 * the mirror service from the environment — the same index path the server
 * resolves, per-user cache default included — with no MCP transport and no tool
 * registration. Imported by the three named scripts, so it travels with them in
 * the npm tarball and the Docker image.
 * @module scripts/_mirror-context
 */

import { logger } from '@cyanheads/mcp-ts-core/utils';
import { getServerConfig } from '@/config/server-config.js';
import {
  type CsafMirrorService,
  initCsafMirror,
  type SyncOutcome,
} from '@/services/csaf-mirror/csaf-mirror-service.js';

/**
 * Initialize the logger for console output and build the mirror service from
 * env config, logging the index path it resolved.
 *
 * The logger buffers every record until `initialize()` resolves, so a CLI that
 * skips this step runs correctly and prints nothing — which for a multi-minute
 * index build is indistinguishable from a hang. `'http'` is the transport
 * argument because these scripts own stdout; under `'stdio'` it is reserved for
 * the MCP protocol stream.
 *
 * The mirror is built regardless of `CISA_CSAF_MIRROR_AUTO_INIT` — that flag
 * gates the server's in-process background seed, not out-of-band construction.
 */
export async function getMirror(): Promise<CsafMirrorService> {
  const config = getServerConfig();
  await logger.initialize('info', 'http');
  logger.info(`ICS advisory index: ${config.csafMirrorPath}`);
  return initCsafMirror({
    mirrorPath: config.csafMirrorPath,
    timeoutMs: config.httpTimeoutMs,
  });
}

/**
 * Pass a sync that ran through; for one the lease skipped — a server or another
 * script is already syncing this index — log it and exit 0: the index is being
 * brought current, just not by this run.
 */
export async function exitIfSkipped(
  mirror: CsafMirrorService,
  outcome: SyncOutcome,
): Promise<Extract<SyncOutcome, { ran: true }>> {
  if (outcome.ran) return outcome;
  logger.warning(
    `ICS advisory mirror ${outcome.mode} not run: another process is already syncing this index. Re-run once it finishes, or check its state with mirror:verify.`,
  );
  await mirror.close();
  process.exit(0);
}
