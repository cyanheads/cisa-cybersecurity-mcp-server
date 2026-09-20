/**
 * @fileoverview Shared bootstrap for the ICS advisory mirror lifecycle CLI
 * scripts (csaf-mirror-init / csaf-mirror-refresh / csaf-mirror-verify). Builds
 * the mirror service from the environment and hands back the underlying mirror —
 * no MCP transport, no tool registration. Imported by the three named scripts, so
 * it travels with them in the npm tarball and the Docker image.
 * @module scripts/_mirror-context
 */

import type { Mirror } from '@cyanheads/mcp-ts-core/mirror';
import { logger } from '@cyanheads/mcp-ts-core/utils';
import { getServerConfig } from '@/config/server-config.js';
import { initCsafMirror } from '@/services/csaf-mirror/csaf-mirror-service.js';

/**
 * Initialize the logger for console output and build the mirror from env config.
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
export async function getMirror(): Promise<Mirror> {
  const config = getServerConfig();
  await logger.initialize('info', 'http');
  return initCsafMirror({
    mirrorPath: config.csafMirrorPath,
    timeoutMs: config.httpTimeoutMs,
  }).mirrorInstance;
}
