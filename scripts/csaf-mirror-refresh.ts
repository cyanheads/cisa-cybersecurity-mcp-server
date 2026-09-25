#!/usr/bin/env bun
/**
 * @fileoverview mirror:refresh — incremental refresh of the ICS advisory index.
 * Conditionally fetches the changes.csv manifest, fetches only the documents
 * whose release date moved, and tombstones anything dropped upstream. The index
 * stays transactionally queryable throughout. The server runs the same refresh
 * once at startup and on CISA_CSAF_REFRESH_CRON, on every transport; this script
 * is for CI and operators who drive refreshes themselves with that cron set to
 * `off`. It takes the sync lease the server takes, so it skips rather than
 * running alongside a server's sync.
 * @module scripts/csaf-mirror-refresh
 */

import { logger } from '@cyanheads/mcp-ts-core/utils';
import { exitIfSkipped, getMirror } from './_mirror-context.js';

const mirror = await getMirror();
logger.info('Starting ICS advisory mirror refresh.');

const { result } = await exitIfSkipped(
  mirror,
  await mirror.sync('refresh', AbortSignal.timeout(1_800_000)),
);

logger.info(
  `ICS advisory mirror refresh complete: ${result.recordsApplied} advisories applied, ${result.tombstonesApplied} removed (total ${result.total}).`,
);
await mirror.close();
process.exit(0);
