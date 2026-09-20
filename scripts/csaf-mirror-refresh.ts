#!/usr/bin/env bun
/**
 * @fileoverview mirror:refresh — incremental refresh of the ICS advisory index.
 * Conditionally fetches the changes.csv manifest, fetches only the documents
 * whose release date moved, and tombstones anything dropped upstream. The index
 * stays transactionally queryable throughout. Run out-of-band for stdio
 * deployments; the HTTP server schedules the same sync on CISA_CSAF_REFRESH_CRON.
 * @module scripts/csaf-mirror-refresh
 */

import { logger } from '@cyanheads/mcp-ts-core/utils';
import { getMirror } from './_mirror-context.js';

const mirror = await getMirror();
logger.info('Starting ICS advisory mirror refresh.');

const result = await mirror.runSync({ mode: 'refresh', signal: AbortSignal.timeout(1_800_000) });

logger.info(
  `ICS advisory mirror refresh complete: ${result.recordsApplied} advisories applied, ${result.tombstonesApplied} removed (total ${result.total}).`,
);
await mirror.close();
process.exit(0);
