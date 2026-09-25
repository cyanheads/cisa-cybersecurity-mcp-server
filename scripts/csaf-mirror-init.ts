#!/usr/bin/env bun
/**
 * @fileoverview mirror:init — full out-of-band build of the ICS advisory index.
 * Streams the CSAF repository archive, normalizes every document under the OT
 * distribution, and writes the SQLite index. Idempotent (the framework upserts by
 * primary key), so it is safe to re-run after an interrupt. The server also seeds
 * itself in the background on first run; this script is the explicit-control
 * escape hatch for Docker `exec`, CI, and operators. It takes the sync lease the
 * server takes, so it skips rather than running alongside a server's sync.
 * @module scripts/csaf-mirror-init
 */

import { logger } from '@cyanheads/mcp-ts-core/utils';
import { exitIfSkipped, getMirror } from './_mirror-context.js';

const mirror = await getMirror();
logger.info('Starting ICS advisory mirror init (full build).');

const { result } = await exitIfSkipped(
  mirror,
  await mirror.sync('init', AbortSignal.timeout(3_600_000)),
);

logger.info(
  `ICS advisory mirror init complete: ${result.recordsApplied} advisories applied across ${result.pagesFetched} pages (total ${result.total}).`,
);
await mirror.close();
process.exit(0);
