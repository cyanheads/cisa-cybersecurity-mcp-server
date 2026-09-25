#!/usr/bin/env bun
/**
 * @fileoverview mirror:verify — report the ICS advisory index's health:
 * readiness, sync status, checkpoint, document count, ingest-content version,
 * and a SQLite integrity check. Exits non-zero when the index is not ready or
 * integrity fails, so it can gate a deployment or a post-build smoke check. A
 * stale content version is reported as a warning, not a failure: the index still
 * serves every row it holds, and the server re-ingests it on its next boot.
 * @module scripts/csaf-mirror-verify
 */

import { logger, requestContextService } from '@cyanheads/mcp-ts-core/utils';
import { INGEST_CONTENT_VERSION, readIngestContentVersion } from '@/services/csaf-mirror/ingest.js';
import { getMirror } from './_mirror-context.js';

const context = requestContextService.createRequestContext({ operation: 'mirror:verify' });

const mirror = (await getMirror()).mirrorInstance;
const status = await mirror.status();
const contentVersion = readIngestContentVersion(await mirror.raw());

logger.info(
  `ICS advisory mirror status: ready=${status.ready}, status=${status.status}, total=${status.total ?? 0}, checkpoint=${status.checkpoint ?? 'none'}, completedAt=${status.completedAt ?? 'never'}, contentVersion=${contentVersion ?? 'none'} (current ${INGEST_CONTENT_VERSION})`,
);
if (status.error) logger.warning(`Last sync error: ${status.error}`);

if (!status.ready) {
  logger.error('Mirror is NOT ready — run mirror:init to build the index.', context);
  await mirror.close();
  process.exit(1);
}

if (contentVersion === null || contentVersion < INGEST_CONTENT_VERSION) {
  logger.warning(
    `Index content is STALE — built by ingest-content version ${contentVersion ?? 'none (pre-versioning)'}, current is ${INGEST_CONTENT_VERSION}. It keeps serving its existing rows; the server re-ingests it in the background on its next start (CISA_CSAF_MIRROR_AUTO_INIT=true), or run mirror:init now. mirror:refresh does not clear this.`,
  );
}

const integrity = await mirror.store.integrityCheck();
if (!integrity.ok) {
  logger.error(`SQLite integrity check FAILED: ${integrity.results.join('; ')}`, context);
  await mirror.close();
  process.exit(1);
}

logger.info('ICS advisory mirror integrity check passed.');
await mirror.close();
process.exit(0);
