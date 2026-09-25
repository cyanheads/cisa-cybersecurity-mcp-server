/**
 * @fileoverview Background data maintenance started from `setup()`: one boot
 * pass over the ICS advisory index and the two refresh cron jobs, on every
 * transport. A stdio server is often a long-lived child of a desktop client, so
 * leaving the schedules to HTTP left its index and KEV snapshot at whatever the
 * first load fetched. Kept out of the entry point so the scheduling rules are
 * testable without starting a transport.
 * @module services/refresh-schedule
 */

import { logger, schedulerService } from '@cyanheads/mcp-ts-core/utils';
import { CRON_OFF } from '@/config/server-config.js';
import type { CsafMirrorService } from '@/services/csaf-mirror/csaf-mirror-service.js';
import type { KevCatalogService } from '@/services/kev-catalog/kev-catalog-service.js';

/** Options for {@link startBackgroundRefresh}. */
export interface BackgroundRefreshOptions {
  /** Seed a never-synced index, or re-ingest a content-stale one. Gates nothing else. */
  csafMirrorAutoInit: boolean;
  /** Cron for the advisory index refresh; `off` disables it and the boot refresh. */
  csafRefreshCron: string;
  kev: Pick<KevCatalogService, 'refresh'>;
  /** Cron for the KEV conditional poll; `off` disables it. */
  kevRefreshCron: string;
  mirror: CsafMirrorService;
}

/**
 * Run the boot pass and register the cron jobs. Boot never waits on it — the
 * entry point discards the promise — and it never rejects: a failed pass is
 * logged, and the index keeps serving whatever it holds.
 *
 * The boot pass is the same `maintain()` the scheduled job runs: a never-synced
 * or content-stale index seeds or re-ingests (under auto-init), a current one
 * refreshes once (unless its cron is off). Running a refresh at boot as well as
 * on the schedule covers the short-lived launch that never reaches a tick.
 */
export async function startBackgroundRefresh(options: BackgroundRefreshOptions): Promise<void> {
  const { kev, mirror } = options;
  const refreshAdvisories = options.csafRefreshCron !== CRON_OFF;

  const boot = mirror
    .maintain({ autoInit: options.csafMirrorAutoInit, refresh: refreshAdvisories })
    .catch((error: unknown) => {
      logger.warning(
        `ICS advisory index boot sync failed; a never-seeded index reports mirror_not_ready, an existing one keeps serving its current rows, and the next scheduled pass retries: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    });

  await Promise.all([
    boot,
    scheduleJob(
      'kev-catalog-refresh',
      options.kevRefreshCron,
      () => kev.refresh(),
      'Conditional refresh of the CISA KEV catalog snapshot',
    ),
    scheduleJob(
      'csaf-mirror-refresh',
      options.csafRefreshCron,
      async () => {
        await mirror.maintain({ autoInit: options.csafMirrorAutoInit, refresh: true });
      },
      'Incremental refresh of the ICS advisory index; seeds it first under auto-init when it has never synced',
    ),
  ]);
}

/**
 * Register and start one cron job unless its expression is `off`. The config
 * schema has already rejected any expression `node-cron` would, so a failure
 * here is the scheduler itself (no Node runtime) and is logged, not fatal.
 */
async function scheduleJob(
  id: string,
  expression: string,
  task: () => Promise<void>,
  description: string,
): Promise<void> {
  if (expression === CRON_OFF) return;
  try {
    await schedulerService.schedule(id, expression, task, description);
    schedulerService.start(id);
  } catch (error: unknown) {
    logger.warning(
      `Could not schedule ${id} (${expression}): ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}
