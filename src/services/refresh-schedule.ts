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
 * entry point owns the promise — and it never rejects: a failed pass is
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
  const signal = mirror.shutdownSignal;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let retryDelayMs = 1000;
  signal.addEventListener('abort', () => clearTimeout(retry), { once: true });

  const maintain = async (refresh: boolean): Promise<void> => {
    if (signal.aborted) return;
    try {
      await mirror.maintain({ autoInit: options.csafMirrorAutoInit, refresh });
    } catch (error: unknown) {
      if (signal.aborted) return;
      logger.warning(
        `ICS advisory index boot sync failed; a never-seeded index reports mirror_not_ready, an existing one keeps serving its current rows, and the next scheduled pass retries: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      /* The recheck below is for a seed skipped under contention. Retrying a seed
       * that failed would re-request the whole archive every few seconds. */
      return;
    }
    if (signal.aborted || !options.csafMirrorAutoInit) return;
    /* A lease may have expired or its holder may have finished. Recheck before
     * seeding, so a completed shared index is reused without another archive. */
    const availability = await mirror.availability().catch(() => undefined);
    if (
      signal.aborted ||
      !availability ||
      availability.status === 'ready' ||
      availability.status === 'unavailable'
    )
      return;
    if (retry) clearTimeout(retry);
    retry = setTimeout(() => {
      void maintain(false);
    }, retryDelayMs);
    retry.unref();
    retryDelayMs = Math.min(retryDelayMs * 2, 5000);
  };

  const boot = maintain(refreshAdvisories);

  await Promise.all([
    boot,
    scheduleJob(
      'kev-catalog-refresh',
      options.kevRefreshCron,
      () => kev.refresh(),
      'Conditional refresh of the CISA KEV catalog snapshot',
      signal,
    ),
    scheduleJob(
      'csaf-mirror-refresh',
      options.csafRefreshCron,
      async () => {
        await maintain(true);
      },
      'Incremental refresh of the ICS advisory index; seeds it first under auto-init when it has never synced',
      signal,
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
  signal: AbortSignal,
): Promise<void> {
  if (expression === CRON_OFF || signal.aborted) return;
  try {
    await schedulerService.schedule(
      id,
      expression,
      async () => {
        if (!signal.aborted) await task();
      },
      description,
    );
    if (signal.aborted) {
      schedulerService.remove(id);
      return;
    }
    schedulerService.start(id);
  } catch (error: unknown) {
    logger.warning(
      `Could not schedule ${id} (${expression}): ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}
