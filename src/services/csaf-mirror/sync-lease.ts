/**
 * @fileoverview Cross-process sync lease for the ICS advisory index. The
 * framework's `defineMirror` guards `runSync` with an in-process flag only, and
 * under a per-user default index path every stdio session a client launches
 * shares one SQLite file — so two processes could seed or refresh it at once,
 * doubling the upstream fetches and contending for the write lock.
 *
 * The lease is one `mirror_meta` row holding its owner, the sync mode, and an
 * expiry. It is claimed, renewed, and released under `BEGIN IMMEDIATE`, which
 * takes SQLite's write lock before the read, so the check and the write are one
 * atomic step across processes. The holder renews it well inside the TTL while
 * it syncs; a lease whose holder crashed simply expires and the next claim takes
 * it over. Replace with the framework primitive once cyanheads/mcp-ts-core#517
 * ships one.
 * @module services/csaf-mirror/sync-lease
 */

import type { SqliteHandle, SyncMode } from '@cyanheads/mcp-ts-core/mirror';
import { MIRROR_META_TABLE } from './schema.js';

/** How long a claimed lease lives without renewal. Bounds the wait after a holder crashes. */
export const SYNC_LEASE_TTL_MS = 120_000;

/** How often the holder renews — a quarter of the TTL, so three renewals can slip before it lapses. */
export const SYNC_LEASE_RENEW_MS = SYNC_LEASE_TTL_MS / 4;

/** `mirror_meta` key holding the lease. */
const LEASE_KEY = 'sync_lease';

/** The lease row's value. */
export interface SyncLease {
  /** Epoch milliseconds after which another process may take the lease over. */
  expiresAt: number;
  mode: SyncMode;
  /** `<hostname>/<pid>/<random>` — unique per mirror service instance. */
  owner: string;
}

/** The outcome of a claim: acquired, or the live lease that blocked it. */
export type LeaseClaim = { acquired: true } | { acquired: false; holder: SyncLease };

/** Run `fn` inside a `BEGIN IMMEDIATE` transaction on `handle`. */
function immediate<T>(handle: SqliteHandle, fn: () => T): T {
  handle.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    handle.exec('COMMIT');
    return result;
  } catch (error) {
    handle.exec('ROLLBACK');
    throw error;
  }
}

function readLease(handle: SqliteHandle): SyncLease | undefined {
  const row = handle
    .prepare<{ value: string | null }>(`SELECT value FROM ${MIRROR_META_TABLE} WHERE key = ?`)
    .get(LEASE_KEY);
  if (!row?.value) return;
  try {
    return JSON.parse(row.value) as SyncLease;
  } catch {
    /* An unreadable row cannot be honored; treating it as absent lets the next claim replace it. */
    return;
  }
}

function writeLease(handle: SqliteHandle, lease: SyncLease): void {
  handle
    .prepare(
      `INSERT INTO ${MIRROR_META_TABLE} (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    )
    .run(LEASE_KEY, JSON.stringify(lease));
}

/**
 * Claim the lease for `owner`, unless another owner holds one that has not
 * expired. An expired lease — its holder crashed or hung — is taken over.
 */
export function claimSyncLease(handle: SqliteHandle, owner: string, mode: SyncMode): LeaseClaim {
  return immediate(handle, () => {
    const current = readLease(handle);
    if (current && current.owner !== owner && current.expiresAt > Date.now()) {
      return { acquired: false, holder: current };
    }
    writeLease(handle, { owner, mode, expiresAt: Date.now() + SYNC_LEASE_TTL_MS });
    return { acquired: true };
  });
}

/**
 * Push the expiry out for the lease `owner` holds. Returns `false` when the row
 * names another owner or is gone — the lease lapsed and was taken over, so the
 * caller must stop syncing.
 */
export function renewSyncLease(handle: SqliteHandle, owner: string, mode: SyncMode): boolean {
  return immediate(handle, () => {
    if (readLease(handle)?.owner !== owner) return false;
    writeLease(handle, { owner, mode, expiresAt: Date.now() + SYNC_LEASE_TTL_MS });
    return true;
  });
}

/** Drop the lease if `owner` still holds it; a lease taken over by another owner is left alone. */
export function releaseSyncLease(handle: SqliteHandle, owner: string): void {
  immediate(handle, () => {
    if (readLease(handle)?.owner !== owner) return;
    handle.prepare(`DELETE FROM ${MIRROR_META_TABLE} WHERE key = ?`).run(LEASE_KEY);
  });
}
