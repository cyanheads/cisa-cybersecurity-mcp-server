/**
 * @fileoverview ICS advisory mirror service — the read path over the local SQLite
 * index of the CSAF corpus. Built on the framework MirrorService: it owns the
 * store and the ingester, runs every seed and refresh under a cross-process
 * lease, classifies a store it cannot open, and translates the search tool's
 * filters into SQL.
 *
 * The generic `mirror.query()` cannot express two of this surface's filters —
 * substring matching over the unnormalized vendor and product labels, and exact
 * membership in the CVE, sector, and CWE junction tables — so the read path goes
 * through the raw-handle escape hatch. Scanning a delimited text column for
 * either is both slow and wrong: `Water` is a substring of `Wastewater`.
 *
 * There is no live fallback. The corpus exists upstream only as thousands of
 * individual files, so fanning out per query is not a serving strategy; a never-seeded
 * mirror is a typed retryable error, because an empty result would assert that
 * nothing matches when the index simply does not exist yet.
 * @module services/csaf-mirror/csaf-mirror-service
 */

import { randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import type { Context } from '@cyanheads/mcp-ts-core';
import {
  defineMirror,
  type Mirror,
  type MirrorStore,
  type SqlValue,
  type SyncMode,
  type SyncResult,
  sqliteMirrorStore,
} from '@cyanheads/mcp-ts-core/mirror';
import { logger } from '@cyanheads/mcp-ts-core/utils';
import type { SeverityBand } from '@/reference/cvss.js';
import type { SectorName } from '@/reference/sectors.js';
import { assertSearchTextLength } from '@/services/search-text.js';
import { createCsafIngester, INGEST_CONTENT_VERSION, readIngestContentVersion } from './ingest.js';
import { toFtsMatch, toSubstringGlob } from './normalize.js';
import {
  ADVISORIES_FTS,
  ADVISORIES_TABLE,
  ADVISORY_CVES_TABLE,
  ADVISORY_CWES_TABLE,
  ADVISORY_SECTORS_TABLE,
  advisoryStoreSpec,
} from './schema.js';
import {
  claimSyncLease,
  releaseSyncLease,
  renewSyncLease,
  SYNC_LEASE_RENEW_MS,
} from './sync-lease.js';
import type {
  AdvisoryFilterCount,
  AdvisoryFilterKey,
  AdvisorySearchFilters,
  AdvisorySearchPage,
  AdvisorySearchResult,
  AdvisorySeries,
  CsafMirrorState,
  IngestContentState,
  NormalizedAdvisory,
  StoreUnavailableReason,
} from './types.js';

/** Vendors listed inline on a search result before only the count is reported. */
const VENDOR_PREVIEW = 10;

/** CVEs listed inline on a search result before only the count is reported. */
const CVE_PREVIEW = 20;

/** Coverage counts the search tool discloses when a sector or score filter is set. */
export interface AdvisoryCoverage {
  noCvss: number;
  noSector: number;
  total: number;
  v2Only: number;
}

/** Columns the search projection reads. `document` is deliberately not among them. */
const SEARCH_COLUMNS = [
  'advisoryId',
  'series',
  'title',
  'vendorsText',
  'vendorCount',
  'productCount',
  'cveCount',
  'maxCvss',
  'maxCvssSeverity',
  'maxCvssVersion',
  'sectorsText',
  'sectorsRaw',
  'published',
  'revised',
  'revision',
  'publisherCategory',
  'url',
  'csafUrl',
  'attribution',
]
  .map((column) => `a.${column}`)
  .join(', ');

interface SearchRow {
  advisoryId: string;
  attribution: string | null;
  csafUrl: string | null;
  cveCount: number | null;
  maxCvss: number | null;
  maxCvssSeverity: string | null;
  maxCvssVersion: string | null;
  productCount: number | null;
  published: string | null;
  publisherCategory: string | null;
  revised: string | null;
  revision: string | null;
  sectorsRaw: string | null;
  sectorsText: string | null;
  series: string | null;
  title: string | null;
  url: string | null;
  vendorCount: number | null;
  vendorsText: string | null;
}

/** Options for {@link initCsafMirror}. */
export interface CsafMirrorOptions {
  /** Filesystem path to the SQLite index. */
  mirrorPath: string;
  /** Per-request upstream timeout in milliseconds. */
  timeoutMs: number;
}

/** Whether the index can serve a read right now. */
export type IndexAvailability =
  | { status: 'ready' }
  | { status: 'not_ready' }
  | { status: 'unavailable'; reason: StoreUnavailableReason };

/** One sync attempt: run to completion, or skipped because a sync was already running. */
export type SyncOutcome =
  | { mode: SyncMode; ran: true; result: SyncResult }
  | { mode: SyncMode; ran: false; reason: 'in_progress' | 'lease_held' };

const noop = (): void => {};

/** Every string `code` on an error and its `cause` chain — errno, SQLite, or neither. */
function errorCodes(error: unknown): string[] {
  const codes: string[] = [];
  let current: unknown = error;
  for (let depth = 0; depth < 4 && current instanceof Error; depth += 1) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === 'string') codes.push(code);
    current = current.cause;
  }
  return codes;
}

/**
 * Classify a failure to open the index store. The framework raises it in three
 * shapes — the raw `mkdir` errno, a `DatabaseError` whose cause is the driver's
 * error, and a raw SQLite error from the connection pragmas — so every code on
 * the cause chain is read. `undefined` for anything that is not a known open
 * failure (a busy lock, an abort, a bug), which callers must not report as
 * misconfiguration.
 */
export function classifyStoreOpenFailure(error: unknown): StoreUnavailableReason | undefined {
  for (const code of errorCodes(error)) {
    if (code === 'EROFS' || code.startsWith('SQLITE_READONLY')) return 'read_only';
    if (
      code === 'EACCES' ||
      code === 'EPERM' ||
      code === 'SQLITE_CANTOPEN' ||
      code === 'SQLITE_PERM'
    )
      return 'not_writable';
    if (code === 'ENOENT') return 'missing_directory';
    /* `mkdir -p` reports EEXIST when a path component is a regular file. */
    if (code === 'ENOTDIR' || code === 'EEXIST') return 'not_a_directory';
    if (code === 'SQLITE_NOTADB') return 'not_a_database';
  }
  return;
}

function splitList(value: string | null): string[] {
  return value ? value.split(' | ').filter((part) => part.trim() !== '') : [];
}

/** One applied search filter as a SQL predicate over `ics_advisories a`. */
interface FilterClause {
  filter: AdvisoryFilterKey;
  params: SqlValue[];
  sql: string;
}

/**
 * Every applied filter as its own predicate, in a fixed order. `search()` ANDs
 * them; `filterCounts()` scores each one separately. Both build from this list,
 * so the counts behind a zero-hit notice cannot drift from the search they
 * explain. `q` is written as a rowid subquery over the FTS index; `search()`
 * matches it through a join instead, which bm25 ranking needs, with the same
 * `MATCH` expression.
 */
function filterClauses(
  filters: AdvisorySearchFilters,
  kevCves: ReadonlySet<string> | undefined,
): FilterClause[] {
  const clauses: FilterClause[] = [];
  const add = (filter: AdvisoryFilterKey, sql: string, param: SqlValue) => {
    clauses.push({ filter, sql, params: [param] });
  };

  if (filters.q) {
    add(
      'q',
      `a.rowid IN (SELECT rowid FROM ${ADVISORIES_FTS} WHERE ${ADVISORIES_FTS} MATCH ?)`,
      toFtsMatch(filters.q),
    );
  }
  /* SQLite refuses a GLOB pattern over 50,000 bytes, which a class per non-ASCII
   * letter reaches at about 8,300 characters; the shared ceiling keeps that
   * refusal from ever reaching a caller as a raw SQLite error. */
  if (filters.vendor) {
    assertSearchTextLength(filters.vendor, 'vendor');
    add('vendor', 'LOWER(a.vendorsText) GLOB ?', toSubstringGlob(filters.vendor));
  }
  if (filters.product) {
    assertSearchTextLength(filters.product, 'product');
    add('product', 'LOWER(a.productsText) GLOB ?', toSubstringGlob(filters.product));
  }
  if (filters.cve) {
    add(
      'cve',
      `a.advisoryId IN (SELECT advisoryId FROM ${ADVISORY_CVES_TABLE} WHERE cve = ?)`,
      filters.cve,
    );
  }
  if (filters.sector) {
    add(
      'sector',
      `a.advisoryId IN (SELECT advisoryId FROM ${ADVISORY_SECTORS_TABLE} WHERE sector = ?)`,
      filters.sector,
    );
  }
  if (filters.cwe) {
    add(
      'cwe',
      `a.advisoryId IN (SELECT advisoryId FROM ${ADVISORY_CWES_TABLE} WHERE cweId = ?)`,
      filters.cwe,
    );
  }
  if (filters.inKev !== undefined) {
    if (!kevCves) throw new Error('search(): the inKev filter needs the KEV CVE set.');
    add(
      'inKev',
      `a.advisoryId ${filters.inKev ? 'IN' : 'NOT IN'} (SELECT advisoryId FROM ${ADVISORY_CVES_TABLE} WHERE cve IN (SELECT value FROM json_each(?)))`,
      JSON.stringify([...kevCves]),
    );
  }
  if (filters.cvssMin !== undefined) add('cvssMin', 'a.maxCvss >= ?', filters.cvssMin);
  if (filters.cvssMax !== undefined) add('cvssMax', 'a.maxCvss <= ?', filters.cvssMax);
  if (filters.severity) add('severity', 'a.maxCvssSeverity = ?', filters.severity);
  if (filters.series) add('series', 'a.series = ?', filters.series);
  if (filters.publisher) add('publisher', 'a.publisherCategory = ?', filters.publisher);
  if (filters.publishedFrom) {
    add('publishedFrom', 'substr(a.published, 1, 10) >= ?', filters.publishedFrom);
  }
  if (filters.publishedTo)
    add('publishedTo', 'substr(a.published, 1, 10) <= ?', filters.publishedTo);
  if (filters.revisedFrom) add('revisedFrom', 'substr(a.revised, 1, 10) >= ?', filters.revisedFrom);
  if (filters.revisedTo) add('revisedTo', 'substr(a.revised, 1, 10) <= ?', filters.revisedTo);
  return clauses;
}

/**
 * Escape `\`, `%`, and `_` for a `LIKE … ESCAPE '\'` pattern, so caller text
 * matches literally — an advisory-ID prefix of `ICSA_25` must not match
 * `ICSA-25`. The `vendor` and `product` filters match through GLOB instead
 * ({@link toSubstringGlob}), which has no `%` or `_` wildcard.
 */
function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, '\\$&');
}

export class CsafMirrorService {
  /** The last coverage scan and the sync completion it was taken after. */
  private coverage: { counts: AdvisoryCoverage; syncedAt: string | null } | undefined;
  private readonly mirror: Mirror;
  /** This instance's identity in the sync lease row. */
  private readonly owner = `${hostname()}/${process.pid}/${randomUUID().slice(0, 8)}`;
  /** Server-log use only — no caller-facing text carries the index path. */
  private readonly path: string;
  /** The sync this instance is running, if any, and how to stop it. */
  private running: { controller: AbortController; settled: Promise<void> } | undefined;
  private readonly store: MirrorStore;

  constructor(options: CsafMirrorOptions) {
    this.path = options.mirrorPath;
    this.store = sqliteMirrorStore(advisoryStoreSpec(options.mirrorPath));
    this.mirror = defineMirror({
      name: 'cisa-ics-advisories',
      store: this.store,
      sync: createCsafIngester({
        getHandle: () => this.store.raw(),
        timeoutMs: options.timeoutMs,
      }),
    });
  }

  /**
   * The underlying mirror — for `mirror:verify`'s status and integrity reads,
   * and for test setup. Syncing through it bypasses the cross-process lease;
   * production code syncs through {@link sync}.
   */
  get mirrorInstance(): Mirror {
    return this.mirror;
  }

  /** `true` once a full sync has ever completed; stays true during and after a refresh. */
  ready(): Promise<boolean> {
    return this.mirror.ready();
  }

  /**
   * Whether the index can serve a read. A store that cannot be opened at all is
   * `unavailable` with the classified reason — an operator fix, not a wait —
   * distinct from an openable index that has never completed a sync. An open
   * failure this cannot classify rethrows rather than being reported as
   * misconfiguration.
   */
  async availability(): Promise<IndexAvailability> {
    try {
      return (await this.mirror.ready()) ? { status: 'ready' } : { status: 'not_ready' };
    } catch (error) {
      const reason = classifyStoreOpenFailure(error);
      if (!reason) throw error;
      return { status: 'unavailable', reason };
    }
  }

  /**
   * In-process state for `cisa_list_reference` topic `sources`. A store that
   * cannot be opened at all — an unwritable path, or no SQLite driver on this
   * runtime — reports as unavailable rather than failing the call, with the
   * reason when it can be classified: that topic is the routing target agents
   * are sent to precisely when the mirror is the thing going wrong.
   */
  async state(): Promise<CsafMirrorState> {
    try {
      const status = await this.mirror.status();
      return {
        ready: status.ready,
        documentCount: status.total ?? null,
        checkpoint: status.checkpoint ?? null,
        syncStatus: status.status,
        lastCompletedAt: status.completedAt ?? null,
      };
    } catch (error) {
      const reason = classifyStoreOpenFailure(error);
      return {
        ready: false,
        documentCount: null,
        checkpoint: null,
        syncStatus: 'unavailable',
        lastCompletedAt: null,
        ...(reason ? { unavailableReason: reason } : {}),
      };
    }
  }

  /** Which ingest build the index content comes from — see {@link IngestContentState}. */
  async contentState(): Promise<IngestContentState> {
    const stored = readIngestContentVersion(await this.store.raw());
    return {
      current: INGEST_CONTENT_VERSION,
      stored,
      stale: stored === null || stored < INGEST_CONTENT_VERSION,
    };
  }

  /**
   * One maintenance pass — what boot and the scheduled job both run. An index
   * that has never completed a sync, or whose content an older ingest built,
   * gets an `init` when `autoInit` allows it and nothing otherwise, so a refresh
   * never runs against a never-synced store (on an empty store the manifest diff
   * marks every document changed and fetches each one individually). A synced,
   * content-current index gets a `refresh` when `refresh` allows it.
   *
   * The re-ingest is a full `init` over the populated index: it upserts in
   * place, so `ready()` stays true and every existing row keeps serving until
   * its replacement lands, and the new content version is recorded only once the
   * whole archive has been applied. An interrupted re-ingest leaves the version
   * stale, so the next pass runs it again. A store that cannot be opened is
   * logged — with its path, which never reaches a caller — and skipped.
   */
  async maintain(options: {
    autoInit: boolean;
    refresh: boolean;
  }): Promise<SyncOutcome | undefined> {
    const availability = await this.availability();
    if (availability.status === 'unavailable') {
      logger.warning(
        `ICS advisory index at ${this.path} cannot be opened (${availability.reason}); the ICS tools report mirror_unavailable until CISA_CSAF_MIRROR_PATH names a writable location.`,
      );
      return;
    }
    if (availability.status === 'not_ready' || (await this.contentState()).stale) {
      return options.autoInit ? this.sync('init', AbortSignal.timeout(3_600_000)) : undefined;
    }
    return options.refresh ? this.sync('refresh', AbortSignal.timeout(1_800_000)) : undefined;
  }

  /** Seed a never-synced index or re-ingest a content-stale one; no refresh. */
  autoInit(): Promise<SyncOutcome | undefined> {
    return this.maintain({ autoInit: true, refresh: false });
  }

  /**
   * Run one sync under the cross-process lease. Returns `ran: false` — after a
   * log line, and without touching upstream — when this process is already
   * syncing or another process holds a live lease on the same index; a caller at
   * boot or on a schedule simply skips. The lease is renewed while the sync runs,
   * and a renewal that finds it taken over aborts the sync.
   */
  async sync(mode: SyncMode, signal: AbortSignal): Promise<SyncOutcome> {
    if (this.running) {
      logger.info(`ICS advisory index ${mode} skipped: a sync is already running in this process.`);
      return { ran: false, mode, reason: 'in_progress' };
    }
    const controller = new AbortController();
    const run = this.runLeased(mode, AbortSignal.any([signal, controller.signal]), controller);
    const running = { controller, settled: run.then(noop, noop) };
    this.running = running;
    try {
      return await run;
    } finally {
      if (this.running === running) this.running = undefined;
    }
  }

  /**
   * Abort an in-flight sync, wait for it to release its lease, then close the
   * store. Runs from `teardown()` on every shutdown path, so a stdio process that
   * exits mid-refresh does not leave its lease to block the next one for a TTL.
   */
  async close(): Promise<void> {
    const running = this.running;
    if (running) {
      running.controller.abort(new Error('The ICS advisory index is closing.'));
      await running.settled;
    }
    await this.mirror.close();
  }

  private async runLeased(
    mode: SyncMode,
    signal: AbortSignal,
    controller: AbortController,
  ): Promise<SyncOutcome> {
    const handle = await this.store.raw();
    const claim = claimSyncLease(handle, this.owner, mode);
    if (!claim.acquired) {
      logger.info(
        `ICS advisory index ${mode} skipped: another process holds the ICS advisory index sync lease (${claim.holder.mode}) until ${new Date(claim.holder.expiresAt).toISOString()}; reads of the shared index are unaffected.`,
      );
      return { ran: false, mode, reason: 'lease_held' };
    }

    const renewal = setInterval(() => {
      try {
        if (!renewSyncLease(handle, this.owner, mode)) {
          controller.abort(
            new Error(
              'The ICS advisory index sync lease lapsed and another process took it over; this sync stopped.',
            ),
          );
        }
      } catch (error) {
        /* A busy database is transient; the next renewal retries well inside the TTL. */
        logger.warning(
          `Could not renew the ICS advisory index sync lease: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }, SYNC_LEASE_RENEW_MS);
    renewal.unref();

    try {
      const result = await this.mirror.runSync({ mode, signal });
      return { ran: true, mode, result };
    } finally {
      clearInterval(renewal);
      try {
        releaseSyncLease(handle, this.owner);
      } catch (error) {
        /* Left in place, the lease expires within one TTL. */
        logger.warning(
          `Could not release the ICS advisory index sync lease: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  /**
   * Corpus-wide coverage counts behind the sector- and score-filter disclosures,
   * which would otherwise hardcode numbers that drift as the corpus grows. The
   * scan is kept until a sync completes: the memo is keyed on the completion
   * time the index itself records, so a sync by this process, another server
   * process, or a mirror script all replace it without a restart.
   */
  async coverageCounts(): Promise<AdvisoryCoverage> {
    const syncedAt = (await this.mirror.status()).completedAt ?? null;
    if (this.coverage?.syncedAt === syncedAt) return this.coverage.counts;
    const handle = await this.store.raw();
    const row = handle
      .prepare<{ noCvss: number; noSector: number; total: number; v2Only: number }>(
        `SELECT COUNT(*) AS total,
                SUM(CASE WHEN sectorsRaw IS NULL OR sectorsRaw = '' THEN 1 ELSE 0 END) AS noSector,
                SUM(CASE WHEN maxCvssVersion LIKE '2%' THEN 1 ELSE 0 END) AS v2Only,
                SUM(CASE WHEN maxCvss IS NULL THEN 1 ELSE 0 END) AS noCvss
         FROM ${ADVISORIES_TABLE}`,
      )
      .get();
    const counts = {
      total: row?.total ?? 0,
      noSector: row?.noSector ?? 0,
      v2Only: row?.v2Only ?? 0,
      noCvss: row?.noCvss ?? 0,
    };
    this.coverage = { syncedAt, counts };
    return counts;
  }

  /**
   * Score each applied filter against the whole index in one query: how many
   * advisories it matches on its own, and how many fail it and nothing else —
   * what dropping it would restore. Backs the zero-hit notice, which asks for it
   * only after a search came back empty.
   *
   * One scan of `ics_advisories`: each predicate is evaluated once per row into
   * a materialized flag column, and the junction, FTS, and KEV subqueries are
   * each built once as a list. Without `MATERIALIZED` the planner flattens the
   * flags into every aggregate that reads them, evaluating the text matches once
   * per sum. A predicate that reads NULL — no CVSS score, no vendor text —
   * counts as a miss, as it does in the search.
   */
  async filterCounts(
    filters: AdvisorySearchFilters,
    kevCves?: ReadonlySet<string>,
  ): Promise<AdvisoryFilterCount[]> {
    const clauses = filterClauses(filters, kevCves);
    if (clauses.length === 0) return [];
    const handle = await this.store.raw();
    const flags = clauses.map((clause, i) => `COALESCE((${clause.sql}), 0) AS f${i}`);
    const passed = clauses.map((_, i) => `f${i}`).join(' + ');
    const sums = clauses.flatMap((_, i) => [
      `SUM(f${i}) AS alone${i}`,
      `SUM(f${i} = 0 AND ${passed} = ${clauses.length - 1}) AS restored${i}`,
    ]);
    const row = handle
      .prepare<Record<string, number | null>>(
        `WITH flags AS MATERIALIZED (SELECT ${flags.join(', ')} FROM ${ADVISORIES_TABLE} a)
         SELECT ${sums.join(', ')} FROM flags`,
      )
      .get(...clauses.flatMap((clause) => clause.params));
    return clauses.map((clause, i) => ({
      filter: clause.filter,
      alone: row?.[`alone${i}`] ?? 0,
      restoredByDropping: row?.[`restored${i}`] ?? 0,
    }));
  }

  /**
   * Search the index. Filters AND together and are applied against the whole
   * corpus.
   *
   * `kevCves` is the KEV catalog's CVE set. When it is passed, every result
   * carries `kevCves` — drawn from the advisory's complete `advisory_cves`
   * membership, not the capped preview — and `filters.inKev` is evaluated in
   * SQL against it, so paging and the total stay correct. The set is bound as
   * one JSON array read through `json_each`: a single parameter, no
   * bound-variable ceiling, and no connection-scoped temp table.
   */
  async search(
    filters: AdvisorySearchFilters,
    ctx: Context,
    kevCves?: ReadonlySet<string>,
  ): Promise<AdvisorySearchPage> {
    const handle = await this.store.raw();
    const clauses = filterClauses(filters, kevCves);
    const useFts = clauses.some((clause) => clause.filter === 'q');
    const where = clauses.map((clause) =>
      clause.filter === 'q' ? `${ADVISORIES_FTS} MATCH ?` : clause.sql,
    );
    const params = clauses.flatMap((clause) => clause.params);

    const join = useFts ? `JOIN ${ADVISORIES_FTS} ON ${ADVISORIES_FTS}.rowid = a.rowid` : '';
    const clause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
    const direction = filters.order === 'asc' ? 'ASC' : 'DESC';
    const orderBy =
      filters.sortBy === 'relevance'
        ? /* bm25 is a distance, so "most relevant first" is ascending. */
          `bm25(${ADVISORIES_FTS}) ${filters.order === 'asc' ? 'DESC' : 'ASC'}`
        : filters.sortBy === 'maxCvss'
          ? `a.maxCvss IS NULL, a.maxCvss ${direction}`
          : `a.${filters.sortBy} ${direction}`;

    ctx.log.debug('Searching the ICS advisory index', {
      filters: where.length,
      sortBy: filters.sortBy,
      limit: filters.limit,
      offset: filters.offset,
    });

    const totalRow = handle
      .prepare<{ n: number }>(`SELECT COUNT(*) AS n FROM ${ADVISORIES_TABLE} a ${join} ${clause}`)
      .get(...params);

    const rows = handle
      .prepare<SearchRow>(
        `SELECT ${SEARCH_COLUMNS} FROM ${ADVISORIES_TABLE} a ${join} ${clause}
         ORDER BY ${orderBy}, a.advisoryId ASC
         LIMIT ? OFFSET ?`,
      )
      .all(...params, filters.limit, filters.offset);

    const cveMap = this.readCves(
      handle,
      rows.map((row) => row.advisoryId),
    );

    return {
      total: totalRow?.n ?? 0,
      items: rows.map((row) => this.toSearchResult(row, cveMap.get(row.advisoryId) ?? [], kevCves)),
    };
  }

  /** Read one normalized advisory by ID, or `undefined` when the index has no such row. */
  async getAdvisory(advisoryId: string): Promise<NormalizedAdvisory | undefined> {
    const handle = await this.store.raw();
    const row = handle
      .prepare<{ document: string | null }>(
        `SELECT document FROM ${ADVISORIES_TABLE} WHERE advisoryId = ?`,
      )
      .get(advisoryId);
    if (!row?.document) return undefined;
    return JSON.parse(row.document) as NormalizedAdvisory;
  }

  /**
   * The most recently revised advisories as `{ advisoryId, title }` — backs the
   * resource listing, which runs without a request context.
   */
  async recentlyRevised(limit: number): Promise<Array<{ advisoryId: string; title: string }>> {
    const handle = await this.store.raw();
    const rows = handle
      .prepare<{ advisoryId: string; title: string | null }>(
        `SELECT advisoryId, title FROM ${ADVISORIES_TABLE} ORDER BY revised DESC LIMIT ?`,
      )
      .all(limit);
    return rows.map((row) => ({ advisoryId: row.advisoryId, title: row.title ?? '' }));
  }

  /** Advisory IDs matching a prefix — backs resource-template argument completion. */
  async completeAdvisoryIds(prefix: string, limit: number): Promise<string[]> {
    const handle = await this.store.raw();
    const rows = handle
      .prepare<{ advisoryId: string }>(
        `SELECT advisoryId FROM ${ADVISORIES_TABLE} WHERE advisoryId LIKE ? ESCAPE '\\' ORDER BY advisoryId LIMIT ?`,
      )
      .all(`${escapeLike(prefix.toUpperCase())}%`, limit);
    return rows.map((row) => row.advisoryId);
  }

  /** Every CVE of each page advisory, alphabetically — the preview is cut from it later. */
  private readCves(
    handle: Awaited<ReturnType<MirrorStore['raw']>>,
    advisoryIds: string[],
  ): Map<string, string[]> {
    const map = new Map<string, string[]>();
    if (advisoryIds.length === 0) return map;
    const placeholders = advisoryIds.map(() => '?').join(', ');
    const rows = handle
      .prepare<{ advisoryId: string; cve: string }>(
        `SELECT advisoryId, cve FROM ${ADVISORY_CVES_TABLE}
         WHERE advisoryId IN (${placeholders}) ORDER BY advisoryId, cve`,
      )
      .all(...advisoryIds);
    for (const row of rows) {
      const list = map.get(row.advisoryId) ?? [];
      map.set(row.advisoryId, list);
      list.push(row.cve);
    }
    return map;
  }

  private toSearchResult(
    row: SearchRow,
    cves: string[],
    kevCves: ReadonlySet<string> | undefined,
  ): AdvisorySearchResult {
    const version = row.maxCvssVersion ?? '';
    return {
      advisoryId: row.advisoryId,
      title: row.title ?? '',
      series: (row.series === 'ICSMA' ? 'ICSMA' : 'ICSA') as AdvisorySeries,
      vendors: splitList(row.vendorsText).slice(0, VENDOR_PREVIEW),
      vendorCount: row.vendorCount ?? 0,
      productCount: row.productCount ?? 0,
      cves: cves.slice(0, CVE_PREVIEW),
      cveCount: row.cveCount ?? 0,
      ...(kevCves ? { kevCves: cves.filter((cve) => kevCves.has(cve)) } : {}),
      ...(row.maxCvss !== null && row.maxCvssSeverity
        ? {
            maxCvss: {
              score: row.maxCvss,
              severity: row.maxCvssSeverity as SeverityBand,
              version,
              severityDerived: version.startsWith('2'),
            },
          }
        : {}),
      sectors: splitList(row.sectorsText) as SectorName[],
      ...(row.sectorsRaw ? { sectorsRaw: row.sectorsRaw } : {}),
      published: row.published ?? '',
      revised: row.revised ?? '',
      revision: row.revision ?? '',
      publisherCategory: row.publisherCategory ?? '',
      url: row.url ?? '',
      csafUrl: row.csafUrl ?? '',
      attribution: row.attribution ?? '',
    };
  }
}

// --- Init/accessor pattern ---

let _service: CsafMirrorService | undefined;

/** Construct the advisory mirror service. Call once from `createApp`'s `setup()`. */
export function initCsafMirror(options: CsafMirrorOptions): CsafMirrorService {
  _service = new CsafMirrorService(options);
  return _service;
}

/** Access the initialized advisory mirror service. */
export function getCsafMirror(): CsafMirrorService {
  if (!_service) {
    throw new Error('CsafMirrorService not initialized — call initCsafMirror() in setup().');
  }
  return _service;
}

/**
 * Stop any in-flight sync and close the mirror's SQLite handle, if a service was
 * ever constructed. A no-op otherwise: `teardown()` also runs on the
 * startup-failure rollback path, where throwing "not initialized" would bury
 * the real configuration error.
 */
export async function closeCsafMirror(): Promise<void> {
  await _service?.close();
}

/** Reset the singleton — test-only. */
export function resetCsafMirror(): void {
  _service = undefined;
}
