/**
 * @fileoverview ICS advisory mirror service — the read path over the local SQLite
 * index of the CSAF corpus. Built on the framework MirrorService: it owns the
 * store and the ingester, exposes the mirror instance to the lifecycle CLI and
 * the refresh scheduler, and translates the search tool's filters into SQL.
 *
 * The generic `mirror.query()` cannot express two of this surface's filters —
 * substring matching over the unnormalized vendor and product labels, and exact
 * membership in the CVE and sector junction tables — so the read path goes
 * through the raw-handle escape hatch. Scanning a delimited text column for
 * either is both slow and wrong: `Water` is a substring of `Wastewater`.
 *
 * There is no live fallback. The corpus exists upstream only as 3,926 individual
 * files, so fanning out per query is not a serving strategy; a never-seeded
 * mirror is a typed retryable error, because an empty result would assert that
 * nothing matches when the index simply does not exist yet.
 * @module services/csaf-mirror/csaf-mirror-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import {
  defineMirror,
  type Mirror,
  type MirrorStore,
  type SqlValue,
  sqliteMirrorStore,
} from '@cyanheads/mcp-ts-core/mirror';
import type { SeverityBand } from '@/reference/cvss.js';
import type { SectorName } from '@/reference/sectors.js';
import { createCsafIngester } from './ingest.js';
import { toFtsMatch } from './normalize.js';
import {
  ADVISORIES_FTS,
  ADVISORIES_TABLE,
  ADVISORY_CVES_TABLE,
  ADVISORY_SECTORS_TABLE,
  advisoryStoreSpec,
} from './schema.js';
import type {
  AdvisorySearchFilters,
  AdvisorySearchPage,
  AdvisorySearchResult,
  AdvisorySeries,
  CsafMirrorState,
  NormalizedAdvisory,
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

function splitList(value: string | null): string[] {
  return value ? value.split(' | ').filter((part) => part.trim() !== '') : [];
}

export class CsafMirrorService {
  private coverage: AdvisoryCoverage | undefined;
  private readonly mirror: Mirror;
  private readonly path: string;
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

  /** The underlying mirror — for the lifecycle CLI and the refresh scheduler. */
  get mirrorInstance(): Mirror {
    return this.mirror;
  }

  /** `true` once a full sync has ever completed; stays true during and after a refresh. */
  ready(): Promise<boolean> {
    return this.mirror.ready();
  }

  /**
   * In-process state for `cisa_list_reference` topic `sources`. A store that
   * cannot be opened at all — no index file yet, or no SQLite driver on this
   * runtime — reports as not ready rather than failing the call: that topic is
   * the routing target agents are sent to precisely when the mirror is the thing
   * going wrong.
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
        path: this.path,
      };
    } catch {
      return {
        ready: false,
        documentCount: null,
        checkpoint: null,
        syncStatus: 'unavailable',
        lastCompletedAt: null,
        path: this.path,
      };
    }
  }

  /** Seed the index in the background when it has never completed a sync. */
  async autoInit(): Promise<void> {
    if (await this.ready()) return;
    await this.mirror.runSync({ mode: 'init', signal: AbortSignal.timeout(3_600_000) });
  }

  /**
   * Corpus-wide coverage counts, computed once per process. They back the
   * sector- and score-filter disclosures, which would otherwise hardcode numbers
   * that drift as the corpus grows.
   */
  async coverageCounts(): Promise<AdvisoryCoverage> {
    if (this.coverage) return this.coverage;
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
    this.coverage = {
      total: row?.total ?? 0,
      noSector: row?.noSector ?? 0,
      v2Only: row?.v2Only ?? 0,
      noCvss: row?.noCvss ?? 0,
    };
    return this.coverage;
  }

  /** Search the index. Filters AND together and are applied against the whole corpus. */
  async search(filters: AdvisorySearchFilters, ctx: Context): Promise<AdvisorySearchPage> {
    const handle = await this.store.raw();
    const where: string[] = [];
    const params: SqlValue[] = [];

    const match = filters.q ? toFtsMatch(filters.q) : '';
    const useFts = match !== '';
    if (useFts) {
      where.push(`${ADVISORIES_FTS} MATCH ?`);
      params.push(match);
    }
    if (filters.vendor) {
      where.push('LOWER(a.vendorsText) LIKE ?');
      params.push(`%${filters.vendor.toLowerCase()}%`);
    }
    if (filters.product) {
      where.push('LOWER(a.productsText) LIKE ?');
      params.push(`%${filters.product.toLowerCase()}%`);
    }
    if (filters.cve) {
      where.push(`a.advisoryId IN (SELECT advisoryId FROM ${ADVISORY_CVES_TABLE} WHERE cve = ?)`);
      params.push(filters.cve.toUpperCase());
    }
    if (filters.sector) {
      where.push(
        `a.advisoryId IN (SELECT advisoryId FROM ${ADVISORY_SECTORS_TABLE} WHERE sector = ?)`,
      );
      params.push(filters.sector);
    }
    if (filters.cvssMin !== undefined) {
      where.push('a.maxCvss >= ?');
      params.push(filters.cvssMin);
    }
    if (filters.cvssMax !== undefined) {
      where.push('a.maxCvss <= ?');
      params.push(filters.cvssMax);
    }
    if (filters.severity) {
      where.push('a.maxCvssSeverity = ?');
      params.push(filters.severity);
    }
    if (filters.series) {
      where.push('a.series = ?');
      params.push(filters.series);
    }
    if (filters.publisher) {
      where.push('a.publisherCategory = ?');
      params.push(filters.publisher);
    }
    if (filters.publishedFrom) {
      where.push('substr(a.published, 1, 10) >= ?');
      params.push(filters.publishedFrom);
    }
    if (filters.publishedTo) {
      where.push('substr(a.published, 1, 10) <= ?');
      params.push(filters.publishedTo);
    }
    if (filters.revisedFrom) {
      where.push('substr(a.revised, 1, 10) >= ?');
      params.push(filters.revisedFrom);
    }
    if (filters.revisedTo) {
      where.push('substr(a.revised, 1, 10) <= ?');
      params.push(filters.revisedTo);
    }

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
      items: rows.map((row) => this.toSearchResult(row, cveMap.get(row.advisoryId) ?? [])),
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
        `SELECT advisoryId FROM ${ADVISORIES_TABLE} WHERE advisoryId LIKE ? ORDER BY advisoryId LIMIT ?`,
      )
      .all(`${prefix.toUpperCase()}%`, limit);
    return rows.map((row) => row.advisoryId);
  }

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
      if (list.length < CVE_PREVIEW) list.push(row.cve);
    }
    return map;
  }

  private toSearchResult(row: SearchRow, cves: string[]): AdvisorySearchResult {
    const version = row.maxCvssVersion ?? '';
    return {
      advisoryId: row.advisoryId,
      title: row.title ?? '',
      series: (row.series === 'ICSMA' ? 'ICSMA' : 'ICSA') as AdvisorySeries,
      vendors: splitList(row.vendorsText).slice(0, VENDOR_PREVIEW),
      vendorCount: row.vendorCount ?? 0,
      productCount: row.productCount ?? 0,
      cves,
      cveCount: row.cveCount ?? 0,
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
 * Close the mirror's SQLite handle if one was ever constructed. A no-op
 * otherwise: `teardown()` also runs on the startup-failure rollback path, where
 * throwing "not initialized" would bury the real configuration error.
 */
export async function closeCsafMirror(): Promise<void> {
  await _service?.mirrorInstance.close();
}

/** Reset the singleton — test-only. */
export function resetCsafMirror(): void {
  _service = undefined;
}
