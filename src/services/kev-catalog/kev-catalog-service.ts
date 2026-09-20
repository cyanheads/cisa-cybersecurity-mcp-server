/**
 * @fileoverview KEV catalog service — the Tier 1 storage layer. 1,716 records and
 * 1.74 MB of public, tenant-invariant data sit below the mirror tier's floor, so
 * one process-level snapshot is shared by every request: the parsed records, the
 * feed envelope, and the derived indexes (`Map<cveId>`, plus arrays sorted by
 * `dateAdded` and `dueDate`).
 *
 * Refresh is conditional on `If-Modified-Since` only. The origin serves an ETag
 * but ignores it on conditional requests and returns the full 1.74 MB body, so
 * `If-None-Match` would defeat the point; `If-Modified-Since` answers a no-change
 * poll with a 304 and zero bytes.
 *
 * Cold start is single-flight: `setup()` kicks the first load off without
 * awaiting it and a request arriving before it lands awaits the same promise
 * rather than racing a second fetch. A failed refresh with a snapshot in hand
 * logs and keeps serving the old snapshot — a stale catalog beats no catalog, and
 * `cisa_list_reference` topic `sources` exposes `lastCheckedAt` so the staleness
 * is visible rather than silent.
 * @module services/kev-catalog/kev-catalog-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { logger, withRetry } from '@cyanheads/mcp-ts-core/utils';
import { assertSearchTextLength } from '@/services/search-text.js';
import { assertNotHtml, fetchUpstream, readUpstreamText } from '@/services/upstream-http.js';
import { daysBetween, type RawKevRecord, toKevRecord } from './parse.js';
import type { KevCatalogState, KevDirective, KevRecord, KevSnapshot } from './types.js';

/** The published KEV JSON feed. */
export const KEV_FEED_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** Ceiling on the feed body. It is 1.74 MB today; this leaves room to grow. */
const FEED_MAX_BYTES = 64 * 1024 * 1024;

/** Filters accepted by {@link KevCatalogService.search}. All AND together. */
export interface KevSearchFilters {
  cveIdPrefix?: string | undefined;
  cwe?: string | undefined;
  dateAddedFrom?: string | undefined;
  dateAddedTo?: string | undefined;
  directive?: 'BOD 26-04' | 'BOD 22-01' | 'none' | undefined;
  dueAfter?: string | undefined;
  dueBefore?: string | undefined;
  forensicTriage?: boolean | undefined;
  nameContains?: string | undefined;
  overdue?: boolean | undefined;
  product?: string | undefined;
  ransomware?: boolean | undefined;
  vendorProject?: string | undefined;
}

/** Options for {@link initKevCatalog}. */
export interface KevCatalogOptions {
  /** Injected clock — the seam that makes `overdue` / `daysUntilDue` testable. */
  now?: () => Date;
  /** Cron expression reported by `cisa_list_reference` topic `sources`. */
  refreshCron: string;
  /** Per-request upstream timeout in milliseconds. */
  timeoutMs: number;
}

/** Normalize a string for token matching: lowercase, strip punctuation. */
function normalizeText(value: string): string {
  return value
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9\s]/g, ' ');
}

/**
 * Normalize a `nameContains` query into its match tokens, once per search rather
 * than once per record: the query is normalized with an NFKD pass and two regex
 * sweeps, and repeating that against all 1,716 records makes the cost of one call
 * the length of the query times the size of the catalog.
 *
 * The length ceiling is what keeps the token count bounded — every token is then
 * searched for in every record, so the two multiply.
 */
function queryTokens(query: string): string[] {
  assertSearchTextLength(query, 'nameContains');
  return normalizeText(query).split(/\s+/).filter(Boolean);
}

/**
 * Strict token match — every query token must appear in the haystack. No fuzzy
 * fallback: an LLM caller does not need typo tolerance, and a wrong KEV record is
 * worse than a miss.
 */
function matchesTokens(haystack: string, tokens: string[]): boolean {
  if (tokens.length === 0) return false;
  const hay = normalizeText(haystack);
  return tokens.every((token) => hay.includes(token));
}

export class KevCatalogService {
  private inFlight: Promise<KevSnapshot> | undefined;
  private lastCheckedAt: string | undefined;
  private readonly now: () => Date;
  private readonly options: KevCatalogOptions;
  private current: KevSnapshot | undefined;

  constructor(options: KevCatalogOptions) {
    this.options = options;
    this.now = options.now ?? (() => new Date());
  }

  /** The UTC date `overdue` and `daysUntilDue` are computed against. */
  asOf(): string {
    return this.now().toISOString().slice(0, 10);
  }

  /**
   * The loaded snapshot, loading it on first call. Concurrent callers share one
   * in-flight fetch. Throws the retryable `catalog_unavailable` failure only when
   * no snapshot is held and the load fails.
   */
  async snapshot(ctx: Context): Promise<KevSnapshot> {
    if (this.current) return this.current;
    this.inFlight ??= this.load(ctx).finally(() => {
      this.inFlight = undefined;
    });
    try {
      return await this.inFlight;
    } catch (error) {
      if (this.current) return this.current;
      throw serviceUnavailable(
        'The KEV catalog snapshot is not loaded and the fetch from cisa.gov failed.',
        {
          reason: 'catalog_unavailable',
          retryable: true,
          ...ctx.recoveryFor('catalog_unavailable'),
        },
        { cause: error },
      );
    }
  }

  /** In-process state for `cisa_list_reference` topic `sources`. Never touches the network. */
  state(): KevCatalogState {
    return {
      catalogVersion: this.current?.catalogVersion ?? null,
      dateReleased: this.current?.dateReleased ?? null,
      count: this.current?.count ?? null,
      lastCheckedAt: this.lastCheckedAt ?? null,
      lastModified: this.current?.lastModified ?? null,
      refreshCron: this.options.refreshCron,
    };
  }

  /** Look up records by CVE ID against the snapshot's index, preserving input order. */
  async lookup(cveIds: string[], ctx: Context): Promise<Array<KevRecord | undefined>> {
    const snapshot = await this.snapshot(ctx);
    return cveIds.map((id) => snapshot.byId.get(id));
  }

  /**
   * The loaded snapshot without triggering a load — for surfaces that must answer
   * without blocking on the network (resource listings and argument completion).
   */
  currentSnapshot(): KevSnapshot | undefined {
    return this.current;
  }

  /**
   * Filter the complete snapshot — never a page — and return the matching records
   * in the requested order. Date-derived filters (`overdue`) resolve against the
   * same `asOf` date the tool echoes.
   */
  async search(
    filters: KevSearchFilters,
    sortBy: 'dueDate' | 'dateAdded',
    order: 'asc' | 'desc',
    ctx: Context,
  ): Promise<KevRecord[]> {
    const snapshot = await this.snapshot(ctx);
    const asOf = this.asOf();
    const source = sortBy === 'dueDate' ? snapshot.byDueDate : snapshot.byDateAdded;
    const nameTokens = filters.nameContains ? queryTokens(filters.nameContains) : [];

    const matched = source.filter((record) => this.matches(record, filters, nameTokens, asOf));
    return order === 'asc' ? matched : matched.slice().reverse();
  }

  /** The most recently added entries — backs the `cisa://kev/{cveId}` resource listing. */
  async recentlyAdded(limit: number, ctx: Context): Promise<KevRecord[]> {
    const snapshot = await this.snapshot(ctx);
    return snapshot.byDateAdded.slice(-limit).reverse();
  }

  /** Days from today (`asOf`) to the entry's due date; negative once overdue. */
  daysUntilDue(record: KevRecord, asOf: string): number {
    return daysBetween(asOf, record.dueDate);
  }

  /**
   * Conditionally refresh the snapshot. A 304 leaves the snapshot in place and
   * only advances `lastCheckedAt`; a failure with a snapshot in hand logs a
   * warning and keeps serving.
   */
  async refresh(ctx?: Context): Promise<void> {
    try {
      await this.load(ctx);
    } catch (error) {
      if (!this.current) throw error;
      logger.warning(
        `KEV catalog refresh failed; serving the snapshot from ${this.current.fetchedAt}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  /** Start the first load without awaiting it. Called from `setup()`. */
  primeInBackground(): void {
    void this.refresh().catch(() => {
      /* refresh() already logged; a cold failure surfaces on the first request. */
    });
  }

  private matches(
    record: KevRecord,
    filters: KevSearchFilters,
    nameTokens: string[],
    asOf: string,
  ): boolean {
    if (
      filters.vendorProject &&
      !record.vendorProject.toLowerCase().includes(filters.vendorProject.toLowerCase())
    ) {
      return false;
    }
    if (filters.product && !record.product.toLowerCase().includes(filters.product.toLowerCase())) {
      return false;
    }
    if (
      filters.nameContains &&
      !matchesTokens(`${record.vulnerabilityName} ${record.shortDescription}`, nameTokens)
    ) {
      return false;
    }
    if (filters.cwe && !record.cwes.includes(filters.cwe.toUpperCase())) return false;
    if (filters.cveIdPrefix && !record.cveId.startsWith(`${filters.cveIdPrefix.toUpperCase()}-`)) {
      return false;
    }
    if (filters.dateAddedFrom && record.dateAdded < filters.dateAddedFrom) return false;
    if (filters.dateAddedTo && record.dateAdded > filters.dateAddedTo) return false;
    if (filters.dueBefore && record.dueDate > filters.dueBefore) return false;
    if (filters.dueAfter && record.dueDate < filters.dueAfter) return false;
    if (filters.overdue !== undefined && record.dueDate < asOf !== filters.overdue) return false;
    if (
      filters.ransomware !== undefined &&
      (record.knownRansomwareCampaignUse === 'Known') !== filters.ransomware
    ) {
      return false;
    }
    if (
      filters.forensicTriage !== undefined &&
      (record.forensicTriage === 'Yes') !== filters.forensicTriage
    ) {
      return false;
    }
    if (filters.directive) {
      const wanted: KevDirective = filters.directive === 'none' ? null : filters.directive;
      if (record.directive !== wanted) return false;
    }
    return true;
  }

  /**
   * Fetch, decompress, parse, and index — the whole pipeline under one retry
   * boundary, because a body that arrives truncated or as an HTML error page is
   * exactly as transient as the connection failure that would precede it.
   */
  private async load(ctx?: Context): Promise<KevSnapshot> {
    const headers: Record<string, string> = {};
    if (this.current?.lastModified) headers['if-modified-since'] = this.current.lastModified;

    const loaded = await withRetry(
      async () => {
        const response = await fetchUpstream(KEV_FEED_URL, {
          service: 'CISA KEV',
          timeoutMs: this.options.timeoutMs,
          acceptStatuses: [304],
          headers,
          ...(ctx?.signal ? { signal: ctx.signal } : {}),
        });
        this.lastCheckedAt = new Date().toISOString();
        if (response.status === 304) return;

        const body = await readUpstreamText(response, {
          maxBytes: FEED_MAX_BYTES,
          service: 'CISA KEV',
          url: KEV_FEED_URL,
        });
        assertNotHtml(body, response.headers.get('content-type'), 'json', KEV_FEED_URL);
        return buildSnapshot(body, response.headers.get('last-modified'));
      },
      {
        operation: 'KevCatalogService.load',
        baseDelayMs: 1000,
        ...(ctx ? { context: ctx, signal: ctx.signal } : {}),
      },
    );

    if (loaded) {
      this.current = loaded;
      logger.info(
        `KEV catalog loaded: ${loaded.count} entries, catalogVersion ${loaded.catalogVersion}.`,
      );
    }
    if (!this.current) {
      throw serviceUnavailable('KEV feed answered 304 with no snapshot held.', {
        reason: 'catalog_unavailable',
        retryable: true,
      });
    }
    return this.current;
  }
}

/** Parse the feed body into a snapshot with its derived indexes. */
function buildSnapshot(body: string, lastModified: string | null): KevSnapshot {
  const parsed = JSON.parse(body) as {
    catalogVersion?: unknown;
    count?: unknown;
    dateReleased?: unknown;
    vulnerabilities?: unknown;
  };

  const rawRecords = Array.isArray(parsed.vulnerabilities)
    ? (parsed.vulnerabilities as RawKevRecord[])
    : [];
  const records: KevRecord[] = [];
  for (const raw of rawRecords) {
    const record = toKevRecord(raw);
    if (record) records.push(record);
  }

  const byId = new Map(records.map((record) => [record.cveId, record]));
  const byDateAdded = records
    .slice()
    .sort((a, b) => a.dateAdded.localeCompare(b.dateAdded) || a.cveId.localeCompare(b.cveId));
  const byDueDate = records
    .slice()
    .sort((a, b) => a.dueDate.localeCompare(b.dueDate) || a.cveId.localeCompare(b.cveId));

  return {
    catalogVersion: typeof parsed.catalogVersion === 'string' ? parsed.catalogVersion : '',
    dateReleased: typeof parsed.dateReleased === 'string' ? parsed.dateReleased : '',
    count: typeof parsed.count === 'number' ? parsed.count : records.length,
    fetchedAt: new Date().toISOString(),
    ...(lastModified ? { lastModified } : {}),
    records,
    byId,
    byDateAdded,
    byDueDate,
  };
}

// --- Init/accessor pattern ---

let _service: KevCatalogService | undefined;

/** Construct the KEV catalog service. Call once from `createApp`'s `setup()`. */
export function initKevCatalog(options: KevCatalogOptions): KevCatalogService {
  _service = new KevCatalogService(options);
  return _service;
}

/** Access the initialized KEV catalog service. */
export function getKevCatalog(): KevCatalogService {
  if (!_service) {
    throw new Error('KevCatalogService not initialized — call initKevCatalog() in setup().');
  }
  return _service;
}

/** Reset the singleton — test-only. */
export function resetKevCatalog(): void {
  _service = undefined;
}
