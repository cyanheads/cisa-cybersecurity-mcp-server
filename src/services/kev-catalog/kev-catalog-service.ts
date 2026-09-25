/**
 * @fileoverview KEV catalog service — the Tier 1 storage layer. The catalog is
 * public, tenant-invariant, and small (1,716 records and 1.74 MB at catalog
 * 2026.09.18) — well below the mirror tier's floor — so one process-level
 * snapshot is shared by every request: the parsed records, the feed envelope,
 * and the derived indexes (`Map<cveId>`, plus arrays sorted by `dateAdded` and
 * `dueDate`).
 *
 * Refresh is conditional on `If-Modified-Since` only. The origin serves an ETag
 * but ignores it on conditional requests and returns the full body, so
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
import { serviceUnavailable, validationError } from '@cyanheads/mcp-ts-core/errors';
import { logger, withRetry } from '@cyanheads/mcp-ts-core/utils';
import { assertSearchTextLength } from '@/services/search-text.js';
import { assertNotHtml, fetchUpstream, readUpstreamText } from '@/services/upstream-http.js';
import { daysBetween, type RawKevRecord, toKevRecord } from './parse.js';
import type { KevCatalogState, KevDirective, KevRecord, KevSnapshot } from './types.js';

/** The published KEV JSON feed. */
export const KEV_FEED_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** Ceiling on the feed body. It was 1.74 MB at catalog 2026.09.18; this leaves room to grow. */
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

/** One filter {@link KevCatalogService.search} accepts, by the name the caller sets it under. */
export type KevFilterKey = keyof KevSearchFilters;

/** How one applied filter behaves against the whole snapshot. */
export interface KevFilterCount {
  /** Entries this filter matches on its own. */
  alone: number;
  filter: KevFilterKey;
  /** Entries that fail this filter and pass every other applied one — what dropping it restores. */
  restoredByDropping: number;
}

/** One applied filter as a record predicate. */
type FilterPredicate = readonly [KevFilterKey, (record: KevRecord) => boolean];

/** Options for {@link initKevCatalog}. */
export interface KevCatalogOptions {
  /** Injected clock — the seam that makes `overdue` / `daysUntilDue` testable. */
  now?: () => Date;
  /** Cron expression reported by `cisa_list_reference` topic `sources`. */
  refreshCron: string;
  /** Per-request upstream timeout in milliseconds. */
  timeoutMs: number;
}

/**
 * The lowercase letters of Latin-1 Supplement and Latin Extended-A that NFKD
 * does not decompose to a-z, spelled as CLDR's Latin-ASCII transform spells them
 * — except `ŉ`, which CLDR writes `'n` and which becomes `n` here, since the
 * apostrophe would split the word. Without this table each of them became a
 * separator and split its word into fragments that match as substrings:
 * `Straße` searched `stra e`.
 */
const LATIN_ASCII: Readonly<Record<string, string>> = {
  ß: 'ss',
  æ: 'ae',
  ð: 'd',
  ø: 'o',
  þ: 'th',
  đ: 'd',
  ħ: 'h',
  ı: 'i',
  ĸ: 'q',
  ł: 'l',
  ŀ: 'l',
  ŉ: 'n',
  ŋ: 'n',
  œ: 'oe',
  ŧ: 't',
};

const LATIN_ASCII_LETTER = new RegExp(`[${Object.keys(LATIN_ASCII).join('')}]`, 'g');

/**
 * Fold case, the {@link LATIN_ASCII} letters, and accents — everything the match
 * does before discarding what is left outside a-z and 0-9. The table runs before
 * NFKD, which would otherwise split `ŀ` and `ŉ` around a separator; capitals,
 * `ẞ` included, reach it lowercased.
 */
function foldText(value: string): string {
  return value
    .toLowerCase()
    .replace(LATIN_ASCII_LETTER, (letter) => LATIN_ASCII[letter] ?? letter)
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '');
}

/**
 * Normalize a string for token matching: {@link foldText}, then every character
 * outside a-z, 0-9, and whitespace becomes a separator. Query and record text
 * both pass through it, so matching stays symmetric.
 */
export function normalizeText(value: string): string {
  return foldText(value).replace(/[^a-z0-9\s]/g, ' ');
}

/** A `nameContains` query as matching reads it. */
export interface NameQuery {
  /**
   * The caller's whitespace-separated words that carry a letter or digit the
   * normalization folds away — a word in another script, a Latin letter outside
   * the {@link LATIN_ASCII} table such as `ƒ`, digits outside 0-9. Record text is
   * folded the same way, so those characters can never match.
   */
  dropped: string[];
  /** The tokens every matching record must contain. */
  tokens: string[];
}

/** A letter or digit that survives {@link normalizeText}. */
const KEPT_CHARACTER = /[a-z0-9]/;

/** Any letter or digit, in any script. */
const LETTER_OR_DIGIT = /[\p{L}\p{N}]/u;

/**
 * Normalize a `nameContains` query into its match tokens, once per search rather
 * than once per record: the query is normalized with an NFKD pass and two regex
 * sweeps, and repeating that against every record in the catalog makes the cost
 * of one call the length of the query times the size of the catalog.
 *
 * The words that lost a letter or digit to the normalization are reported
 * beside the tokens, so a search that ran on less than the caller typed can say
 * so. Punctuation is not reported — it separates tokens rather than being one.
 *
 * The length ceiling is what keeps the token count bounded — every token is then
 * searched for in every record, so the two multiply. A query that normalizes to
 * no token at all — punctuation, whitespace, or only letters outside a-z, which
 * the normalization folds away — throws `empty_search_text` rather than matching
 * nothing: an empty result would read as "no entry matches" when nothing was
 * searched for.
 */
export function queryTokens(query: string): NameQuery {
  assertSearchTextLength(query, 'nameContains');
  const tokens = normalizeText(query).split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    throw validationError(
      'nameContains holds no searchable token — matching folds case and accents, spells letters such as ß and ø as ss and o, and keeps only the letters a-z and the digits 0-9, and none remain.',
      {
        reason: 'empty_search_text',
        field: 'nameContains',
        recovery: {
          hint: 'Put at least one word or number in nameContains that uses the letters a-z, accented or not, or the digits 0-9, such as a product or vulnerability term, or omit nameContains to search by the other filters alone.',
        },
      },
    );
  }
  const dropped = query
    .trim()
    .split(/\s+/)
    .filter((word) =>
      [...foldText(word)].some((char) => LETTER_OR_DIGIT.test(char) && !KEPT_CHARACTER.test(char)),
    );
  return { tokens, dropped };
}

/**
 * Strict token match — every query token must appear in the haystack. No fuzzy
 * fallback: an LLM caller does not need typo tolerance, and a wrong KEV record is
 * worse than a miss.
 */
function matchesTokens(haystack: string, tokens: string[]): boolean {
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
    const source = sortBy === 'dueDate' ? snapshot.byDueDate : snapshot.byDateAdded;
    const predicates = this.predicates(filters, this.asOf());

    const matched = source.filter((record) => predicates.every(([, test]) => test(record)));
    return order === 'asc' ? matched : matched.slice().reverse();
  }

  /**
   * Score each applied filter against the whole snapshot in one pass: how many
   * entries it matches on its own, and how many fail it and nothing else — the
   * entries dropping it would restore. Backs the zero-hit notice, which asks for
   * it only after a search came back empty.
   */
  async filterCounts(filters: KevSearchFilters, ctx: Context): Promise<KevFilterCount[]> {
    const snapshot = await this.snapshot(ctx);
    const scored = this.predicates(filters, this.asOf()).map(([filter, test]) => ({
      filter,
      test,
      alone: 0,
      restoredByDropping: 0,
    }));

    for (const record of snapshot.records) {
      let failures = 0;
      let failed: (typeof scored)[number] | undefined;
      for (const entry of scored) {
        if (entry.test(record)) {
          entry.alone += 1;
        } else {
          failures += 1;
          failed = entry;
        }
      }
      if (failures === 1 && failed) failed.restoredByDropping += 1;
    }

    return scored.map(({ filter, alone, restoredByDropping }) => ({
      filter,
      alone,
      restoredByDropping,
    }));
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

  /**
   * One predicate per applied filter, in a fixed order. `search` requires all of
   * them; `filterCounts` scores them one at a time. An empty string or an absent
   * value is not an applied filter. Date-derived filters (`overdue`) resolve
   * against `asOf`.
   */
  private predicates(filters: KevSearchFilters, asOf: string): FilterPredicate[] {
    const {
      vendorProject,
      product,
      nameContains,
      cwe,
      cveIdPrefix,
      dateAddedFrom,
      dateAddedTo,
      dueBefore,
      dueAfter,
      overdue,
      ransomware,
      forensicTriage,
      directive,
    } = filters;
    const predicates: FilterPredicate[] = [];

    if (vendorProject) {
      const needle = vendorProject.toLowerCase();
      predicates.push([
        'vendorProject',
        (record) => record.vendorProject.toLowerCase().includes(needle),
      ]);
    }
    if (product) {
      const needle = product.toLowerCase();
      predicates.push(['product', (record) => record.product.toLowerCase().includes(needle)]);
    }
    if (nameContains) {
      const { tokens } = queryTokens(nameContains);
      predicates.push([
        'nameContains',
        (record) => matchesTokens(`${record.vulnerabilityName} ${record.shortDescription}`, tokens),
      ]);
    }
    if (cwe) predicates.push(['cwe', (record) => record.cwes.includes(cwe)]);
    if (cveIdPrefix) {
      predicates.push(['cveIdPrefix', (record) => record.cveId.startsWith(`${cveIdPrefix}-`)]);
    }
    if (dateAddedFrom)
      predicates.push(['dateAddedFrom', (record) => record.dateAdded >= dateAddedFrom]);
    if (dateAddedTo) predicates.push(['dateAddedTo', (record) => record.dateAdded <= dateAddedTo]);
    if (dueBefore) predicates.push(['dueBefore', (record) => record.dueDate <= dueBefore]);
    if (dueAfter) predicates.push(['dueAfter', (record) => record.dueDate >= dueAfter]);
    if (overdue !== undefined) {
      predicates.push(['overdue', (record) => record.dueDate < asOf === overdue]);
    }
    if (ransomware !== undefined) {
      predicates.push([
        'ransomware',
        (record) => (record.knownRansomwareCampaignUse === 'Known') === ransomware,
      ]);
    }
    if (forensicTriage !== undefined) {
      predicates.push([
        'forensicTriage',
        (record) => (record.forensicTriage === 'Yes') === forensicTriage,
      ]);
    }
    if (directive) {
      const wanted: KevDirective = directive === 'none' ? null : directive;
      predicates.push(['directive', (record) => record.directive === wanted]);
    }
    return predicates;
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
