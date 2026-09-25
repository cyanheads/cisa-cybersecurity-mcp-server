/**
 * @fileoverview The ICS advisory ingester — the one irreducibly per-source part
 * of the mirror.
 *
 * `init` streams one 11.4 MB repository archive and normalizes every document
 * under the OT distribution; the alternative is one `raw.githubusercontent.com`
 * request per document, several thousand of them. `refresh` conditionally fetches the
 * 228 KB `changes.csv` manifest with `If-None-Match` (which
 * `raw.githubusercontent.com` honors), diffs its timestamps against the stored
 * `revised` values, and fetches only the documents whose timestamp moved. Because
 * the manifest is a full listing rather than an append-only log, a document
 * dropped upstream is detectable and emitted as a tombstone.
 *
 * The three junction tables are maintained here, written just before each page is
 * yielded. A page interrupted between the junction write and the upsert leaves a
 * junction row for an advisory the main table does not yet carry — harmless,
 * because every read joins from the main table — and the next run replaces it.
 *
 * A completed `init` records {@link INGEST_CONTENT_VERSION} in `mirror_meta`.
 * `refresh` only reprocesses documents whose upstream revision date moved, so a
 * change to what ingest derives from an unchanged document would otherwise never
 * reach an existing index; the service compares the recorded version and re-runs
 * `init` in place when it is older.
 * @module services/csaf-mirror/ingest
 */

import type {
  MirrorRow,
  SqliteHandle,
  SyncContext,
  SyncGenerator,
  SyncPage,
} from '@cyanheads/mcp-ts-core/mirror';
import { logger, withRetry } from '@cyanheads/mcp-ts-core/utils';
import { assertNotHtml, fetchUpstream, readUpstreamText } from '@/services/upstream-http.js';
import {
  CSAF_OT_BASE,
  isCsafSourcePath,
  normalizeAdvisory,
  parseChangesCsv,
  toMirrorRow,
} from './normalize.js';
import {
  ADVISORIES_TABLE,
  ADVISORY_CVES_TABLE,
  ADVISORY_CWES_TABLE,
  ADVISORY_SECTORS_TABLE,
  MIRROR_META_TABLE,
} from './schema.js';
import { iterateTarGz } from './tar.js';

/** Whole-repository archive of the CSAF repository's default branch. */
export const CSAF_ARCHIVE_URL =
  'https://codeload.github.com/cisagov/CSAF/tar.gz/refs/heads/develop';

/** The full manifest of every OT document and its current release date. */
export const CSAF_CHANGES_URL = `${CSAF_OT_BASE}/changes.csv`;

/** Documents per page on the archive-seeded init path. */
const INIT_PAGE_SIZE = 200;

/** Documents per page on the incremental refresh path, where each is its own fetch. */
const REFRESH_PAGE_SIZE = 50;

/** Concurrent per-document fetches during a refresh. Self-imposed; the source publishes no limit. */
const REFRESH_CONCURRENCY = 6;

/** `mirror_meta` key holding the ETag of the last successfully applied manifest. */
const CHANGES_ETAG_KEY = 'changes_csv_etag';

/**
 * What the current ingest derives from an unchanged upstream document. Raise it
 * whenever normalization changes a stored row, the stored document, or a junction
 * table for a document upstream has not revised — an index built at a lower
 * version re-ingests in the background on its next boot.
 *
 * 1 — every product row stored and indexed (no 200-row cap), short-form sector
 *     aliases, and the `advisory_cwes` junction. An index with no recorded
 *     version predates versioning and counts as older.
 */
export const INGEST_CONTENT_VERSION = 1;

/** `mirror_meta` key holding the content version of the last completed `init`. */
const CONTENT_VERSION_KEY = 'ingest_content_version';

/** Path segment that scopes the archive to the OT (ICS) distribution. */
const OT_PREFIX = 'csaf_files/OT/white/';

/** Ceiling on the manifest body. It is 228 KB today; this is two orders above it. */
const MANIFEST_MAX_BYTES = 16 * 1024 * 1024;

/** Ceiling on one advisory document. The largest in the corpus is 1.38 MB. */
const DOCUMENT_MAX_BYTES = 16 * 1024 * 1024;

/** A normalized document paired with the membership rows its junctions need. */
interface IngestRecord {
  advisoryId: string;
  cves: string[];
  cwes: string[];
  revised: string;
  row: MirrorRow;
  sectors: string[];
}

/** Options for {@link createCsafIngester}. */
export interface CsafIngestOptions {
  /** Opens the raw SQLite handle the junction tables are written through. */
  getHandle: () => Promise<SqliteHandle>;
  /** Per-request upstream timeout in milliseconds. */
  timeoutMs: number;
}

/** Turn a parsed CSAF document into a mirror row plus its junction membership. */
function toIngestRecord(parsed: unknown, sourcePath: string): IngestRecord | null {
  const doc = normalizeAdvisory(parsed, sourcePath);
  if (!doc) return null;
  return {
    advisoryId: doc.advisory.advisoryId,
    revised: doc.advisory.revised,
    cves: [...new Set(doc.vulnerabilities.map((vulnerability) => vulnerability.cve))],
    cwes: [
      ...new Set(
        doc.vulnerabilities.flatMap((vulnerability) =>
          vulnerability.cweId ? [vulnerability.cweId.toUpperCase()] : [],
        ),
      ),
    ],
    sectors: doc.summary.sectors,
    row: toMirrorRow(doc, sourcePath),
  };
}

/** Replace the junction rows for every advisory in the page, in one transaction. */
function writeJunctions(handle: SqliteHandle, records: IngestRecord[]): void {
  const deleteCves = handle.prepare(`DELETE FROM ${ADVISORY_CVES_TABLE} WHERE advisoryId = ?`);
  const deleteSectors = handle.prepare(
    `DELETE FROM ${ADVISORY_SECTORS_TABLE} WHERE advisoryId = ?`,
  );
  const deleteCwes = handle.prepare(`DELETE FROM ${ADVISORY_CWES_TABLE} WHERE advisoryId = ?`);
  const insertCve = handle.prepare(
    `INSERT OR IGNORE INTO ${ADVISORY_CVES_TABLE} (advisoryId, cve) VALUES (?, ?)`,
  );
  const insertSector = handle.prepare(
    `INSERT OR IGNORE INTO ${ADVISORY_SECTORS_TABLE} (advisoryId, sector) VALUES (?, ?)`,
  );
  const insertCwe = handle.prepare(
    `INSERT OR IGNORE INTO ${ADVISORY_CWES_TABLE} (advisoryId, cweId) VALUES (?, ?)`,
  );

  handle.transaction(() => {
    for (const record of records) {
      deleteCves.run(record.advisoryId);
      deleteSectors.run(record.advisoryId);
      deleteCwes.run(record.advisoryId);
      for (const cve of record.cves) insertCve.run(record.advisoryId, cve);
      for (const sector of record.sectors) insertSector.run(record.advisoryId, sector);
      for (const cwe of record.cwes) insertCwe.run(record.advisoryId, cwe);
    }
  });
}

/** Drop the junction rows of advisories that disappeared upstream. */
function deleteJunctions(handle: SqliteHandle, advisoryIds: string[]): void {
  if (advisoryIds.length === 0) return;
  const deletes = [ADVISORY_CVES_TABLE, ADVISORY_SECTORS_TABLE, ADVISORY_CWES_TABLE].map((table) =>
    handle.prepare(`DELETE FROM ${table} WHERE advisoryId = ?`),
  );
  handle.transaction(() => {
    for (const advisoryId of advisoryIds) {
      for (const statement of deletes) statement.run(advisoryId);
    }
  });
}

/**
 * The content version the index was last fully built with, or `null` when none
 * was ever recorded — a never-seeded index, or one built before versioning.
 */
export function readIngestContentVersion(handle: SqliteHandle): number | null {
  const value = readMeta(handle, CONTENT_VERSION_KEY);
  return value === undefined ? null : Number(value);
}

function readMeta(handle: SqliteHandle, key: string): string | undefined {
  const row = handle
    .prepare<{ value: string | null }>(`SELECT value FROM ${MIRROR_META_TABLE} WHERE key = ?`)
    .get(key);
  return row?.value ?? undefined;
}

function writeMeta(handle: SqliteHandle, key: string, value: string): void {
  handle
    .prepare(
      `INSERT INTO ${MIRROR_META_TABLE} (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    )
    .run(key, value);
}

/** Build a page from accumulated records, writing their junctions first. */
function emitPage(
  handle: SqliteHandle,
  records: IngestRecord[],
  checkpoint: string | undefined,
): SyncPage {
  writeJunctions(handle, records);
  return {
    records: records.map((record) => record.row),
    ...(checkpoint ? { checkpoint } : {}),
  };
}

/**
 * Build the advisory ingester. `init` seeds from the repository archive; `refresh`
 * diffs the `changes.csv` manifest and fetches only what moved.
 */
export function createCsafIngester(options: CsafIngestOptions): SyncGenerator {
  return async function* sync({ mode, checkpoint, signal }: SyncContext): AsyncGenerator<SyncPage> {
    const handle = await options.getHandle();
    if (mode === 'init') {
      yield* runInit(handle, options, signal, checkpoint);
      return;
    }
    yield* runRefresh(handle, options, signal, checkpoint);
  };
}

/** Stream the repository archive and normalize every OT document in it. */
async function* runInit(
  handle: SqliteHandle,
  options: CsafIngestOptions,
  signal: AbortSignal,
  checkpoint: string | undefined,
): AsyncGenerator<SyncPage> {
  logger.info('ICS advisory mirror init: streaming the CSAF repository archive.');

  /*
   * The retry covers the connection and response headers; the archive body is
   * streamed straight into the page generator below, so a mid-stream failure
   * fails the run and the next `mirror:init` starts over.
   */
  const response = await withRetry(
    () =>
      fetchUpstream(CSAF_ARCHIVE_URL, {
        service: 'CISA CSAF archive',
        timeoutMs: Math.max(options.timeoutMs, 300_000),
        signal,
      }),
    { operation: 'CsafMirror.init.archive', baseDelayMs: 1000, signal },
  );
  if (!response.body) {
    throw new Error('CSAF repository archive returned an empty body.');
  }

  /*
   * Filenames always start with the series prefix, never a digit, so a `.json`
   * suffix match also excludes the `<name>.json.asc` and `<name>.json.sha512`
   * sidecars every document ships alongside — no extra exclusion rule needed.
   */
  const include = (name: string): boolean =>
    name.includes(OT_PREFIX) && name.endsWith('.json') && !name.endsWith(`${OT_PREFIX}index.json`);

  let maxRevised = checkpoint;
  let batch: IngestRecord[] = [];
  let total = 0;

  for await (const entry of iterateTarGz(response.body, include)) {
    if (signal.aborted) return;
    const sourcePath = entry.name.slice(entry.name.indexOf(OT_PREFIX) + OT_PREFIX.length);
    /* The entry name is upstream text and the path composes this document's
     * fetch URL and its published `csafUrl`, so only the addressable shape rides. */
    if (!isCsafSourcePath(sourcePath)) continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(entry.data));
    } catch {
      logger.warning(`Skipping unparseable CSAF document ${sourcePath}.`);
      continue;
    }

    const record = toIngestRecord(parsed, sourcePath);
    if (!record) continue;
    if (record.revised && (maxRevised === undefined || record.revised > maxRevised)) {
      maxRevised = record.revised;
    }
    batch.push(record);
    total += 1;

    if (batch.length >= INIT_PAGE_SIZE) {
      yield emitPage(handle, batch, maxRevised);
      batch = [];
    }
  }

  if (batch.length > 0) yield emitPage(handle, batch, maxRevised);
  if (signal.aborted) return;
  if (total === 0) {
    /* Recording the content version here would mark whatever an existing index
     * holds as current without having re-derived any of it. */
    throw new Error('CSAF repository archive yielded no OT advisory documents.');
  }

  /* The runner applies a page before resuming the generator, so every page is
   * already written when this line runs. */
  writeMeta(handle, CONTENT_VERSION_KEY, String(INGEST_CONTENT_VERSION));
  logger.info(`ICS advisory mirror init: ${total} advisories normalized.`);
}

/** Diff the manifest and fetch only the documents whose release date moved. */
async function* runRefresh(
  handle: SqliteHandle,
  options: CsafIngestOptions,
  signal: AbortSignal,
  checkpoint: string | undefined,
): AsyncGenerator<SyncPage> {
  const etag = readMeta(handle, CHANGES_ETAG_KEY);
  const fetched = await withRetry(
    async () => {
      const response = await fetchUpstream(CSAF_CHANGES_URL, {
        service: 'CISA CSAF manifest',
        timeoutMs: options.timeoutMs,
        acceptStatuses: [304],
        ...(etag ? { headers: { 'if-none-match': etag } } : {}),
        signal,
      });
      if (response.status === 304) return null;
      const body = await readUpstreamText(response, {
        maxBytes: MANIFEST_MAX_BYTES,
        service: 'CISA CSAF manifest',
        url: CSAF_CHANGES_URL,
      });
      assertNotHtml(body, response.headers.get('content-type'), 'text', CSAF_CHANGES_URL);
      return { response, manifest: parseChangesCsv(body) };
    },
    { operation: 'CsafMirror.refresh.manifest', baseDelayMs: 500, signal },
  );

  if (!fetched) {
    logger.info('ICS advisory mirror refresh: manifest unchanged (304).');
    return;
  }

  const { response, manifest } = fetched;
  if (manifest.length === 0) {
    throw new Error(
      'CSAF changes.csv parsed to zero rows — refusing to tombstone the whole index.',
    );
  }

  const stored = handle
    .prepare<{ advisoryId: string; revised: string | null; sourcePath: string | null }>(
      `SELECT advisoryId, sourcePath, revised FROM ${ADVISORIES_TABLE}`,
    )
    .all();
  const byPath = new Map(
    stored
      .filter((row) => row.sourcePath)
      .map((row) => [
        row.sourcePath as string,
        { advisoryId: row.advisoryId, revised: row.revised },
      ]),
  );

  const manifestPaths = new Set(manifest.map((row) => row.path));
  const changed = manifest.filter((row) => {
    const existing = byPath.get(row.path);
    return !existing || (existing.revised ?? '') !== row.timestamp;
  });
  const tombstones = [...byPath.entries()]
    .filter(([path]) => !manifestPaths.has(path))
    .map(([, value]) => value.advisoryId);

  logger.info(
    `ICS advisory mirror refresh: ${changed.length} changed, ${tombstones.length} removed upstream.`,
  );

  let maxRevised = checkpoint;
  let batch: IngestRecord[] = [];
  let index = 0;

  const fetchOne = (path: string): Promise<IngestRecord | null> => {
    const url = `${CSAF_OT_BASE}/${path}`;
    return withRetry(
      async () => {
        const doc = await fetchUpstream(url, {
          service: 'CISA CSAF document',
          timeoutMs: options.timeoutMs,
          signal,
        });
        const text = await readUpstreamText(doc, {
          maxBytes: DOCUMENT_MAX_BYTES,
          service: 'CISA CSAF document',
          url,
        });
        assertNotHtml(text, doc.headers.get('content-type'), 'json', url);
        return toIngestRecord(JSON.parse(text), path);
      },
      { operation: 'CsafMirror.refresh.document', baseDelayMs: 500, signal },
    );
  };

  while (index < changed.length && !signal.aborted) {
    const slice = changed.slice(index, index + REFRESH_CONCURRENCY);
    index += slice.length;
    const settled = await Promise.allSettled(slice.map((row) => fetchOne(row.path)));

    for (const [position, outcome] of settled.entries()) {
      if (outcome.status === 'rejected') {
        logger.warning(
          `ICS advisory mirror refresh: ${slice[position]?.path} failed — ${
            outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason)
          }`,
        );
        continue;
      }
      const record = outcome.value;
      if (!record) continue;
      if (record.revised && (maxRevised === undefined || record.revised > maxRevised)) {
        maxRevised = record.revised;
      }
      batch.push(record);
    }

    if (batch.length >= REFRESH_PAGE_SIZE) {
      yield emitPage(handle, batch, maxRevised);
      batch = [];
    }
  }

  if (batch.length > 0 || tombstones.length > 0) {
    writeJunctions(handle, batch);
    deleteJunctions(handle, tombstones);
    yield {
      records: batch.map((record) => record.row),
      ...(tombstones.length > 0 ? { tombstones } : {}),
      ...(maxRevised ? { checkpoint: maxRevised } : {}),
    };
  }

  const newEtag = response.headers.get('etag');
  if (newEtag && !signal.aborted) writeMeta(handle, CHANGES_ETAG_KEY, newEtag);
}
