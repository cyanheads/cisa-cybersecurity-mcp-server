/**
 * @fileoverview Mirror store schema for the ICS advisory index. One
 * MirrorService-owned table (`ics_advisories`) with an FTS5 index over the
 * searchable text and secondary indexes on the filterable columns, plus three
 * auxiliary tables created by a migration.
 *
 * The junction tables exist because exact CVE and sector membership cannot be
 * answered by scanning a delimited text column: it is both slow and wrong —
 * `Water` is a substring of `Wastewater`. `mirror_meta` holds the `changes.csv`
 * ETag between refresh runs, which the framework's own sync state has no field
 * for.
 * @module services/csaf-mirror/schema
 */

import type { Migration, SqliteHandle, SqliteMirrorStoreSpec } from '@cyanheads/mcp-ts-core/mirror';

/** The MirrorService-owned primary table. */
export const ADVISORIES_TABLE = 'ics_advisories';

/** The FTS5 external-content index the framework generates for the primary table. */
export const ADVISORIES_FTS = `${ADVISORIES_TABLE}_fts`;

/** Junction table for exact CVE membership. */
export const ADVISORY_CVES_TABLE = 'advisory_cves';

/** Junction table for exact sector membership. */
export const ADVISORY_SECTORS_TABLE = 'advisory_sectors';

/** Key/value table for ingest state the framework's sync state has no field for. */
export const MIRROR_META_TABLE = 'mirror_meta';

/**
 * Auxiliary DDL. Runs identically on a fresh database and on an upgrade, so
 * everything is `CREATE … IF NOT EXISTS` and nothing alters a declared column.
 */
const auxiliaryTables: Migration = {
  version: 1,
  up(handle: SqliteHandle): void {
    handle.exec(`
CREATE TABLE IF NOT EXISTS ${ADVISORY_CVES_TABLE} (
  advisoryId TEXT NOT NULL,
  cve TEXT NOT NULL,
  PRIMARY KEY (advisoryId, cve)
);
CREATE INDEX IF NOT EXISTS ${ADVISORY_CVES_TABLE}_cve_idx ON ${ADVISORY_CVES_TABLE}(cve);

CREATE TABLE IF NOT EXISTS ${ADVISORY_SECTORS_TABLE} (
  advisoryId TEXT NOT NULL,
  sector TEXT NOT NULL,
  PRIMARY KEY (advisoryId, sector)
);
CREATE INDEX IF NOT EXISTS ${ADVISORY_SECTORS_TABLE}_sector_idx ON ${ADVISORY_SECTORS_TABLE}(sector);

CREATE TABLE IF NOT EXISTS ${MIRROR_META_TABLE} (
  key TEXT PRIMARY KEY,
  value TEXT
);
`);
  },
};

/**
 * The store spec. `document` holds the normalized advisory JSON rather than the
 * raw CSAF, so the flattening, sector extraction, and CVSS computation run once
 * at ingest instead of on every read.
 */
export function advisoryStoreSpec(path: string): SqliteMirrorStoreSpec {
  return {
    path,
    table: ADVISORIES_TABLE,
    primaryKey: 'advisoryId',
    version: 1,
    columns: {
      advisoryId: 'TEXT',
      series: 'TEXT',
      title: 'TEXT',
      vendorsText: 'TEXT',
      productsText: 'TEXT',
      vendorCount: 'INTEGER',
      productCount: 'INTEGER',
      cveCount: 'INTEGER',
      maxCvss: 'REAL',
      maxCvssSeverity: 'TEXT',
      maxCvssVersion: 'TEXT',
      sectorsText: 'TEXT',
      sectorsRaw: 'TEXT',
      published: 'TEXT',
      revised: 'TEXT',
      revision: 'TEXT',
      publisherCategory: 'TEXT',
      sourcePath: 'TEXT',
      url: 'TEXT',
      csafUrl: 'TEXT',
      attribution: 'TEXT',
      document: 'TEXT',
    },
    fts: ['title', 'vendorsText', 'productsText'],
    indexes: [
      { columns: ['series'] },
      { columns: ['maxCvss'] },
      { columns: ['published'] },
      { columns: ['revised'] },
      { columns: ['publisherCategory'] },
      { columns: ['sourcePath'] },
    ],
    migrations: [auxiliaryTables],
  };
}
