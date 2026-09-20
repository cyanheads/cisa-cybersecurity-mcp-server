/**
 * @fileoverview `cisa://kev/{cveId}` — one KEV catalog entry, in the same shape a
 * `cisa_check_cve_status` result carries. Fully covered by that tool, so a
 * tool-only client loses nothing.
 * @module mcp-server/resources/definitions/kev-entry.resource
 */

import { resource, z } from '@cyanheads/mcp-ts-core';
import { notFound } from '@cyanheads/mcp-ts-core/errors';
import {
  CveIdInputSchema,
  KevRecordSchema,
  toKevRecordOutput,
} from '@/mcp-server/schemas/kev-record.js';
import { getKevCatalog } from '@/services/kev-catalog/kev-catalog-service.js';

/** Entries surfaced by `list()` and the maximum completion suggestions. */
const LIST_LIMIT = 30;
const COMPLETION_LIMIT = 100;

export const kevEntryResource = resource('cisa://kev/{cveId}', {
  name: 'kev-entry',
  title: 'KEV catalog entry',
  description:
    'One entry from the CISA Known Exploited Vulnerabilities catalog, addressed by CVE ID — the same record shape cisa_check_cve_status returns, including the federal remediation deadline, the directive cited, ransomware and forensic-triage flags, and the references parsed from the entry notes. Listing returns the 30 most recently added entries.',
  mimeType: 'application/json',
  /* Public-domain data, byte-identical per tenant, refreshed on a 30-minute poll. */
  cacheHint: { ttlMs: 1_800_000, cacheScope: 'public' },

  params: z.object({
    cveId: CveIdInputSchema.describe(
      'The CVE identifier to look up, e.g. CVE-2025-39964. Case and surrounding whitespace are normalized.',
    ),
  }),

  output: KevRecordSchema,

  async handler(params, ctx) {
    const catalog = getKevCatalog();
    const snapshot = await catalog.snapshot(ctx);
    const cveId = params.cveId.trim().toUpperCase();
    const record = snapshot.byId.get(cveId);
    if (!record) {
      throw notFound(
        `${cveId} is not in the KEV catalog. Absence is not a statement about severity — KEV lists only vulnerabilities CISA has confirmed are exploited in the wild.`,
        { cveId },
      );
    }
    return toKevRecordOutput(record, catalog.asOf());
  },

  list: () => {
    const snapshot = getKevCatalog().currentSnapshot();
    const recent = snapshot ? snapshot.byDateAdded.slice(-LIST_LIMIT).reverse() : [];
    return {
      resources: recent.map((record) => ({
        uri: `cisa://kev/${record.cveId}`,
        name: `${record.cveId} — ${record.vulnerabilityName}`,
        mimeType: 'application/json',
      })),
    };
  },

  complete: {
    cveId: (partial) => {
      const snapshot = getKevCatalog().currentSnapshot();
      if (!snapshot) return [];
      const prefix = partial.trim().toUpperCase();
      const matches: string[] = [];
      for (const cveId of snapshot.byId.keys()) {
        if (cveId.startsWith(prefix)) matches.push(cveId);
        if (matches.length >= COMPLETION_LIMIT) break;
      }
      return matches;
    },
  },
});
