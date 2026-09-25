/**
 * @fileoverview `cisa_list_reference` — decodes the vocabulary the rest of the
 * surface takes as input, and reports what data this server currently holds.
 *
 * No network call and no service dependency beyond the in-process accessors,
 * which is what keeps it callable while another tool is failing — it is the
 * routing target of every recovery hint, zero-hit notice, and resolver miss on
 * this surface, so `openWorldHint` is `false` for the whole tool.
 * @module mcp-server/tools/definitions/list-reference.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import {
  BOD_2604_DEFINITIONS,
  BOD_2604_SUPERSEDES,
  BOD_2604_TABLE_1,
} from '@/reference/bod-2604.js';
import { REFERENCE_BLOCKS, REFERENCE_TOPICS } from '@/reference/tables.js';
import { getCisaFeeds } from '@/services/cisa-feeds/cisa-feeds-service.js';
import { getCsafMirror } from '@/services/csaf-mirror/csaf-mirror-service.js';
import { STORE_UNAVAILABLE_REASONS } from '@/services/csaf-mirror/types.js';
import { getKevCatalog } from '@/services/kev-catalog/kev-catalog-service.js';
import { getVulnrichment } from '@/services/vulnrichment/vulnrichment-service.js';

const TimelineRowSchema = z
  .object({
    row: z.number().int().describe('Table 1 row number, 1 through 16.'),
    publiclyExposed: z
      .boolean()
      .describe('Whether the asset is reachable by unauthenticated or untrusted entities.'),
    inKev: z.boolean().describe('Whether the CVE is in the CISA KEV catalog.'),
    automatable: z.boolean().describe('The SSVC Automatable decision point for this row.'),
    technicalImpact: z
      .enum(['partial', 'total'])
      .describe('The SSVC Technical Impact decision point for this row.'),
    timelineLabel: z.string().describe("The agency timeline in the directive's own wording."),
    remediationTimelineDays: z
      .number()
      .int()
      .nullable()
      .describe('Calendar days allowed, or null for the "Fix on system upgrade" rows.'),
    forensicTriageRequired: z
      .boolean()
      .describe('Whether the row additionally requires a forensic triage of the asset.'),
  })
  .describe('One row of BOD 26-04 Appendix A, Table 1.');

export const listReferenceTool = tool('cisa_list_reference', {
  title: 'cisa_list_reference',
  description:
    "Decode the vocabulary the other CISA tools take as input. Topics cover the BOD 26-04 remediation timeline table and what each tier means, the KEV record fields and their value domains, the SSVC decision points CISA publishes, the critical-infrastructure sector names as the advisory corpus spells them, advisory ID formats, CVSS severity bands, and the freshness of the data this server currently holds. Call this before constructing filters for cisa_search_kev or cisa_search_ics_advisories, and whenever another tool's recovery hint points here.",
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    topic: z
      .enum(REFERENCE_TOPICS)
      .describe(
        'Which reference block to return: directives (BOD 26-04 Table 1 and its definitions), kev_fields, ssvc_values, sectors, advisory_id_formats, severity_bands, or sources (what this server currently holds).',
      ),
  }),

  output: z.object({
    topic: z.enum(REFERENCE_TOPICS).describe('The topic that was decoded.'),
    title: z.string().describe('Human-readable title for the topic.'),
    summary: z.string().describe('What this topic covers and when to reach for it.'),
    entries: z
      .array(
        z
          .object({
            key: z.string().describe('Stable identifier for the term.'),
            label: z.string().describe('Human-readable name for the term.'),
            description: z.string().describe('What the term means and how it affects a query.'),
            values: z
              .array(z.string().describe('One accepted value.'))
              .optional()
              .describe('The value domain, when the term has a closed or enumerated one.'),
          })
          .describe('One decoded term within the topic.'),
      )
      .describe('The decoded terms for this topic.'),
    timelineTable: z
      .array(TimelineRowSchema)
      .optional()
      .describe('Topic directives only — all sixteen rows of BOD 26-04 Appendix A, Table 1.'),
    definitions: z
      .array(
        z
          .object({
            term: z.string().describe('The defined term.'),
            definition: z.string().describe("The directive's own definition of the term."),
          })
          .describe('One supporting definition from the directive text.'),
      )
      .optional()
      .describe('Topic directives only — supporting definitions from the directive text.'),
    supersedes: z
      .array(
        z
          .object({
            directive: z.string().describe('The superseded directive identifier.'),
            issued: z
              .string()
              .regex(/^\d{4}-\d{2}-\d{2}$/)
              .describe('Issue date, YYYY-MM-DD.'),
            note: z.string().describe('What the superseded directive covered.'),
          })
          .describe('One directive that BOD 26-04 supersedes and revokes.'),
      )
      .optional()
      .describe('Topic directives only — the directives BOD 26-04 supersedes and revokes.'),
    sources: z
      .object({
        kev: z
          .object({
            catalogVersion: z
              .string()
              .nullable()
              .describe(
                'Catalog version of the loaded snapshot; null before the first load lands.',
              ),
            dateReleased: z
              .string()
              .nullable()
              .describe(
                'Release timestamp the loaded snapshot carries; null before the first load.',
              ),
            count: z
              .number()
              .int()
              .nullable()
              .describe('Entry count the loaded snapshot carries; null before the first load.'),
            lastCheckedAt: z
              .string()
              .nullable()
              .describe('When the refresh poll last reached the origin, ISO 8601; null if never.'),
            lastModified: z
              .string()
              .nullable()
              .describe(
                'Upstream Last-Modified of the loaded snapshot, used for the conditional poll.',
              ),
            refreshCron: z
              .string()
              .describe('Cron expression the refresh poll runs on, or off when it is disabled.'),
          })
          .describe('The in-memory KEV catalog snapshot.'),
        csafMirror: z
          .object({
            ready: z
              .boolean()
              .describe('True once a full sync has ever completed; stays true during a refresh.'),
            documentCount: z
              .number()
              .int()
              .nullable()
              .describe('Advisories held in the index; null before the first sync completes.'),
            checkpoint: z
              .string()
              .nullable()
              .describe('Durable high-water mark — the newest current_release_date ingested.'),
            syncStatus: z
              .string()
              .describe('Lifecycle state: pending, in_progress, complete, error, or unavailable.'),
            lastCompletedAt: z
              .string()
              .nullable()
              .describe('When a full sync last completed, ISO 8601; null if never.'),
            unavailableReason: z
              .enum(STORE_UNAVAILABLE_REASONS)
              .optional()
              .describe(
                'Present only when the index cannot be opened: its location is not writable, is read-only, has a missing directory, runs through a file, or holds a file that is not a SQLite database. Fixed by CISA_CSAF_MIRROR_PATH, not by waiting.',
              ),
          })
          .describe('The local ICS advisory index.'),
        vulnrichment: z
          .object({
            mode: z
              .literal('on_demand')
              .describe('Access mode — fetched per CVE on demand; the repository is not mirrored.'),
            cacheTtlSeconds: z
              .number()
              .int()
              .describe('TTL for a cached record; negative results use one sixth of it.'),
          })
          .describe('The per-CVE SSVC enrichment tier.'),
        feeds: z
          .object({
            windowItems: z
              .number()
              .int()
              .describe('Items each feed serves — a fixed upstream ceiling, not a server choice.'),
            cached: z
              .array(
                z
                  .object({
                    feed: z
                      .enum(['advisories', 'alerts', 'ics'])
                      .describe('Which feed this cached window belongs to.'),
                    oldest: z
                      .string()
                      .nullable()
                      .describe('Publication date of the oldest item in the cached window.'),
                    newest: z
                      .string()
                      .nullable()
                      .describe('Publication date of the newest item in the cached window.'),
                    fetchedAt: z.string().describe('When this window was fetched, ISO 8601.'),
                  })
                  .describe('One cached feed window.'),
              )
              .describe('Feed windows currently held in memory; empty before any feed is read.'),
          })
          .describe('The RSS feed tier.'),
      })
      .optional()
      .describe(
        'Topic sources only — what this server currently holds, read from in-process state.',
      ),
  }),

  async handler(input, ctx) {
    const block = REFERENCE_BLOCKS[input.topic];
    ctx.log.debug('Serving reference block', { topic: input.topic });

    if (input.topic === 'directives') {
      return {
        topic: input.topic,
        title: block.title,
        summary: block.summary,
        entries: block.entries,
        timelineTable: BOD_2604_TABLE_1.map((row) => ({ ...row })),
        definitions: BOD_2604_DEFINITIONS.map((entry) => ({ ...entry })),
        supersedes: BOD_2604_SUPERSEDES.map((entry) => ({ ...entry })),
      };
    }

    if (input.topic === 'sources') {
      return {
        topic: input.topic,
        title: block.title,
        summary: block.summary,
        entries: block.entries,
        sources: {
          kev: getKevCatalog().state(),
          csafMirror: await getCsafMirror().state(),
          vulnrichment: getVulnrichment().state(),
          feeds: getCisaFeeds().state(),
        },
      };
    }

    return {
      topic: input.topic,
      title: block.title,
      summary: block.summary,
      entries: block.entries,
    };
  },

  format: (result) => {
    const lines: string[] = [
      `# ${result.title}`,
      '',
      `**Topic:** ${result.topic}`,
      '',
      result.summary,
      '',
    ];

    for (const entry of result.entries) {
      lines.push(`### ${entry.label} (\`${entry.key}\`)`);
      lines.push(entry.description);
      if (entry.values) lines.push(`**Values:** ${entry.values.join(', ')}`);
      lines.push('');
    }

    if (result.timelineTable) {
      lines.push('### BOD 26-04 Appendix A, Table 1');
      lines.push(
        '| # | Publicly Exposed | In KEV | Automatable | Technical Impact | Agency timeline | Days | Forensic triage |',
      );
      lines.push('|--:|:--|:--|:--|:--|:--|--:|:--|');
      for (const row of result.timelineTable) {
        lines.push(
          `| ${row.row} | ${row.publiclyExposed ? 'Yes' : 'No'} | ${row.inKev ? 'Yes' : 'No'} | ${
            row.automatable ? 'Yes' : 'No'
          } | ${row.technicalImpact} | ${row.timelineLabel} | ${
            row.remediationTimelineDays === null ? 'n/a' : row.remediationTimelineDays
          } | ${row.forensicTriageRequired ? 'required' : 'not required'} |`,
        );
      }
      lines.push('');
    }

    if (result.definitions) {
      lines.push('### Definitions');
      for (const entry of result.definitions)
        lines.push(`- **${entry.term}** — ${entry.definition}`);
      lines.push('');
    }

    if (result.supersedes) {
      lines.push('### Supersedes');
      for (const entry of result.supersedes) {
        lines.push(`- **${entry.directive}** (issued ${entry.issued}) — ${entry.note}`);
      }
      lines.push('');
    }

    if (result.sources) {
      const { kev, csafMirror, vulnrichment, feeds } = result.sources;
      lines.push('### Live data held by this server');
      lines.push(
        `- **KEV catalog** — version ${kev.catalogVersion ?? 'not loaded'}, released ${
          kev.dateReleased ?? 'not loaded'
        }, ${kev.count ?? 'no'} entries. Last checked ${kev.lastCheckedAt ?? 'never'}; upstream Last-Modified ${
          kev.lastModified ?? 'unknown'
        }; refresh cron \`${kev.refreshCron}\`.`,
      );
      lines.push(
        `- **ICS advisory index** — ready: ${csafMirror.ready ? 'yes' : 'no'}, ${
          csafMirror.documentCount ?? 'no'
        } documents, sync status ${csafMirror.syncStatus}, checkpoint ${
          csafMirror.checkpoint ?? 'none'
        }, last completed ${csafMirror.lastCompletedAt ?? 'never'}.`,
      );
      if (csafMirror.unavailableReason) {
        lines.push(
          `  - The index cannot be opened — unavailable: ${csafMirror.unavailableReason.replaceAll('_', ' ')}. The ICS tools fail until the server operator sets CISA_CSAF_MIRROR_PATH to a writable path; every other tool works.`,
        );
      }
      lines.push(
        `- **Vulnrichment** — mode ${vulnrichment.mode}, cache TTL ${vulnrichment.cacheTtlSeconds}s.`,
      );
      lines.push(`- **RSS feeds** — ${feeds.windowItems} items per feed window.`);
      if (feeds.cached.length === 0) {
        lines.push('  - No feed window is cached yet.');
      } else {
        for (const entry of feeds.cached) {
          lines.push(
            `  - \`${entry.feed}\`: ${entry.oldest ?? 'unknown'} → ${entry.newest ?? 'unknown'} (fetched ${entry.fetchedAt})`,
          );
        }
      }
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
