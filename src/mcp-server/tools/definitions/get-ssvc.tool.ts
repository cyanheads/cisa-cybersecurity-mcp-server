/**
 * @fileoverview `cisa_get_ssvc` — the SSVC decision points CISA publishes per CVE,
 * plus the BOD 26-04 remediation timeline they imply for a caller-stated asset
 * exposure.
 *
 * Three of the four Table 1 decision points come from CISA: Automatable and
 * Technical Impact from Vulnrichment, In the KEV from this server's own catalog
 * snapshot. The fourth, Publicly Exposed, is a property of the caller's estate
 * and CISA cannot publish it — so it is an input, and `unknown` returns both arms
 * rather than a guess.
 *
 * The computed timeline and CISA's own assigned KEV due date are reported side by
 * side and never reconciled: in a 24-CVE sample, 9 disagreed under a
 * publicly-exposed assumption.
 * @module mcp-server/tools/definitions/get-ssvc.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { CVE_ID_REGEX, CveIdInputSchema, ISO_DATE_REGEX } from '@/mcp-server/schemas/kev-record.js';
import {
  BOD_2604_BASIS,
  BOD_2604_CAVEAT,
  resolveBod2604Timeline,
  type TechnicalImpact,
} from '@/reference/bod-2604.js';
import { getKevCatalog } from '@/services/kev-catalog/kev-catalog-service.js';
import { daysBetween } from '@/services/kev-catalog/parse.js';
import { getVulnrichment } from '@/services/vulnrichment/vulnrichment-service.js';

/** The exposure arms returned when the caller cannot state one. */
const BOTH_ARMS = ['publicly_exposed', 'not_publicly_exposed'] as const;

export const getSsvcTool = tool('cisa_get_ssvc', {
  title: 'cisa_get_ssvc',
  description:
    "Fetch the SSVC decision points CISA publishes per CVE as a CVE Authorized Data Publisher — Exploitation, Automatable, and Technical Impact — along with the CVSS score and CWE CISA contributes where present, and compute the BOD 26-04 remediation timeline those values imply for the asset exposure you supply. The computed timeline applies CISA's published decision table to CISA's published decision points and your stated exposure; it is not a compliance determination and it is not CISA's own due-date assignment, which is reported separately when the CVE is in KEV and can differ. Not every CVE is enriched — a miss returns found false with guidance rather than an error. Call cisa_list_reference with topic ssvc_values for the decision-point vocabulary.",
  annotations: { readOnlyHint: true, idempotentHint: true },

  input: z.object({
    cveIds: z
      .array(
        CveIdInputSchema.describe(
          'One CVE identifier, e.g. CVE-2025-39964. Case and surrounding whitespace are normalized.',
        ),
      )
      .min(1)
      .max(50)
      .describe(
        "CVE identifiers to look up, up to 50 per call — lower than cisa_check_cve_status's 200-CVE cap because each CVE needs its own live enrichment lookup rather than a cached batch check.",
      ),
    assetExposure: z
      .enum(['publicly_exposed', 'not_publicly_exposed', 'unknown'])
      .default('unknown')
      .describe(
        'Whether the affected asset is reachable by unauthenticated or untrusted entities over public networks. The one BOD 26-04 decision point CISA cannot publish. "unknown" returns both arms so the spread is visible without guessing.',
      ),
  }),

  output: z.object({
    results: z
      .array(
        z
          .object({
            cveId: z
              .string()
              .regex(CVE_ID_REGEX)
              .describe('The CVE identifier that was looked up.'),
            found: z
              .boolean()
              .describe('Whether CISA has published SSVC decision points for this CVE.'),
            exploitation: z
              .string()
              .optional()
              .describe(
                'The SSVC Exploitation value (none, poc, or active). Values outside that set are passed through verbatim.',
              ),
            automatable: z.string().optional().describe('The SSVC Automatable value (yes or no).'),
            technicalImpact: z
              .string()
              .optional()
              .describe('The SSVC Technical Impact value (partial or total).'),
            ssvcVersion: z
              .string()
              .optional()
              .describe('SSVC schema version CISA published against.'),
            ssvcTimestamp: z
              .string()
              .optional()
              .describe('When CISA published these decision points, ISO 8601.'),
            ssvcRole: z
              .string()
              .optional()
              .describe('The SSVC role CISA recorded, e.g. CISA Coordinator.'),
            cvss: z
              .object({
                version: z.string().describe('CVSS version of the contributed score.'),
                baseScore: z.number().describe('CVSS base score, 0.0 through 10.0.'),
                baseSeverity: z.string().describe('Qualitative severity band as published.'),
                vectorString: z.string().describe('The full CVSS vector string.'),
              })
              .optional()
              .describe('The CVSS score CISA contributed through its ADP container, when present.'),
            cwes: z
              .array(
                z
                  .object({
                    cweId: z
                      .string()
                      .regex(/^CWE-[0-9]+$/)
                      .describe('CWE identifier.'),
                    description: z.string().describe('CWE name as published.'),
                  })
                  .describe('One CWE from the CISA-authored container.'),
              )
              .describe('CWEs CISA contributed. Empty when none were published.'),
            inKev: z
              .boolean()
              .describe("Whether the CVE is in this server's KEV catalog snapshot."),
            bod2604: z
              .object({
                timelines: z
                  .array(
                    z
                      .object({
                        assetExposure: z
                          .enum(['publicly_exposed', 'not_publicly_exposed'])
                          .describe('The exposure arm this timeline applies to.'),
                        tableRow: z
                          .number()
                          .int()
                          .describe('BOD 26-04 Table 1 row number, 1 to 16.'),
                        timelineLabel: z
                          .string()
                          .describe("The agency timeline in the directive's own wording."),
                        remediationTimelineDays: z
                          .number()
                          .int()
                          .nullable()
                          .describe('Calendar days allowed, or null for "Fix on system upgrade".'),
                        forensicTriageRequired: z
                          .boolean()
                          .describe('Whether a forensic triage of the asset is also required.'),
                      })
                      .describe('One computed remediation timeline.'),
                  )
                  .describe(
                    'One timeline per exposure arm — one when the caller stated an exposure, both when it is unknown.',
                  ),
                basis: z.string().describe('The decision table the timeline was resolved against.'),
                caveat: z
                  .string()
                  .describe('What the computation is and is not. Fixed text on every result.'),
              })
              .optional()
              .describe('The BOD 26-04 timeline implied by the published decision points.'),
            kevAssigned: z
              .object({
                dateAdded: z
                  .string()
                  .regex(ISO_DATE_REGEX)
                  .describe('Date CISA added the CVE to the KEV catalog.'),
                dueDate: z
                  .string()
                  .regex(ISO_DATE_REGEX)
                  .describe('Federal remediation deadline CISA assigned.'),
                daysFromAdd: z.number().int().describe('Calendar days from dateAdded to dueDate.'),
                forensicTriage: z
                  .enum(['Yes', 'No'])
                  .describe('Whether the KEV entry is in the three-day forensic-triage tier.'),
                directive: z
                  .enum(['BOD 26-04', 'BOD 22-01'])
                  .nullable()
                  .describe('The directive the KEV entry cites, or null when it cites neither.'),
              })
              .optional()
              .describe("CISA's own assignment for this CVE, reported alongside the computation."),
            assignmentAgrees: z
              .boolean()
              .optional()
              .describe(
                "Whether CISA's assigned deadline matches the computed timeline. Present only when the CVE is in KEV and an exposure was stated. Reported, never reconciled.",
              ),
            sourceUrl: z
              .string()
              .describe('The Vulnrichment record URL this result was read from.'),
            guidance: z
              .string()
              .optional()
              .describe('What to do instead, present on every result where found is false.'),
          })
          .describe('One SSVC lookup result.'),
      )
      .describe('One result per requested CVE, in the order supplied.'),
    foundCount: z.number().int().describe('How many CVEs carry published SSVC decision points.'),
    notFoundCount: z.number().int().describe('How many CVEs do not.'),
  }),

  enrichment: {
    echo: z
      .object({
        assetExposure: z.string().describe('The asset exposure the server applied.'),
        requested: z.number().int().describe('How many CVE IDs were requested.'),
      })
      .describe('The request as the server parsed it.'),
    notice: z
      .string()
      .optional()
      .describe('Guidance when nothing was enriched, or when a decision timestamp predates KEV.'),
  },

  enrichmentTrailer: {
    echo: {
      render: (echo) =>
        `**Request:** ${echo.requested} CVE(s), assetExposure ${echo.assetExposure}`,
    },
  },

  errors: [
    {
      reason: 'enrichment_source_unavailable',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'Every per-CVE fetch failed with a transport or 5xx error.',
      retryable: true,
      recovery:
        'The CISA enrichment source is unreachable; retry in a few minutes, or call cisa_check_cve_status which serves from a cached catalog and needs no network.',
    },
  ],

  async handler(input, ctx) {
    const cveIds = input.cveIds.map((id) => id.trim().toUpperCase());
    const catalog = getKevCatalog();
    const snapshot = await catalog.snapshot(ctx);
    const records = await getVulnrichment().fetchMany(cveIds, ctx);

    if (records.length > 0 && records.every((record) => record.outcome === 'fetch_failed')) {
      throw ctx.fail(
        'enrichment_source_unavailable',
        `All ${records.length} Vulnrichment fetches failed.`,
        { ...ctx.recoveryFor('enrichment_source_unavailable') },
      );
    }

    let lagging = 0;
    const results = records.map((record) => {
      const kev = snapshot.byId.get(record.cveId);
      const inKev = kev !== undefined;
      const found = record.outcome === 'ssvc';

      const exposures =
        input.assetExposure === 'unknown'
          ? BOTH_ARMS
          : ([input.assetExposure] as ReadonlyArray<'publicly_exposed' | 'not_publicly_exposed'>);

      const bod2604 =
        found && record.automatable && record.technicalImpact
          ? {
              timelines: exposures.map((assetExposure) => {
                const row = resolveBod2604Timeline({
                  publiclyExposed: assetExposure === 'publicly_exposed',
                  inKev,
                  automatable: record.automatable === 'yes',
                  technicalImpact: record.technicalImpact as TechnicalImpact,
                });
                return {
                  assetExposure,
                  tableRow: row.row,
                  timelineLabel: row.timelineLabel,
                  remediationTimelineDays: row.remediationTimelineDays,
                  forensicTriageRequired: row.forensicTriageRequired,
                };
              }),
              basis: BOD_2604_BASIS,
              caveat: BOD_2604_CAVEAT,
            }
          : undefined;

      const kevAssigned = kev
        ? {
            dateAdded: kev.dateAdded,
            dueDate: kev.dueDate,
            daysFromAdd: daysBetween(kev.dateAdded, kev.dueDate),
            forensicTriage: kev.forensicTriage,
            directive: kev.directive,
          }
        : undefined;

      const assignmentAgrees =
        kevAssigned && bod2604 && input.assetExposure !== 'unknown'
          ? bod2604.timelines[0]?.remediationTimelineDays === kevAssigned.daysFromAdd
          : undefined;

      if (kev && record.ssvcTimestamp && record.ssvcTimestamp.slice(0, 10) < kev.dateAdded) {
        lagging += 1;
      }

      return {
        cveId: record.cveId,
        found,
        ...(record.exploitation ? { exploitation: record.exploitation } : {}),
        ...(record.automatable ? { automatable: record.automatable } : {}),
        ...(record.technicalImpact ? { technicalImpact: record.technicalImpact } : {}),
        ...(record.ssvcVersion ? { ssvcVersion: record.ssvcVersion } : {}),
        ...(record.ssvcTimestamp ? { ssvcTimestamp: record.ssvcTimestamp } : {}),
        ...(record.ssvcRole ? { ssvcRole: record.ssvcRole } : {}),
        ...(record.cvss ? { cvss: record.cvss } : {}),
        cwes: record.cwes,
        inKev,
        ...(bod2604 ? { bod2604 } : {}),
        ...(kevAssigned ? { kevAssigned } : {}),
        ...(assignmentAgrees !== undefined ? { assignmentAgrees } : {}),
        sourceUrl: record.sourceUrl,
        ...(record.guidance ? { guidance: record.guidance } : {}),
      };
    });

    const foundCount = results.filter((result) => result.found).length;
    ctx.log.info('Resolved SSVC decision points', { requested: cveIds.length, found: foundCount });

    ctx.enrich({ echo: { assetExposure: input.assetExposure, requested: cveIds.length } });

    if (foundCount === 0) {
      ctx.enrich.notice(
        'None of the requested CVEs carry published SSVC decision points. Coverage is incomplete — not every CVE, including some in the KEV catalog, has a Vulnrichment record. Call cisa_check_cve_status for KEV status, which carries its own remediation deadline independent of SSVC.',
      );
    } else if (lagging > 0) {
      ctx.enrich.notice(
        `SSVC decision points for ${lagging} of the CVEs were published before CISA added them to KEV and may not reflect current exploitation status.`,
      );
    }

    return { results, foundCount, notFoundCount: results.length - foundCount };
  },

  format: (result) => {
    const lines: string[] = [
      `**${result.foundCount} of ${result.foundCount + result.notFoundCount} CVEs carry published SSVC decision points** (${result.notFoundCount} without).`,
      '',
    ];

    for (const entry of result.results) {
      lines.push(`### ${entry.cveId}`);
      lines.push(
        `**SSVC decision points found:** ${entry.found ? 'yes' : 'no'} · **In KEV:** ${entry.inKev ? 'yes' : 'no'}`,
      );
      if (entry.exploitation || entry.automatable || entry.technicalImpact) {
        lines.push(
          `**Decision points:** Exploitation ${entry.exploitation ?? 'not published'} · Automatable ${
            entry.automatable ?? 'not published'
          } · Technical Impact ${entry.technicalImpact ?? 'not published'}`,
        );
      }
      if (entry.ssvcVersion || entry.ssvcTimestamp || entry.ssvcRole) {
        lines.push(
          `**Published:** version ${entry.ssvcVersion ?? 'unknown'}, ${
            entry.ssvcTimestamp ?? 'unknown timestamp'
          }, role ${entry.ssvcRole ?? 'unknown'}`,
        );
      }
      if (entry.cvss) {
        lines.push(
          `**CISA CVSS:** ${entry.cvss.baseScore} ${entry.cvss.baseSeverity} (v${entry.cvss.version}) \`${entry.cvss.vectorString}\``,
        );
      }
      lines.push(
        `**CWEs:** ${
          entry.cwes.length > 0
            ? /* The published description usually repeats the ID; drop the duplicate prefix. */
              entry.cwes
                .map(
                  (cwe) =>
                    `${cwe.cweId} — ${
                      cwe.description.startsWith(cwe.cweId)
                        ? cwe.description.slice(cwe.cweId.length).trim()
                        : cwe.description
                    }`,
                )
                .join('; ')
            : 'none published'
        }`,
      );
      if (entry.bod2604) {
        lines.push('**BOD 26-04 computed timeline:**');
        for (const timeline of entry.bod2604.timelines) {
          lines.push(
            `- ${timeline.assetExposure}: row ${timeline.tableRow} — ${timeline.timelineLabel} (${
              timeline.remediationTimelineDays === null
                ? 'no fixed day count'
                : `${timeline.remediationTimelineDays} days`
            }, forensic triage ${timeline.forensicTriageRequired ? 'required' : 'not required'})`,
          );
        }
        lines.push(`  Basis: ${entry.bod2604.basis}`);
        lines.push(`  ${entry.bod2604.caveat}`);
      }
      if (entry.kevAssigned) {
        lines.push(
          `**CISA's assigned KEV deadline:** added ${entry.kevAssigned.dateAdded}, due ${entry.kevAssigned.dueDate} (${entry.kevAssigned.daysFromAdd} days), forensic triage ${entry.kevAssigned.forensicTriage}, directive ${entry.kevAssigned.directive ?? 'none'}`,
        );
      }
      if (entry.assignmentAgrees !== undefined) {
        lines.push(
          `**Assignment agrees with the computed timeline:** ${entry.assignmentAgrees ? 'yes' : 'no'}`,
        );
      }
      if (entry.guidance) lines.push(`**Guidance:** ${entry.guidance}`);
      lines.push(`**Source:** ${entry.sourceUrl}`);
      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
