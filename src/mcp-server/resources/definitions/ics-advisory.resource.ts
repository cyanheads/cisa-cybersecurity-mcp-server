/**
 * @fileoverview `cisa://advisory/{advisoryId}` — one flattened ICS advisory,
 * carrying the identical outline-on-overflow treatment `cisa_get_advisory`
 * applies on a no-`sections` call.
 *
 * Nothing about reading an advisory through a resource template makes a 1.38 MB,
 * 585-product document cheaper to hand back whole, and a resource client has no
 * `sections` or `cves` parameter to opt out with — so a caller who lands on the
 * outline arm follows up with `cisa_get_advisory` to name the sections, or the
 * vulnerability CVE IDs, it needs. The outline lists both.
 * @module mcp-server/resources/definitions/ics-advisory.resource
 */

import { resource, z } from '@cyanheads/mcp-ts-core';
import { configurationError, notFound, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { outlineOnOverflow } from '@cyanheads/mcp-ts-core/utils';
import {
  ADVISORY_OUTLINE_BUDGET,
  AdvisoryDocumentOutputShape,
  AdvisoryIdInputSchema,
  cvesNarrowingHint,
  extractAdvisorySections,
  indexFreshnessNote,
} from '@/mcp-server/schemas/advisory.js';
import { getCsafMirror } from '@/services/csaf-mirror/csaf-mirror-service.js';

/** Entries surfaced by `list()` and the maximum completion suggestions. */
const LIST_LIMIT = 30;
const COMPLETION_LIMIT = 100;

export const icsAdvisoryResource = resource('cisa://advisory/{advisoryId}', {
  name: 'ics-advisory',
  title: 'ICS advisory (CSAF)',
  description:
    'One CISA industrial control system advisory, flattened from CSAF 2.0 — affected products with version ranges, per-CVE CVSS and CWE, remediations, sectors, and revision history. Large advisories return a section outline instead of the whole document; follow up with cisa_get_advisory to request named sections. Listing returns the 30 most recently revised advisories.',
  mimeType: 'application/json',
  /* Advisories revise rarely; the index itself refreshes every six hours. */
  cacheHint: { ttlMs: 21_600_000, cacheScope: 'public' },

  params: z.object({
    advisoryId: AdvisoryIdInputSchema.describe(
      'The advisory identifier, e.g. ICSA-26-260-07. Case, surrounding whitespace, and a trailing .json are normalized.',
    ),
  }),

  output: z.object(AdvisoryDocumentOutputShape),

  async handler(params) {
    const mirror = getCsafMirror();
    const availability = await mirror.availability();
    if (availability.status === 'unavailable') {
      throw configurationError(
        `The ICS advisory index cannot be opened (${availability.reason.replaceAll('_', ' ')}).`,
        {
          reason: 'mirror_unavailable',
          retryable: false,
          recovery: {
            hint: 'The server operator must set CISA_CSAF_MIRROR_PATH to a writable path and restart. Retrying will not help, but the cisa://kev resource and the KEV, SSVC, and alert tools still work.',
          },
        },
      );
    }
    if (availability.status === 'not_ready') {
      throw serviceUnavailable('The ICS advisory index is still building.', {
        reason: 'mirror_not_ready',
        retryable: true,
        recovery: {
          hint: 'Call cisa_list_reference with topic sources to check the index progress, then read this resource again.',
        },
      });
    }

    const { advisoryId } = params;
    const doc = await mirror.getAdvisory(advisoryId);
    if (!doc) {
      const index = await mirror.state();
      throw notFound(
        `No advisory with ID ${advisoryId} is in the index. ${indexFreshnessNote(advisoryId, index)} Call cisa_search_ics_advisories to find the right ID.`,
        {
          advisoryId,
          indexCheckpoint: index.checkpoint,
          indexLastSyncedAt: index.lastCompletedAt,
        },
      );
    }

    const result = outlineOnOverflow(doc as unknown as Record<string, unknown>, {
      budget: ADVISORY_OUTLINE_BUDGET,
      extract: () => extractAdvisorySections(doc),
    });
    if (result.kind === 'outline') {
      /*
       * The framework notice tells the caller to re-call "this tool" with
       * `sections`, which a resource read cannot do — route to the tool by name.
       */
      const { notice: _notice, ...outline } = result;
      const smallest = [...outline.sections].sort((a, b) => a.bytes - b.bytes)[0];
      const example = smallest
        ? ` — e.g. sections: ["${smallest.name}"] (${smallest.bytes} bytes)`
        : '';
      const hint = cvesNarrowingHint(outline.sections, ADVISORY_OUTLINE_BUDGET);
      return {
        ...outline,
        outlineNotice: `Advisory too large to inline against a ${ADVISORY_OUTLINE_BUDGET}-byte budget; this is its section outline. Call cisa_get_advisory with advisoryId "${advisoryId}" and sections naming the sections you need${example}. A selection returns whatever it names, so sum the listed sizes before requesting several.${hint ? ` ${hint}` : ''}`,
      };
    }
    return result;
  },

  /* Listing and completion degrade to empty on an unopenable index: a throw here
   * would fail the whole resources/list, KEV entries included. */
  list: async () => {
    const mirror = getCsafMirror();
    if ((await mirror.availability()).status !== 'ready') return { resources: [] };
    const recent = await mirror.recentlyRevised(LIST_LIMIT);
    return {
      resources: recent.map((entry) => ({
        uri: `cisa://advisory/${entry.advisoryId}`,
        name: `${entry.advisoryId} — ${entry.title}`,
        mimeType: 'application/json',
      })),
    };
  },

  complete: {
    advisoryId: async (partial) => {
      const mirror = getCsafMirror();
      if ((await mirror.availability()).status !== 'ready') return [];
      return mirror.completeAdvisoryIds(partial, COMPLETION_LIMIT);
    },
  },
});
