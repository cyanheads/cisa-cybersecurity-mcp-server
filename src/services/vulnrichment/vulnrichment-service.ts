/**
 * @fileoverview Vulnrichment service — the Tier 3 per-CVE fetch. The repository
 * is ~343 MB against a corpus a triage session touches tens of records from, so
 * mirroring it would cost three orders of magnitude more than it saves. Each CVE
 * is fetched from `raw.githubusercontent.com` (which honors `If-None-Match`, and
 * sets `max-age=300`) and the normalized result is cached in `ctx.state`.
 *
 * Cache reads and writes are best-effort in both directions — a miss or a storage
 * failure falls through to a fetch, so correctness never depends on the cache.
 * The cached value is a deterministic public-identifier-to-record map, so the
 * shared `default` tenant is benign. A 404 caches as a negative at one sixth the
 * positive TTL: CISA enriches continuously, and a permanent negative cache would
 * hide a record that appeared an hour later.
 * @module services/vulnrichment/vulnrichment-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { withRetry } from '@cyanheads/mcp-ts-core/utils';
import { assertNotHtml, fetchUpstream, readUpstreamText } from '@/services/upstream-http.js';
import { cveToVulnrichmentUrl } from './paths.js';
import type { SsvcCvss, SsvcCwe, SsvcRecord, VulnrichmentState } from './types.js';

/** Concurrent per-CVE fetches. The source publishes no rate limit; this is self-imposed. */
const CONCURRENCY = 6;

/** Ceiling on one CVE record. They run 3–15 KB; this is three orders above that. */
const RECORD_MAX_BYTES = 16 * 1024 * 1024;

/** Guidance strings, one per non-`ssvc` outcome. */
const GUIDANCE = {
  not_found:
    'CISA has published no enrichment record for this CVE. Call cisa_check_cve_status to see whether it is in KEV, which carries its own remediation deadline independent of SSVC.',
  no_cisa_container:
    'The CVE record exists but carries no CISA-authored enrichment container, so no SSVC decision points are available. Call cisa_check_cve_status for KEV status.',
  no_ssvc_metric:
    'CISA has enriched this CVE with CVSS or CWE data but has not published SSVC decision points for it. The CVSS and CWE values returned are what is available.',
} as const;

/** Options for {@link initVulnrichment}. */
export interface VulnrichmentOptions {
  /** TTL in seconds for a cached record. Negative results use one sixth of this. */
  cacheTtlSeconds: number;
  /** Per-request upstream timeout in milliseconds. */
  timeoutMs: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

/** Read the SSVC decision points out of a CISA-ADP `metrics[]` array. */
function readSsvc(metrics: unknown[]): {
  automatable?: string;
  exploitation?: string;
  role?: string;
  technicalImpact?: string;
  timestamp?: string;
  version?: string;
} | null {
  for (const metric of metrics) {
    if (!isRecord(metric) || !isRecord(metric.other)) continue;
    if (metric.other.type !== 'ssvc' || !isRecord(metric.other.content)) continue;
    const content = metric.other.content;
    const options = Array.isArray(content.options) ? content.options : [];

    const values: Record<string, string> = {};
    for (const option of options) {
      if (!isRecord(option)) continue;
      for (const [key, value] of Object.entries(option)) {
        if (typeof value === 'string') values[key] = value;
      }
    }

    const version = str(content.version);
    const timestamp = str(content.timestamp);
    const role = str(content.role);
    return {
      ...(values.Exploitation ? { exploitation: values.Exploitation } : {}),
      ...(values.Automatable ? { automatable: values.Automatable } : {}),
      /* The published key carries a space — "Technical Impact", not "TechnicalImpact". */
      ...(values['Technical Impact'] ? { technicalImpact: values['Technical Impact'] } : {}),
      ...(version ? { version } : {}),
      ...(timestamp ? { timestamp } : {}),
      ...(role ? { role } : {}),
    };
  }
  return null;
}

/** Read the first CVSS score CISA contributed, preferring v4 over v3.1 over v3.0. */
function readCvss(metrics: unknown[]): SsvcCvss | undefined {
  const keys = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0'] as const;
  for (const key of keys) {
    for (const metric of metrics) {
      if (!isRecord(metric)) continue;
      const score = metric[key];
      if (!isRecord(score)) continue;
      const baseScore = typeof score.baseScore === 'number' ? score.baseScore : undefined;
      if (baseScore === undefined) continue;
      return {
        version: str(score.version) ?? key,
        baseScore,
        baseSeverity: str(score.baseSeverity) ?? '',
        vectorString: str(score.vectorString) ?? '',
      };
    }
  }
  return undefined;
}

/** Read the CWE list out of a CISA-ADP `problemTypes[]` array. */
function readCwes(problemTypes: unknown[]): SsvcCwe[] {
  const cwes: SsvcCwe[] = [];
  for (const problemType of problemTypes) {
    if (!isRecord(problemType) || !Array.isArray(problemType.descriptions)) continue;
    for (const description of problemType.descriptions) {
      if (!isRecord(description)) continue;
      const cweId = str(description.cweId);
      if (!cweId) continue;
      cwes.push({ cweId, description: str(description.description) ?? '' });
    }
  }
  return cwes;
}

/** Normalize one CVE 5.x record into the domain shape. */
export function normalizeVulnrichment(cveId: string, sourceUrl: string, raw: unknown): SsvcRecord {
  const containers = isRecord(raw) && isRecord(raw.containers) ? raw.containers : undefined;
  const adp = containers && Array.isArray(containers.adp) ? containers.adp : [];

  const cisa = adp.find(
    (entry) =>
      isRecord(entry) &&
      isRecord(entry.providerMetadata) &&
      entry.providerMetadata.shortName === 'CISA-ADP',
  );

  if (!isRecord(cisa)) {
    return {
      cveId,
      outcome: 'no_cisa_container',
      guidance: GUIDANCE.no_cisa_container,
      cwes: [],
      sourceUrl,
    };
  }

  const metrics = Array.isArray(cisa.metrics) ? cisa.metrics : [];
  const problemTypes = Array.isArray(cisa.problemTypes) ? cisa.problemTypes : [];
  const cvss = readCvss(metrics);
  const cwes = readCwes(problemTypes);
  const ssvc = readSsvc(metrics);

  if (!ssvc?.automatable || !ssvc.technicalImpact) {
    return {
      cveId,
      outcome: 'no_ssvc_metric',
      guidance: GUIDANCE.no_ssvc_metric,
      cwes,
      ...(cvss ? { cvss } : {}),
      sourceUrl,
    };
  }

  return {
    cveId,
    outcome: 'ssvc',
    ...(ssvc.exploitation ? { exploitation: ssvc.exploitation } : {}),
    automatable: ssvc.automatable,
    technicalImpact: ssvc.technicalImpact,
    ...(ssvc.version ? { ssvcVersion: ssvc.version } : {}),
    ...(ssvc.timestamp ? { ssvcTimestamp: ssvc.timestamp } : {}),
    ...(ssvc.role ? { ssvcRole: ssvc.role } : {}),
    ...(cvss ? { cvss } : {}),
    cwes,
    sourceUrl,
  };
}

export class VulnrichmentService {
  constructor(private readonly options: VulnrichmentOptions) {}

  /** In-process state for `cisa_list_reference` topic `sources`. */
  state(): VulnrichmentState {
    return { mode: 'on_demand', cacheTtlSeconds: this.options.cacheTtlSeconds };
  }

  /**
   * Fetch decision points for a batch of CVEs with a fixed concurrency cap. Every
   * CVE yields a result: a transport failure becomes a `fetch_failed` record so a
   * partial outage degrades one row rather than the whole call.
   */
  async fetchMany(cveIds: string[], ctx: Context): Promise<SsvcRecord[]> {
    const results = new Array<SsvcRecord>(cveIds.length);
    let next = 0;

    const worker = async (): Promise<void> => {
      while (next < cveIds.length) {
        const index = next++;
        const cveId = cveIds[index] as string;
        results[index] = await this.fetchOne(cveId, ctx);
      }
    };

    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, cveIds.length) }, () => worker()));
    return results;
  }

  private async fetchOne(cveId: string, ctx: Context): Promise<SsvcRecord> {
    const sourceUrl = cveToVulnrichmentUrl(cveId);
    if (sourceUrl === null) {
      return {
        cveId,
        outcome: 'not_found',
        guidance: GUIDANCE.not_found,
        cwes: [],
        sourceUrl: '',
      };
    }

    const cacheKey = `ssvc/${cveId}`;
    const cached = await ctx.state.get<SsvcRecord>(cacheKey).catch(() => null);
    if (cached) return cached;

    let record: SsvcRecord;
    try {
      record = await withRetry(
        async () => {
          const response = await fetchUpstream(sourceUrl, {
            service: 'CISA Vulnrichment',
            timeoutMs: this.options.timeoutMs,
            acceptStatuses: [404],
            signal: ctx.signal,
          });
          if (response.status === 404) {
            return {
              cveId,
              outcome: 'not_found' as const,
              guidance: GUIDANCE.not_found,
              cwes: [],
              sourceUrl,
            };
          }
          const body = await readUpstreamText(response, {
            maxBytes: RECORD_MAX_BYTES,
            service: 'CISA Vulnrichment',
            url: sourceUrl,
          });
          assertNotHtml(body, response.headers.get('content-type'), 'json', sourceUrl);
          return normalizeVulnrichment(cveId, sourceUrl, JSON.parse(body));
        },
        {
          operation: 'VulnrichmentService.fetchOne',
          baseDelayMs: 500,
          context: ctx,
          signal: ctx.signal,
        },
      );
    } catch (error) {
      ctx.log.warning('Vulnrichment fetch failed', {
        cveId,
        error: error instanceof Error ? error.message : String(error),
      });
      return {
        cveId,
        outcome: 'fetch_failed',
        guidance: `The CISA enrichment source could not be reached for this CVE (${
          error instanceof Error ? error.message : String(error)
        }). Retry in a few minutes, or call cisa_check_cve_status which serves from a cached catalog and needs no network.`,
        cwes: [],
        sourceUrl,
      };
    }

    const ttl =
      record.outcome === 'not_found'
        ? Math.max(1, Math.floor(this.options.cacheTtlSeconds / 6))
        : this.options.cacheTtlSeconds;
    await ctx.state.set(cacheKey, record, { ttl }).catch(() => {
      /* Best-effort: a storage failure must not fail the lookup. */
    });

    return record;
  }
}

// --- Init/accessor pattern ---

let _service: VulnrichmentService | undefined;

/** Construct the Vulnrichment service. Call once from `createApp`'s `setup()`. */
export function initVulnrichment(options: VulnrichmentOptions): VulnrichmentService {
  _service = new VulnrichmentService(options);
  return _service;
}

/** Access the initialized Vulnrichment service. */
export function getVulnrichment(): VulnrichmentService {
  if (!_service) {
    throw new Error('VulnrichmentService not initialized — call initVulnrichment() in setup().');
  }
  return _service;
}

/** Reset the singleton — test-only. */
export function resetVulnrichment(): void {
  _service = undefined;
}
