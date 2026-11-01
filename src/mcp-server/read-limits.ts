/**
 * @fileoverview Shared workload caps and normalization telemetry for CISA read inputs.
 * @module mcp-server/read-limits
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import { ATTR_MCP_TOOL_NAME, createCounter } from '@cyanheads/mcp-ts-core/utils';
import { getServerConfig } from '@/config/server-config.js';

/** Advertised ceiling; handlers retain the smaller per-call workload caps below. */
export const READ_INPUT_HARD_CEILING = 1_000;

/** The input and workload cap for each read that supports oversized requests. */
export const READ_INPUT_LIMITS = {
  cisa_check_cve_status: { input: 'cveIds', cap: 200 },
  cisa_get_ssvc: { input: 'cveIds', cap: 50 },
  cisa_search_kev: { input: 'limit', cap: 100 },
  cisa_search_ics_advisories: { input: 'limit', cap: 50 },
  cisa_get_alerts: { input: 'limit', cap: 30 },
} as const;

let normalizedInputs: ReturnType<typeof createCounter> | undefined;

/**
 * Apply the read cap before upstream or index work. Throws `read_limit_exceeded`
 * when normalization is disabled; callers disclose any omitted rows or IDs.
 */
export function applyReadLimit(
  toolName: keyof typeof READ_INPUT_LIMITS,
  requested: number,
  ctx: Pick<Context, 'log'>,
): number {
  const { cap, input } = READ_INPUT_LIMITS[toolName];
  if (requested <= cap) return requested;
  if (!getServerConfig().clampOversizedInputs) {
    throw validationError(
      `${input} exceeds this tool's per-call cap of ${cap}. Send at most ${cap} per call.`,
      {
        reason: 'read_limit_exceeded',
        retryable: false,
      },
    );
  }
  normalizedInputs ??= createCounter(
    'mcp.cisa.input.normalized',
    'CISA read inputs reduced to their per-call workload cap.',
    '{inputs}',
  );
  normalizedInputs.add(1, { [ATTR_MCP_TOOL_NAME]: toolName, 'mcp.input.name': input });
  ctx.log.info('Applied CISA read input cap', { tool: toolName, input, requested, effective: cap });
  return cap;
}
