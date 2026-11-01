/**
 * @fileoverview Read-cap boundaries, strict-mode refusal, and normalization logging.
 * @module tests/mcp-server/read-limits.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { resetServerConfig } from '@/config/server-config.js';
import { applyReadLimit } from '@/mcp-server/read-limits.js';

afterEach(() => {
  vi.unstubAllEnvs();
  resetServerConfig();
});

describe('read workload limits', () => {
  it.each([
    ['cisa_check_cve_status', 'cveIds', 200],
    ['cisa_get_ssvc', 'cveIds', 50],
    ['cisa_search_kev', 'limit', 100],
    ['cisa_search_ics_advisories', 'limit', 50],
    ['cisa_get_alerts', 'limit', 30],
  ] as const)('%s bounds work and records only normalization', (toolName, input, cap) => {
    vi.stubEnv('CISA_CLAMP_OVERSIZED_INPUTS', 'true');
    resetServerConfig();
    const ctx = createMockContext();
    const log = vi.spyOn(ctx.log, 'info');
    expect(applyReadLimit(toolName, cap - 1, ctx)).toBe(cap - 1);
    expect(applyReadLimit(toolName, cap, ctx)).toBe(cap);
    expect(log).not.toHaveBeenCalled();
    expect(applyReadLimit(toolName, cap + 1, ctx)).toBe(cap);
    expect(log).toHaveBeenCalledExactlyOnceWith('Applied CISA read input cap', {
      tool: toolName,
      input,
      requested: cap + 1,
      effective: cap,
    });
  });

  it('strict mode rejects excess before recording normalization', () => {
    vi.stubEnv('CISA_CLAMP_OVERSIZED_INPUTS', 'false');
    resetServerConfig();
    const ctx = createMockContext();
    const log = vi.spyOn(ctx.log, 'info');
    expect(applyReadLimit('cisa_check_cve_status', 200, ctx)).toBe(200);
    expect(() => applyReadLimit('cisa_check_cve_status', 201, ctx)).toThrow(
      expect.objectContaining({
        code: JsonRpcErrorCode.ValidationError,
        data: expect.objectContaining({ reason: 'read_limit_exceeded', retryable: false }),
      }),
    );
    expect(log).not.toHaveBeenCalled();
  });
});
