/**
 * @fileoverview Smoke test — the registered MCP surface is exactly seven
 * tools, two resources, and zero prompts, matching `docs/design.md`.
 * @module tests/smoke/surface.test
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { allResourceDefinitions } from '@/mcp-server/resources/definitions/index.js';
import { allToolDefinitions } from '@/mcp-server/tools/definitions/index.js';

describe('registered MCP surface', () => {
  it('exposes exactly seven tools', () => {
    expect(allToolDefinitions).toHaveLength(7);
    const names = allToolDefinitions.map((def) => def.name);
    expect(new Set(names).size).toBe(7); /* every name unique */
    expect(names.sort()).toEqual(
      [
        'cisa_check_cve_status',
        'cisa_get_advisory',
        'cisa_get_alerts',
        'cisa_get_ssvc',
        'cisa_list_reference',
        'cisa_search_ics_advisories',
        'cisa_search_kev',
      ].sort(),
    );
  });

  it('every tool is read-only per its annotations', () => {
    for (const def of allToolDefinitions) {
      expect(def.annotations?.readOnlyHint).toBe(true);
    }
  });

  it('exposes exactly two resources', () => {
    expect(allResourceDefinitions).toHaveLength(2);
    const names = allResourceDefinitions.map((def) => def.name);
    expect(names.sort()).toEqual(['ics-advisory', 'kev-entry'].sort());
  });

  it('registers no prompt definitions — there is no prompts/definitions directory', () => {
    const promptsDir = join(process.cwd(), 'src/mcp-server/prompts');
    expect(existsSync(promptsDir)).toBe(false);
  });
});
