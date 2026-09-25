/**
 * @fileoverview Smoke test — the registered MCP surface is exactly seven
 * tools, two resources, and zero prompts, matching `docs/design.md`, and no
 * schema on it carries a regex whose meaning depends on a flag.
 * @module tests/smoke/surface.test
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { z } from '@cyanheads/mcp-ts-core';
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

  it('advertises no regex that leans on a flag — JSON Schema drops flags, so a strict client would read a different pattern', () => {
    const flagged = new Set<string>();
    const collect = (label: string, schema: z.ZodType | undefined, io: 'input' | 'output') => {
      if (!schema) return;
      z.toJSONSchema(schema, {
        io,
        override: ({ zodSchema, path }) => {
          const { checks } = zodSchema._zod.def as { checks?: Array<{ _zod: { def: unknown } }> };
          for (const check of checks ?? []) {
            const def = check._zod.def as { format?: string; pattern?: RegExp };
            if (def.format === 'regex' && def.pattern && def.pattern.flags !== '') {
              flagged.add(`${label} ${path.join('.')} /${def.pattern.source}/${def.pattern.flags}`);
            }
          }
        },
      });
    };
    let checked = 0;
    const count = (schema: z.ZodType | undefined) => {
      if (schema) checked += 1;
      return schema;
    };
    for (const def of allToolDefinitions) {
      collect(`${def.name} input`, count(def.input), 'input');
      const output = def.enrichment ? def.output?.extend(def.enrichment) : def.output;
      collect(`${def.name} output`, count(output), 'output');
    }
    for (const def of allResourceDefinitions) {
      collect(`${def.name} params`, count(def.params), 'input');
      collect(`${def.name} output`, count(def.output), 'output');
    }
    expect(checked).toBe(18);
    expect([...flagged]).toEqual([]);
  });

  it('registers no prompt definitions — there is no prompts/definitions directory', () => {
    const promptsDir = join(process.cwd(), 'src/mcp-server/prompts');
    expect(existsSync(promptsDir)).toBe(false);
  });
});
