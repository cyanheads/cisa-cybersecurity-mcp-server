/** Packaging selectors must preserve the MCP SDK's runtime Skills extension. */
import { describe, expect, it } from 'vitest';
import { AGENT_DOC_ENTRY as cleaner } from '../scripts/clean-mcpb.js';
import { AGENT_DOC_ENTRY as linter } from '../scripts/lint-packaging.js';

describe('dependency agent documentation selection', () => {
  it.each([cleaner, linter])('preserves runtime skill modules and SQLite prebuilds', (selector) => {
    expect(
      selector.test('node_modules/@modelcontextprotocol/server/dist/ext/skills/index.js'),
    ).toBe(false);
    expect(
      selector.test('node_modules/better-sqlite3/prebuilds/linux-x64/better_sqlite3.node'),
    ).toBe(false);
    expect(
      selector.test('node_modules/@cyanheads/mcp-ts-core/framework-skills/add-tool/SKILL.md'),
    ).toBe(true);
    expect(selector.test('node_modules/outer/node_modules/inner/skills/example/SKILL.md')).toBe(
      true,
    );
  });
});
