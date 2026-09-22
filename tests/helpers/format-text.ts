/**
 * @fileoverview Shared test helpers for tool definition suites: extract the
 * `text` of the first content block a tool's `format()` produces, or every text
 * block of a contract-run result's `content[]`. Both assert the blocks exist
 * first, so callers never dereference past an optional-chaining short-circuit
 * the way `(tool.format?.(result)?.[0] as { text: string }).text` does.
 * @module tests/helpers/format-text
 */

import { expect } from 'vitest';

/** Returns the `text` field of the first block, asserting it is present. */
export function firstText(blocks: unknown[] | undefined): string {
  expect(blocks).toBeDefined();
  const block = blocks?.[0];
  expect(block).toBeDefined();
  return (block as { text: string }).text;
}

/**
 * Every text block of a `runToolContract` result's `content[]`, joined — the
 * rendered body plus the enrichment trailer, or the error envelope's text.
 */
export function contentText(result: { content?: unknown[] }): string {
  expect(result.content?.length).toBeGreaterThan(0);
  return (result.content ?? []).map((block) => (block as { text?: string }).text ?? '').join('\n');
}
