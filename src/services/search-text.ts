/**
 * @fileoverview The ceiling on caller-supplied free text before it reaches a
 * query engine.
 *
 * `cisa_search_ics_advisories` turns `q` into an FTS5 `MATCH` expression and
 * `vendor`/`product` into `GLOB` patterns, which SQLite refuses past 50,000
 * bytes, and `cisa_search_kev` tokenizes `nameContains` against every record in
 * the catalog snapshot, so the work a single call costs scales with the length of
 * the string it was handed. The input schemas set a minimum but no maximum — a maximum
 * belongs at the sink that does the work, where it holds for every caller of the
 * function rather than only for the one tool whose schema declares it.
 * @module services/search-text
 */

import { validationError } from '@cyanheads/mcp-ts-core/errors';

/**
 * Characters a free-text search value may carry. Generous against real queries —
 * a vendor, product, or title phrase is a handful of words — and small enough
 * that the tokenized work stays bounded.
 */
export const MAX_SEARCH_TEXT_LENGTH = 512;

/**
 * Reject a free-text search value longer than {@link MAX_SEARCH_TEXT_LENGTH}.
 * Loud rather than truncating: a silently shortened query answers a narrower
 * question than the one asked, and the caller would have no way to tell.
 */
export function assertSearchTextLength(value: string, field: string): void {
  if (value.length <= MAX_SEARCH_TEXT_LENGTH) return;
  throw validationError(
    `${field} is ${value.length} characters; the limit is ${MAX_SEARCH_TEXT_LENGTH} characters. Reduce it to the terms you want to match and call this tool again.`,
    {
      reason: 'search_text_too_long',
      field,
      length: value.length,
      limit: MAX_SEARCH_TEXT_LENGTH,
      recovery: {
        hint: `Shorten ${field} to at most ${MAX_SEARCH_TEXT_LENGTH} characters, then call this tool again.`,
      },
    },
  );
}
