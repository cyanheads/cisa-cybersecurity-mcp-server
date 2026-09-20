/**
 * @fileoverview Pure helpers for the CISA RSS feeds — HTML stripping with entity
 * decoding, `pubDate` normalization, and the advisory-ID extractor that makes a
 * feed item chain into `cisa_get_advisory`. No I/O.
 * @module services/cisa-feeds/normalize
 */

/** Named entities the feeds actually emit, plus the numeric forms. */
function decodeEntities(value: string): string {
  return value
    .replace(/&nbsp;/g, ' ')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#(\d+);/g, (_, code: string) => String.fromCodePoint(Number.parseInt(code, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, code: string) =>
      String.fromCodePoint(Number.parseInt(code, 16)),
    )
    .replace(/&amp;/g, '&');
}

/**
 * Turn a feed item's `description` into plain text. The field is HTML, encoded
 * once for XML transport, so entities are decoded before tags are stripped and
 * again afterwards for entities that were double-encoded. Block-level tags
 * collapse to spaces so adjacent words do not fuse.
 *
 * ICS advisory descriptions run to 14 KB each and thirty of them unstripped is
 * 420 KB of markup, which is why the feed tool caps the result and discloses it.
 */
export function stripFeedHtml(description: string): string {
  const html = decodeEntities(description);
  const text = html
    .replace(/<\s*br\s*\/?\s*>/gi, ' ')
    .replace(/<\s*\/?(p|div|li|ul|ol|h[1-6]|tr|table|blockquote)\b[^>]*>/gi, ' ')
    .replace(/<[^>]*>/g, '');
  return decodeEntities(text).replace(/\s+/g, ' ').trim();
}

/**
 * Normalize a feed `pubDate` to an ISO 8601 timestamp. The feeds emit RFC 822
 * with a two-digit year (`Fri, 18 Sep 26 12:00:00 +0000`), which `Date` resolves
 * correctly; an unparseable value is passed through verbatim rather than
 * replaced with a fabricated timestamp.
 */
export function normalizePubDate(pubDate: string): string {
  const parsed = new Date(pubDate.trim());
  return Number.isNaN(parsed.getTime()) ? pubDate.trim() : parsed.toISOString();
}

/**
 * Extract the advisory ID from a feed item link, uppercased so it chains straight
 * into `cisa_get_advisory`. Returns `undefined` for a link that is not an ICS
 * advisory page.
 */
export function advisoryIdFromLink(link: string): string | undefined {
  const match = /\/(?:ics-advisories|ics-medical-advisories)\/([a-z0-9-]+)/i.exec(link);
  return match?.[1] ? match[1].toUpperCase() : undefined;
}
