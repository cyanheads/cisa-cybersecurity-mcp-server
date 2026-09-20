/**
 * @fileoverview Tests for pure RSS feed normalization — HTML stripping with
 * entity decoding, two-digit-year pubDate parsing, and the advisory-ID
 * extractor.
 * @module tests/services/cisa-feeds/normalize.test
 */

import { describe, expect, it } from 'vitest';
import {
  advisoryIdFromLink,
  normalizePubDate,
  stripFeedHtml,
} from '@/services/cisa-feeds/normalize.js';

describe('stripFeedHtml', () => {
  it('strips tags and collapses block-level tags to spaces', () => {
    expect(stripFeedHtml('<p>Hello</p><p>World</p>')).toBe('Hello World');
  });

  it('decodes entities before and after tag stripping', () => {
    expect(stripFeedHtml('AT&amp;T &lt;b&gt;bold&lt;/b&gt; &quot;quoted&quot;')).toBe(
      'AT&T bold "quoted"',
    );
  });

  it('decodes numeric and hex character references', () => {
    expect(stripFeedHtml('&#65;&#x42;')).toBe('AB');
  });

  it('converts <br> to a space rather than fusing adjacent words', () => {
    expect(stripFeedHtml('Line one<br/>Line two')).toBe('Line one Line two');
  });

  it('collapses repeated whitespace and trims', () => {
    expect(stripFeedHtml('  <div>  spaced   out  </div>  ')).toBe('spaced out');
  });

  it('leaves an out-of-range character reference verbatim instead of throwing', () => {
    /* 0x110000 is one past the last Unicode code point, and a 400-digit value
     * overflows to Infinity; both make String.fromCodePoint throw, and one such
     * reference in one feed item must not take the whole window down. */
    expect(stripFeedHtml('before &#1114112; after')).toBe('before &#1114112; after');
    expect(stripFeedHtml('before &#x110000; after')).toBe('before &#x110000; after');
    expect(stripFeedHtml(`before &#${'9'.repeat(400)}; after`)).toBe(
      `before &#${'9'.repeat(400)}; after`,
    );
  });

  it('still decodes a reference at the top of the valid range', () => {
    expect(stripFeedHtml('&#x10FFFF;')).toBe(String.fromCodePoint(0x10ffff));
  });
});

describe('normalizePubDate', () => {
  it('resolves a two-digit-year RFC 822 date to the correct ISO year', () => {
    const iso = normalizePubDate('Fri, 18 Sep 26 12:00:00 +0000');
    expect(iso).toBe('2026-09-18T12:00:00.000Z');
  });

  it('passes an unparseable value through verbatim rather than fabricating a timestamp', () => {
    expect(normalizePubDate('not a date')).toBe('not a date');
  });

  it('trims surrounding whitespace before parsing', () => {
    expect(normalizePubDate('  Fri, 18 Sep 26 12:00:00 +0000  ')).toBe('2026-09-18T12:00:00.000Z');
  });
});

describe('advisoryIdFromLink', () => {
  it('extracts and uppercases the ID from an ics-advisories link', () => {
    expect(
      advisoryIdFromLink('https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-07'),
    ).toBe('ICSA-26-260-07');
  });

  it('extracts from an ics-medical-advisories link', () => {
    expect(
      advisoryIdFromLink('https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-02'),
    ).toBe('ICSMA-26-253-02');
  });

  it('returns undefined for a link that is not an ICS advisory page', () => {
    expect(advisoryIdFromLink('https://www.cisa.gov/news-events/alerts/aa26-260a')).toBeUndefined();
  });

  it('returns undefined for a slug that is not a well-formed advisory ID', () => {
    /* The value is advertised under the advisory-ID pattern and chains into
     * cisa_get_advisory; a slug that cannot be looked up must not be emitted. */
    expect(
      advisoryIdFromLink('https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-07-update-b'),
    ).toBeUndefined();
    expect(
      advisoryIdFromLink('https://www.cisa.gov/news-events/ics-advisories/ics-alert-17-206-01'),
    ).toBeUndefined();
    expect(
      advisoryIdFromLink('https://www.cisa.gov/news-events/ics-advisories/subscribe'),
    ).toBeUndefined();
  });
});
