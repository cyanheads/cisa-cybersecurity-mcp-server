/**
 * @fileoverview RSS feed fixtures — a two-digit-year pubDate, a trailing-
 * whitespace title, and an oversized ICS-advisory description that exceeds
 * the 1,200-character summary cap.
 * @module tests/fixtures/rss-feeds
 */

export function buildAdvisoriesFeed(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>CISA Advisories</title>
<item>
  <title>Acme Widget Advisory  </title>
  <link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-07</link>
  <description>&lt;p&gt;Acme published a fix.&lt;/p&gt;</description>
  <pubDate>Fri, 18 Sep 26 12:00:00 +0000</pubDate>
  <dc:creator>CISA</dc:creator>
  <guid>/node/25513</guid>
</item>
<item>
  <title>Widget Corp Alert</title>
  <link>https://www.cisa.gov/news-events/alerts/aa26-260a</link>
  <description>An alert with no advisory link.</description>
  <pubDate>Thu, 17 Sep 26 09:00:00 +0000</pubDate>
  <guid>/node/25500</guid>
</item>
</channel></rss>`;
}

export function buildIcsAdvisoriesFeedWithOversizedItem(): string {
  /* Entity-encoded, matching how the real feeds carry HTML inside <description> —
   * unescaped tags here would nest as XML child elements instead of text. */
  const bigDescription = `&lt;p&gt;${'x'.repeat(1400)}&lt;/p&gt;`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>CISA ICS Advisories</title>
<item>
  <title>Big ICS Advisory</title>
  <link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-08</link>
  <description>${bigDescription}</description>
  <pubDate>Fri, 18 Sep 26 12:00:00 +0000</pubDate>
  <guid>/node/25514</guid>
</item>
</channel></rss>`;
}

export function buildEmptyChannelFeed(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>CISA Alerts</title>
</channel></rss>`;
}
