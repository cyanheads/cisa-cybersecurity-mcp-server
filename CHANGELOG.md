# Changelog

All notable changes to this project. Each entry links to its full per-version file in [changelog/](changelog/).

## [0.3.0](changelog/0.3.x/0.3.0.md) — 2026-09-25 · ⚠️ Breaking

The ICS advisory index moves to a per-user cache directory and refreshes at boot and on schedule on every transport, under a cross-process sync lease; ICS zero-hit notices are computed from per-filter counts, and an invalid refresh cron now fails startup.

## [0.2.0](changelog/0.2.x/0.2.0.md) — 2026-09-25 · ⚠️ Breaking

Adds a summary detail to cisa_check_cve_status, reads every KEV notes URL into references, and computes zero-hit notices from per-filter counts; a nameContains with nothing to search is now rejected, and advisoryId patterns are advertised in their canonical, flag-free form.

## [0.1.3](changelog/0.1.x/0.1.3.md) — 2026-09-22

Adds cwe and inKev search filters and cves-narrowed advisory reads; removes the 200-product cap, fixes silent search-filter widening, and resolves more sector aliases.

## [0.1.2](changelog/0.1.x/0.1.2.md) — 2026-09-20

The public hosted endpoint at https://cisa-cybersecurity.caseyjhand.com/mcp is now published in server.json remotes and documented in the README.

## [0.1.1](changelog/0.1.x/0.1.1.md) — 2026-09-19

First published release — seven cisa_ tools and two resources over the CISA KEV catalog, Vulnrichment SSVC decision points, the full CSAF ICS advisory corpus, and CISA's publication feeds. Keyless, read-only, stdio and Streamable HTTP.
