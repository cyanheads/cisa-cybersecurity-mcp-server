<div align="center">
  <h1>@cyanheads/cisa-cybersecurity-mcp-server</h1>
  <p><b>CISA Known Exploited Vulnerabilities with BOD 26-04 deadlines, SSVC prioritization, and the full ICS advisory corpus (CSAF) via MCP. Keyless. STDIO & Streamable HTTP.</b>
  <div>7 Tools • 2 Resources</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.1.1-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/cisa-cybersecurity-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.0.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/cisa-cybersecurity-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/cisa-cybersecurity-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.0-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/cisa-cybersecurity-mcp-server/releases/latest/download/cisa-cybersecurity-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=cisa-cybersecurity-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvY2lzYS1jeWJlcnNlY3VyaXR5LW1jcC1zZXJ2ZXIiXX0=) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22cisa-cybersecurity-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fcisa-cybersecurity-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

<div align="center">

**Public Hosted Server:** [https://cisa-cybersecurity.caseyjhand.com/mcp](https://cisa-cybersecurity.caseyjhand.com/mcp)

</div>

---

## Overview

CISA's open vulnerability outputs, made queryable: the Known Exploited Vulnerabilities catalog and the federal remediation deadlines it carries, the SSVC decision points CISA publishes per CVE in Vulnrichment, the full CSAF corpus of industrial control system advisories back to 2010, and CISA's current publication feeds. Check a scan's worth of CVE IDs against KEV in one call, find what is overdue for a vendor, work out what BOD 26-04 implies for an asset you own, and search or read ICS advisories by vendor, product, CVE, CVSS, or sector. Every source is keyless and read-only. Runs as a stdio process, a local Streamable HTTP server, or the public hosted endpoint above.

### Tools

| Tool | Description |
|:---|:---|
| `cisa_list_reference` | Decode the vocabulary the other tools take as input — BOD 26-04 timelines, KEV fields, SSVC values, sector names, ID formats, severity bands, and what data this server currently holds |
| `cisa_check_cve_status` | Check up to 200 CVE IDs against the KEV catalog in one call — remediation deadlines, overdue status, ransomware and forensic-triage flags, and the directive each entry cites |
| `cisa_search_kev` | Search the KEV catalog by vendor, product, CWE, date added, due date, overdue status, ransomware linkage, forensic-triage tier, or directive |
| `cisa_get_ssvc` | Fetch the SSVC decision points CISA publishes per CVE and compute the BOD 26-04 remediation timeline they imply for a stated asset exposure |
| `cisa_search_ics_advisories` | Search the ICS advisory corpus by vendor, product, CVE, CVSS range, severity, sector, series, or free text over titles and product names |
| `cisa_get_advisory` | Read one ICS advisory in full — affected products with version ranges, per-CVE CVSS and CWE, remediations, sectors, and revision history |
| `cisa_get_alerts` | List what CISA has published recently from its advisory, alert, or ICS advisory feed |

### Resources

| Resource | Description |
|:---|:---|
| `cisa://kev/{cveId}` | One KEV catalog entry by CVE ID |
| `cisa://advisory/{advisoryId}` | One ICS advisory, flattened from CSAF 2.0 |

Both resources are fully covered by the tools above, so a tool-only client loses nothing.

## Capability reference

### `cisa_list_reference` <sub>tool</sub>

- One required `topic`: `directives`, `kev_fields`, `ssvc_values`, `sectors`, `advisory_id_formats`, `severity_bands`, or `sources`
- `directives` returns all sixteen rows of BOD 26-04 Appendix A, Table 1 as data — row number, the four decision points, the timeline label in the directive's own wording, `remediationTimelineDays`, and `forensicTriageRequired` — plus the directive's supporting definitions and what it supersedes
- `sources` reports what this server currently holds: the KEV snapshot's `catalogVersion` and last check, the advisory index's readiness, document count and sync status, the SSVC cache TTL, and the cached feed windows
- Reads in-process state only and makes no network call, so it stays answerable while another tool is failing — which is why every recovery hint on this surface routes here

---

### `cisa_check_cve_status` <sub>tool</sub>

- Up to 200 CVE IDs per call, answered from the cached catalog snapshot at zero upstream cost
- Per CVE: `inKev`, and when present `dateAdded`, `dueDate`, `daysUntilDue`, `overdue`, `requiredAction`, `knownRansomwareCampaignUse`, `forensicTriage`, CISA's `vendorProject` / `product` labels, `cwes[]`, and `references[]` typed by `kind` (`nvd`, `cisa`, `bod_guidance`, `forensic_triage`, `vendor`, `other`)
- `directive` is three-state — `BOD 26-04`, `BOD 22-01`, or `null` for the entries citing neither; it is never inferred from an entry's age
- A CVE that is not in KEV is a normal result, not an error
- Echoes the catalog snapshot that answered the call and the `asOf` date `overdue` and `daysUntilDue` were computed against

---

### `cisa_search_kev` <sub>tool</sub>

- Filters AND together and apply to the whole snapshot, never a page: `vendorProject`, `product`, `nameContains`, `cwe`, `cveIdPrefix`, `dateAddedFrom` / `dateAddedTo`, `dueBefore` / `dueAfter`, `overdue`, `ransomware`, `forensicTriage`, and `directive` (`BOD 26-04` / `BOD 22-01` / `none`)
- Sort by `dueDate` or `dateAdded`; up to 100 per page (default 25) with an opaque cursor, and `totalCount` reports matches before paging
- `vendorProject` and `product` are CISA's own free-text labels, not CPE names — `cisa_list_reference` with topic `kev_fields` carries the value domain
- Setting `dateAddedFrom` adds a caveat: the feed carries no per-record modified timestamp, so the result covers additions in the window, not revisions to existing entries
- Typed errors: `catalog_unavailable` (retryable), `invalid_date_range`

---

### `cisa_get_ssvc` <sub>tool</sub>

- Up to 50 CVE IDs per call — lower than the KEV cap because each CVE needs its own live enrichment lookup rather than a cached batch check
- Returns CISA's published `exploitation`, `automatable`, and `technicalImpact`, plus the CVSS score and CWEs CISA contributes where present
- `assetExposure` (`publicly_exposed` / `not_publicly_exposed` / `unknown`) is the one BOD 26-04 decision point CISA cannot publish; `unknown` returns both arms rather than a guess
- `bod2604.timelines[]` carries the Table 1 row, the label, `remediationTimelineDays` (`null` for the "Fix on system upgrade" rows), and `forensicTriageRequired`, under a fixed caveat that this is CISA's decision table applied to CISA's decision points and your stated exposure — not a compliance determination
- `kevAssigned` reports CISA's own due date side by side, and `assignmentAgrees` surfaces a disagreement as a fact; the two are never reconciled
- A CVE with no published enrichment returns `found: false` with guidance naming the outcome, not an error

---

### `cisa_search_ics_advisories` <sub>tool</sub>

- Full-text `q` over advisory titles, vendor names, and product names — tokens are AND-combined and FTS5 operators in the input are neutralized rather than honored
- Filters: `vendor`, `product`, `cve`, `cvssMin` / `cvssMax`, `severity` (`NONE`–`CRITICAL`), `sector` (the sixteen canonical names plus the `Multiple` sentinel), `series` (`ICSA` / `ICSMA`), `publisher` (`coordinator` = CISA-authored, `other` = republished vendor advisory), `publishedFrom` / `publishedTo`, `revisedFrom` / `revisedTo`
- Sort by `revised` (default), `published`, `maxCvss`, or `relevance` (requires `q`); up to 50 per page (default 20) with an opaque cursor
- Coverage notices fire on the filters that have gaps: sector notes begin in 2017, and some advisories score only in CVSS v2 where the band is derived rather than published
- Results carry `advisoryId` for `cisa_get_advisory`, the CVE set, the cisa.gov `url`, the raw `csafUrl`, and an `attribution` string
- Typed errors: `mirror_not_ready` (retryable), `invalid_cvss_range`, `invalid_date_range`, `relevance_sort_without_query`

---

### `cisa_get_advisory` <sub>tool</sub>

- `advisoryId` is case-insensitive and accepts both real suffix forms (a single letter `a`–`f`, or a numeric `-N`); a trailing `.json` is stripped
- Seven addressable sections: `advisory`, `summary`, `products`, `vulnerabilities`, `revisionHistory`, `references`, `acknowledgments`
- A document over the 24 KB inline budget returns a complete section outline with per-section sizes instead of the whole record — re-call with `sections` to pull what you need; the re-call is stateless
- The `products` arm caps at 200 flattened version rows with the cap disclosed, since a single advisory can carry 585 products
- Products keep their CSAF product IDs, so a CVE maps to the exact affected version ranges
- Typed errors: `mirror_not_ready` (retryable), `unknown_section`. An ID that is not in the index returns `found: false` with guidance

---

### `cisa_get_alerts` <sub>tool</sub>

- `feed` selects `advisories`, `alerts`, or `ics`; `limit` tops out at 30 because that is the upstream window, not a server choice
- `since` filters within the fetched window and cannot reach back beyond it
- Every response carries `window` (`itemCount`, `oldest`, `newest`, `upstreamWindowSize`) and a caveat that the feed has no history, no pagination, and no server-side date filter
- `summary` is the item description with HTML stripped and entities decoded, capped at 1,200 characters with `summaryTruncated` flagging the cut
- ICS items carry a parsed `advisoryId` that chains straight into `cisa_get_advisory`
- Typed error: `feed_unavailable` (retryable)

---

### `cisa://kev/{cveId}` <sub>resource</sub>

- One KEV record as `application/json`, identical in shape to a `cisa_check_cve_status` result
- Listing returns the 30 most recently added entries; `cveId` completes from the snapshot, up to 100 suggestions
- A CVE absent from the catalog is a not-found error, with the reminder that absence is not a statement about severity

---

### `cisa://advisory/{advisoryId}` <sub>resource</sub>

- One flattened advisory as `application/json`, carrying the same 24 KB outline-on-overflow treatment `cisa_get_advisory` applies on a call with no `sections`
- A resource template has no `sections` parameter, so follow an outline up with `cisa_get_advisory` to request named sections
- Listing returns the 30 most recently revised advisories; `advisoryId` completes from the index, up to 100 suggestions

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

CISA-specific:

- No API key, no account, no registration — every source is a free, public, machine-readable file
- No upstream source offers search, so every filter, sort, and full-text query runs locally: the KEV catalog as an in-memory snapshot kept current by a conditional-GET poll, the ICS corpus as a SQLite index with FTS5
- Boot never waits on the advisory corpus — the KEV, SSVC, and alert tools serve from the first request while the index seeds in the background
- The BOD 26-04 decision table is carried as data, so a timeline is a table lookup over published decision points rather than a judgment call

Agent-friendly output:

- Provenance on every response — the catalog version and `asOf` date that answered a KEV call, the index checkpoint behind a search, and a source URL plus attribution on every advisory
- Discriminated output contracts — a three-state `directive`, typed `references[].kind`, `found` / `inKev` booleans, `severityDerived` on a band the upstream never published, and per-tool typed error reasons with recovery hints
- Zero-hit results explain themselves — each one names the filter most likely responsible and the concrete next call, rather than returning a bare empty list
- Coverage gaps are disclosed where they bite: how many advisories a sector filter can never reach, that KEV revisions are undetectable, and that a computed timeline is not CISA's own due-date assignment

## Getting started

### Public Hosted Instance

A public instance is available at `https://cisa-cybersecurity.caseyjhand.com/mcp` — no installation required. Point any MCP client at it via Streamable HTTP:

```json
{
  "mcpServers": {
    "cisa-cybersecurity-mcp-server": {
      "type": "streamable-http",
      "url": "https://cisa-cybersecurity.caseyjhand.com/mcp"
    }
  }
}
```

### Self-Hosted / Local

Add the following to your MCP client configuration file. No API key is required.

```json
{
  "mcpServers": {
    "cisa-cybersecurity-mcp-server": {
      "type": "stdio",
      "command": "bunx",
      "args": ["@cyanheads/cisa-cybersecurity-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Or with npx (no Bun required):

```json
{
  "mcpServers": {
    "cisa-cybersecurity-mcp-server": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@cyanheads/cisa-cybersecurity-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Or with Docker:

```json
{
  "mcpServers": {
    "cisa-cybersecurity-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "MCP_TRANSPORT_TYPE=stdio",
        "-v", "cisa-mirror:/usr/src/app/.mirror",
        "ghcr.io/cyanheads/cisa-cybersecurity-mcp-server:latest"
      ]
    }
  }
}
```

For Streamable HTTP, set the transport and start the server:

```sh
MCP_TRANSPORT_TYPE=http MCP_HTTP_PORT=3010 bun run start:http
# Server listens at http://localhost:3010/mcp
```

### Prerequisites

- [Bun v1.4.0](https://bun.sh/) or higher (or Node.js v24+).
- No credentials. Every upstream source is keyless and public.

### Installation

1. **Clone the repository:**

```sh
git clone https://github.com/cyanheads/cisa-cybersecurity-mcp-server.git
```

2. **Navigate into the directory:**

```sh
cd cisa-cybersecurity-mcp-server
```

3. **Install dependencies:**

```sh
bun install
```

## ICS advisory index

`cisa_search_ics_advisories` and `cisa_get_advisory` read a local SQLite index of the CSAF advisory corpus. CISA offers no search endpoint for it, and the corpus exists only as thousands of individual documents, so the index is what makes the two tools possible.

It seeds itself. On first run the server fetches one repository archive in the background and builds the index in about ten seconds, leaving roughly 55 MB at `CISA_CSAF_MIRROR_PATH` (`.mirror/csaf.sqlite3` by default). Nothing else waits on it: the KEV, SSVC, and alert tools serve from the first request, and until the index is ready the two ICS tools report that state through a retryable `mirror_not_ready` error rather than an empty result. `cisa_list_reference` with topic `sources` reports the progress.

Under HTTP transport the index refreshes itself on a cron. Three scripts cover explicit control — a stdio deployment, a container, a CI gate:

```sh
bun run mirror:init      # full build, idempotent, safe to re-run after an interrupt
bun run mirror:refresh   # incremental — fetches only the documents whose revision date moved
bun run mirror:verify    # readiness, sync status, checkpoint, count, SQLite integrity; exits non-zero on failure
```

Set `CISA_CSAF_MIRROR_AUTO_INIT=false` where seeding runs out of band.

**Docker:** mount a volume over `CISA_CSAF_MIRROR_PATH` so a container recreation does not rebuild the index, then run the scripts with `docker exec <container> bun run mirror:refresh`. The image ships them for exactly that.

**Claude Desktop (`.mcpb`):** the bundle has no shell, so the automatic background seed is the whole story — install it and the ICS tools come online shortly after the first launch.

## Configuration

Every variable is optional; the server runs correctly with none of them set.

| Variable | Description | Default |
|:---|:---|:---|
| `CISA_KEV_REFRESH_CRON` | Cron for the KEV conditional-refresh poll. HTTP transport only; empty disables the in-process schedule. | `*/30 * * * *` |
| `CISA_CSAF_MIRROR_PATH` | Filesystem path to the ICS advisory SQLite index. | `.mirror/csaf.sqlite3` |
| `CISA_CSAF_MIRROR_AUTO_INIT` | Seed the advisory index in the background at startup when it has never synced. | `true` |
| `CISA_CSAF_REFRESH_CRON` | Cron for the incremental advisory refresh. HTTP transport only; empty disables it. | `17 */6 * * *` |
| `CISA_VULNRICHMENT_CACHE_TTL_SECONDS` | TTL for a cached SSVC record. Negative results use one sixth of this. | `21600` |
| `CISA_FEED_CACHE_TTL_SECONDS` | TTL for a parsed RSS feed window. | `900` |
| `CISA_HTTP_TIMEOUT_MS` | Per-request timeout for every upstream fetch, in milliseconds. | `30000` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for the HTTP server. | `3010` |
| `MCP_HTTP_ENDPOINT_PATH` | HTTP endpoint path where the server is mounted. | `/mcp` |
| `MCP_SESSION_MODE` | HTTP session mode. This server ships `stateless` — no handler collects input mid-request. | `stateless` |
| `MCP_AUTH_MODE` | Auth mode: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (RFC 5424). | `info` |
| `LOGS_DIR` | Directory for log files (Node.js only). | `<project-root>/logs` |
| `STORAGE_PROVIDER_TYPE` | Storage backend. | `in-memory` |
| `OTEL_ENABLED` | Enable [OpenTelemetry instrumentation](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry). | `false` |

See [`.env.example`](./.env.example) for the full list of optional overrides.

## Running the server

### Local development

- **Build and run:**

  ```sh
  # One-time build
  bun run rebuild

  # Run the built server
  bun run start:stdio
  # or
  bun run start:http
  ```

- **Run checks and tests:**

  ```sh
  bun run devcheck   # Lint, format, typecheck, security
  bun run test       # Vitest test suite
  bun run lint:mcp   # Validate MCP definitions against spec
  ```

### Docker

```sh
docker build -t cisa-cybersecurity-mcp-server .
docker run --rm -p 3010:3010 -v cisa-mirror:/usr/src/app/.mirror cisa-cybersecurity-mcp-server
```

The Dockerfile defaults to HTTP transport, stateless session mode, and logs to `/var/log/cisa-cybersecurity-mcp-server`. OpenTelemetry peer dependencies are installed by default — build with `--build-arg OTEL_ENABLED=false` to omit them. Mount a volume over `/usr/src/app/.mirror` so the advisory index survives a container recreation.

There is no Cloudflare Workers deployment: the advisory index needs embedded SQLite and a persistent filesystem, and an isolate has neither.

## Data sources and licensing

| Source | What it provides | Status |
|:---|:---|:---|
| KEV catalog | Exploited-in-the-wild CVEs with federal remediation deadlines | US Government work, public domain under 17 U.S.C. §105 |
| Vulnrichment | SSVC decision points, CVSS, and CWE CISA publishes per CVE | CC0-1.0 |
| CSAF ICS advisories | The machine-readable advisory corpus back to 2010 | No declared license — see below |
| Advisory and alert feeds | CISA's current publication windows | Relayed with a link to each item |

The CSAF repository declares no license, and a substantial share of its advisories are vendor advisories CISA republished with the vendor's own text and revision history. This server therefore makes no public-domain claim over advisory content: every advisory a tool or resource returns carries its cisa.gov `url`, its raw `csafUrl`, and an `attribution` string naming the publisher and, for a republication, the originating vendor. Resolve reuse rights against the source before redistributing advisory text.

This project is not affiliated with, endorsed by, or sponsored by CISA or the Department of Homeland Security. It uses no DHS seal, no CISA logo, and no agency branding.

## Known limitations

These are properties of the upstream sources, not of this server. Each is stated in the description or output of the tool it affects.

- **KEV modifications are invisible.** The feed carries `dateAdded` but no per-record modified timestamp, so a revised `dueDate` or `requiredAction` on an existing entry cannot be distinguished from an unchanged one. Additions are queryable; revisions are not.
- **Most KEV entries cite no directive.** The majority name neither BOD 22-01 nor BOD 26-04, and `directive` is `null` for them rather than inferred from an entry's age.
- **A computed BOD 26-04 timeline is not a compliance determination.** It is CISA's published decision table applied to CISA's published decision points and the asset exposure the caller supplies. It also does not reproduce CISA's assigned KEV due date, which reflects values and judgment at the time of addition; the two are reported side by side and never reconciled.
- **SSVC coverage is incomplete and can lag.** Not every CVE has a Vulnrichment record, KEV entries included, and a published `Exploitation` value can predate a KEV addition that contradicts it.
- **Advisory sector coverage begins in 2017.** Hundreds of advisories carry no sector note at all, so a sector filter cannot reach them. The gap is disclosed on every filtered call.
- **The advisory corpus carries no structured CVSS v4.** Some advisories score only in CVSS v2, where the upstream publishes no severity label and the band is derived and flagged as such.
- **Advisory vendor names are unnormalized.** The same company appears under several spellings across the corpus, so vendor filtering is substring matching rather than an enum.
- **The publication feeds have no history.** Thirty items per feed, no pagination, and no date query; anything older is unreachable from the feed. ICS advisory history lives in the local index instead.

## Project structure

| Directory | Purpose |
|:---|:---|
| `src/index.ts` | `createApp()` entry point — wires the four services, schedules the refresh loops, registers the surface. |
| `src/config` | Server-specific environment variable parsing and validation with Zod. |
| `src/mcp-server/tools` | Tool definitions (`*.tool.ts`). Seven tools across KEV, SSVC, ICS advisories, and the feeds. |
| `src/mcp-server/resources` | Resource definitions (`*.resource.ts`). KEV entry and ICS advisory templates. |
| `src/mcp-server/schemas` | Shared output schemas and `format()` renderers for KEV records and advisories. |
| `src/reference` | Static reference data — BOD 26-04 Table 1, canonical sector names, CVSS bands. |
| `src/services/kev-catalog` | KEV JSON feed — snapshot, derived indexes, conditional refresh. |
| `src/services/vulnrichment` | Per-CVE SSVC enrichment fetch with a TTL cache. |
| `src/services/csaf-mirror` | The ICS advisory index — schema, ingest, normalization, queries. |
| `src/services/cisa-feeds` | The three RSS feeds, parsed and cached on a TTL. |
| `scripts/` | Build, checks, and the three `mirror:*` lifecycle commands. |
| `tests/` | Unit, integration, fuzz, and smoke tests mirroring `src/`. |

## Development guide

See [`CLAUDE.md`/`AGENTS.md`](./CLAUDE.md) for development guidelines and architectural rules. The short version:

- Handlers throw, framework catches — no `try/catch` in tool logic
- Use `ctx.log` for request-scoped logging, `ctx.state` for tenant-scoped storage
- Register new tools and resources via the barrels in `src/mcp-server/*/definitions/index.ts`
- Wrap external sources: validate raw → normalize to a domain type → return the output schema; never fabricate a field the upstream omitted

## Contributing

Issues are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

## License

Apache-2.0 — see [LICENSE](./LICENSE) for details.
