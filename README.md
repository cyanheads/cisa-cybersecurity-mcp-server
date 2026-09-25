<div align="center">
  <h1>@cyanheads/cisa-cybersecurity-mcp-server</h1>
  <p><b>CISA Known Exploited Vulnerabilities with BOD 26-04 deadlines, SSVC prioritization, and the full ICS advisory corpus (CSAF) via MCP. Keyless. STDIO & Streamable HTTP.</b>
  <div>7 Tools • 2 Resources</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.2.0-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/cisa-cybersecurity-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.0.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/cisa-cybersecurity-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/cisa-cybersecurity-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.2-blueviolet.svg?style=flat-square)](https://bun.sh/)

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

CISA's open vulnerability data: the Known Exploited Vulnerabilities catalog and its federal remediation deadlines, the SSVC decision points CISA publishes per CVE in Vulnrichment, the CSAF corpus of industrial control system advisories back to 2010, and CISA's publication feeds. Check a scan's worth of CVE IDs against KEV in one call, find what is overdue for a vendor, work out the BOD 26-04 timeline for an asset you own, and search or read ICS advisories. Every source is keyless. Runs as a stdio process, a local Streamable HTTP server, or the public hosted endpoint above.

### Tools

| Tool | Description |
|:---|:---|
| `cisa_list_reference` | Decode the input vocabulary (BOD 26-04 timelines, KEV fields, SSVC values, sectors, ID formats, severity bands) and report what data the server holds |
| `cisa_check_cve_status` | Check up to 200 CVE IDs against KEV in one call: deadlines, overdue status, ransomware and forensic-triage flags, cited directive |
| `cisa_search_kev` | Search KEV by vendor, product, CWE, date added, due date, overdue status, ransomware linkage, forensic-triage tier, or directive |
| `cisa_get_ssvc` | Fetch CISA's published SSVC decision points per CVE and compute the BOD 26-04 timeline for a stated asset exposure |
| `cisa_search_ics_advisories` | Search ICS advisories by vendor, product, CVE, CWE, KEV membership, CVSS, severity, sector, series, dates, or free text |
| `cisa_get_advisory` | Read one ICS advisory: affected product versions, per-CVE CVSS and CWE, remediations, sectors, revision history |
| `cisa_get_alerts` | List CISA's latest items from its advisory, alert, or ICS advisory feed |

### Resources

| Resource | Description |
|:---|:---|
| `cisa://kev/{cveId}` | One KEV catalog entry by CVE ID |
| `cisa://advisory/{advisoryId}` | One ICS advisory, flattened from CSAF 2.0 |

Both resources are fully covered by the tools above, so a tool-only client loses nothing.

## Capability reference

### `cisa_list_reference` <sub>tool</sub>

- One required `topic`: `directives`, `kev_fields`, `ssvc_values`, `sectors`, `advisory_id_formats`, `severity_bands`, or `sources`; reads in-process state only, so it answers while other tools are failing
- `directives` adds `timelineTable` (all 16 rows of BOD 26-04 Table 1, with `remediationTimelineDays` and `forensicTriageRequired`), `definitions`, and `supersedes`; `sources` reports the KEV `catalogVersion`, the advisory index's `ready` / `documentCount` / `syncStatus`, the SSVC cache TTL, and the cached feed windows

---

### `cisa_check_cve_status` <sub>tool</sub>

- Up to 200 `cveIds` per call, answered from the cached KEV snapshot with no upstream request; a CVE outside KEV comes back `inKev: false`, not as an error
- Per CVE: `dateAdded`, `dueDate`, `daysUntilDue`, `overdue`, `requiredAction`, `knownRansomwareCampaignUse`, `forensicTriage`, `cwes[]`, every URL in the entry's notes as `references[]` typed by `kind`, and a three-state `directive` (`BOD 26-04`, `BOD 22-01`, or `null`); the response echoes the `catalog` snapshot and the `asOf` date the deadlines were computed against
- `detail: "summary"` trims each in-KEV record to the triage fields (dates, deadline status, directive, vendor and product labels, ransomware and forensic-triage flags), which keeps a full 200-CVE batch compact; `full` is the default

---

### `cisa_search_kev` <sub>tool</sub>

- Filters AND together over the whole snapshot: `vendorProject` and `product` (CISA's own labels, not CPE names), `nameContains`, `cwe`, `cveIdPrefix`, `dateAddedFrom` / `dateAddedTo`, `dueBefore` / `dueAfter`, `overdue`, `ransomware`, `forensicTriage`, `directive` (`BOD 26-04` / `BOD 22-01` / `none`); up to 100 per page (default 25) with an opaque `cursor`. `cwe` and `cveIdPrefix` normalize case and surrounding whitespace
- Sorts by `dateAdded` (default) or `dueDate` and reports `totalCount` and `appliedFilters`; a zero-hit result names the filter that matches nothing on its own and what dropping it restores, or the filters whose removal restores results and how many
- `nameContains` matches the letters a-z and the digits 0-9 after folding case and accents and spelling letters such as `ß`, `æ`, and `ø` as `ss`, `ae`, and `o`; any other letter or digit, such as a word in another script, is dropped, and the notice names it and the tokens actually searched
- Typed errors: `catalog_unavailable` (retryable), `invalid_date_range`, `empty_search_text`

---

### `cisa_get_ssvc` <sub>tool</sub>

- Up to 50 `cveIds` per call, each a live Vulnrichment lookup, plus `assetExposure`: `publicly_exposed`, `not_publicly_exposed`, or `unknown` (default, returns both arms)
- Per CVE: `found`, `exploitation`, `automatable`, `technicalImpact`, `cvss` and `cwes` where CISA published them, and `bod2604.timelines[]` (`tableRow`, `remediationTimelineDays`, `forensicTriageRequired`); a KEV entry adds `kevAssigned`, plus `assignmentAgrees` when an exposure was stated
- A CVE with no enrichment is `found: false` with `guidance`; `enrichment_source_unavailable` (retryable) fires only when every fetch fails

---

### `cisa_search_ics_advisories` <sub>tool</sub>

- Full-text `q` over titles, vendor names, and product names, plus `vendor`, `product`, `cve`, `cwe`, `inKev`, `cvssMin` / `cvssMax`, `severity`, `sector`, `series` (`ICSA` / `ICSMA`), `publisher` (`coordinator` / `other`), `publishedFrom` / `publishedTo`, `revisedFrom` / `revisedTo`; sorts by `revised` (default), `published`, `maxCvss`, or `relevance` (needs `q`); up to 50 per page (default 20) with an opaque `cursor`. `cve` and `cwe` normalize case and surrounding whitespace
- Results carry `advisoryId`, up to 20 `cves` with `cveCount`, `kevCves`, `maxCvss` with `severityDerived`, `sectors`, `url`, `csafUrl`, and `attribution`; without `inKev`, an unloaded KEV snapshot leaves `kevCves` out and says so rather than failing
- Reports `totalCount` and `appliedFilters`; a zero-hit result names the filter that matches nothing on its own and what dropping it restores, or the filters whose removal restores results and how many
- `vendor` and `product` are case-insensitive substrings matched literally, non-ASCII capitals included, so a label copied from a result matches its own advisories
- Typed errors: `mirror_not_ready` and `catalog_unavailable` (retryable), `mirror_unavailable`, `invalid_cvss_range`, `invalid_date_range`, `relevance_sort_without_query`, `empty_search_text`

---

### `cisa_get_advisory` <sub>tool</sub>

- `advisoryId` (optional revision suffix; case, surrounding whitespace, and a trailing `.json` are normalized, and every ID comes back in its uppercase form), optional `sections` (`advisory`, `summary`, `products`, `vulnerabilities`, `revisionHistory`, `references`, `acknowledgments`), and optional `cves` to narrow `vulnerabilities` to named entries
- Returns `kind: "full"`, or `kind: "outline"` when a document read without `sections` exceeds the 24,000-byte budget: per-section byte sizes plus the CVE IDs in `vulnerabilities`, for a stateless re-call
- An ID not in the index returns `found: false` with `guidance`, `indexCheckpoint`, and `indexLastSyncedAt`; the guidance says when the ID's own date is later than the last sync, so the advisory may be newer than the index
- Typed errors: `mirror_not_ready` (retryable), `mirror_unavailable`, `unknown_section`, `unknown_cve`, `cves_need_vulnerabilities_section`

---

### `cisa_get_alerts` <sub>tool</sub>

- `feed`: `advisories` (default), `alerts`, or `ics`; `limit` up to 30, the upstream window size; `since` (`YYYY-MM-DD`) filters within that window and cannot reach past it
- Items carry `title`, `link`, `pubDate`, `summary` (HTML stripped, capped at 1,200 characters, flagged by `summaryTruncated`), and on ICS items an `advisoryId` for `cisa_get_advisory`; `window` reports `itemCount`, `oldest`, `newest`, and `upstreamWindowSize`. Typed error: `feed_unavailable` (retryable)

---

### `cisa://kev/{cveId}` <sub>resource</sub>

- One KEV record as `application/json`, the same shape as a `cisa_check_cve_status` result under the default `detail: "full"`; a CVE not in KEV is a not-found error
- Listing returns the 30 most recently added entries; `cveId` completes from the snapshot, up to 100 suggestions

---

### `cisa://advisory/{advisoryId}` <sub>resource</sub>

- One flattened advisory as `application/json`, with the same 24,000-byte outline-on-overflow as `cisa_get_advisory`; the template takes no `sections` or `cves`, so follow an outline up with the tool
- Listing returns the 30 most recently revised advisories; `advisoryId` completes from the index, up to 100 suggestions

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

CISA-specific:

- Four public sources, no account or key: the KEV JSON feed, Vulnrichment, the CSAF ICS advisory repository, and CISA's RSS feeds
- None of them offers search, so every filter runs locally: KEV as an in-memory snapshot kept current by a conditional-GET poll, ICS advisories as a SQLite index with FTS5
- Boot never waits on the advisory index; the KEV, SSVC, and alert tools serve from the first request while it seeds in the background
- BOD 26-04 Table 1 ships as data, so a computed timeline is a table lookup over published decision points. It is not a compliance determination, and it is reported beside CISA's assigned KEV due date, never reconciled with it

Agent-friendly output:

- Provenance on every response: the KEV `catalog` version and `asOf` date, the index checkpoint behind a search, and `url`, `csafUrl`, and `attribution` on every advisory
- Discriminated outputs: a three-state `directive`, typed `references[].kind`, `found` / `inKev` booleans, `severityDerived` on a band upstream never published, and typed error reasons with recovery hints
- Empty results and upstream gaps explain themselves: a zero-hit search names the filter responsible and the next call, and filters that hit a known gap (sector notes only from 2017, CVSS v2-only advisories, no KEV revision timestamps) say so in the response. The full list is under [Known Limitations](./docs/design.md#known-limitations) in the design doc

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

## Configuration

Every variable is optional; the server runs correctly with none of them set.

| Variable | Description | Default |
|:---|:---|:---|
| `CISA_KEV_REFRESH_CRON` | Cron for the KEV conditional-refresh poll, on every transport. `off` disables it; an invalid expression fails startup. | `*/30 * * * *` |
| `CISA_CSAF_MIRROR_PATH` | Filesystem path to the ICS advisory SQLite index. | `<user cache dir>/cisa-cybersecurity-mcp-server/csaf.sqlite3` |
| `CISA_CSAF_MIRROR_AUTO_INIT` | Seed the index in the background when it has never synced, and re-ingest one an older version built. | `true` |
| `CISA_CSAF_REFRESH_CRON` | Cron for the incremental advisory refresh, on every transport; it also runs once at startup. `off` disables both; an invalid expression fails startup. | `17 */6 * * *` |
| `CISA_VULNRICHMENT_CACHE_TTL_SECONDS` | TTL for a cached SSVC record; negative results use one sixth of it. | `21600` |
| `CISA_FEED_CACHE_TTL_SECONDS` | TTL for a parsed RSS feed window. | `900` |
| `CISA_HTTP_TIMEOUT_MS` | Per-request timeout for every upstream fetch, in ms. | `30000` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | HTTP server port. | `3010` |
| `MCP_SESSION_MODE` | HTTP session mode: `stateless`, `stateful`, or `auto`. | `stateless` |
| `MCP_AUTH_MODE` | Authentication: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (`debug`, `info`, `warning`, `error`, etc.). | `info` |
| `LOGS_DIR` | Directory for log files (Node.js only). | `<project-root>/logs` |
| `STORAGE_PROVIDER_TYPE` | Storage backend for the SSVC cache: `in-memory`, `filesystem`, or `supabase`. | `in-memory` |
| `OTEL_ENABLED` | Enable [OpenTelemetry](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry). | `false` |

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

### ICS advisory index

The two ICS tools and the advisory resource read a local SQLite index of the CSAF corpus at `CISA_CSAF_MIRROR_PATH`. Unset, it lives in your user cache directory — `~/Library/Caches` on macOS, `$XDG_CACHE_HOME` or `~/.cache` on Linux, `%LOCALAPPDATA%` on Windows — under `cisa-cybersecurity-mcp-server/csaf.sqlite3`, whatever directory the client starts the server from. On first run the server builds it in the background from one repository archive; until it is ready those surfaces return a retryable `mirror_not_ready`, and `cisa_list_reference` with topic `sources` shows progress. An index built by an older version re-ingests on the next start and keeps serving its current rows meanwhile. The `.mcpb` bundle needs nothing beyond that background seed. If the path cannot be opened (not writable, read-only, a missing directory, a file that is not a SQLite database), the ICS surfaces fail with a non-retryable `mirror_unavailable`, `sources` says why, and every other tool keeps working.

On every transport, the server refreshes the index once at startup and then on `CISA_CSAF_REFRESH_CRON`, and polls KEV on `CISA_KEV_REFRESH_CRON`. Server processes that share one index — every stdio session uses the default path — take a lease before seeding or refreshing it, so only one syncs at a time and the rest keep serving reads. For containers, CI, or seeding out of band (`CISA_CSAF_MIRROR_AUTO_INIT=false`, and `CISA_CSAF_REFRESH_CRON=off` to leave refreshes to you), run the scripts directly; they take the same lease:

```sh
bun run mirror:init      # full build, idempotent, safe to re-run after an interrupt
bun run mirror:refresh   # incremental: fetches only documents whose revision date moved
bun run mirror:verify    # readiness, sync status, checkpoint, count, content version, SQLite integrity; non-zero on failure
```

### Docker

```sh
docker build -t cisa-cybersecurity-mcp-server .
docker run --rm -p 3010:3010 -v cisa-mirror:/usr/src/app/.mirror cisa-cybersecurity-mcp-server
```

The Dockerfile defaults to HTTP transport, stateless session mode, and logs to `/var/log/cisa-cybersecurity-mcp-server`. OpenTelemetry peer dependencies are installed by default — build with `--build-arg OTEL_ENABLED=false` to omit them. The image sets `CISA_CSAF_MIRROR_PATH=/usr/src/app/.mirror/csaf.sqlite3`; mount a volume over `/usr/src/app/.mirror` so the advisory index survives a container recreation; the image ships the `mirror:*` scripts for `docker exec <container> bun run mirror:refresh`.

## Project structure

| Directory | Purpose |
|:---|:---|
| `src/index.ts` | `createApp()` entry point: wires the four services, schedules the refresh jobs, registers the surface. |
| `src/config` | Server-specific environment variable parsing and validation with Zod. |
| `src/mcp-server/tools` | Tool definitions (`*.tool.ts`). |
| `src/mcp-server/resources` | Resource definitions (`*.resource.ts`). |
| `src/mcp-server/schemas` | Output schemas and renderers shared by the KEV and advisory tools and resources. |
| `src/reference` | Static reference data: BOD 26-04 Table 1, canonical sector names, CVSS bands. |
| `src/services/kev-catalog` | KEV JSON feed: snapshot, derived indexes, conditional refresh. |
| `src/services/vulnrichment` | Per-CVE SSVC enrichment fetch with a TTL cache. |
| `src/services/csaf-mirror` | The ICS advisory index: schema, ingest, normalization, queries. |
| `src/services/cisa-feeds` | The three RSS feeds, parsed and cached on a TTL. |
| `scripts/` | Build, checks, and the `mirror:*` commands. |
| `tests/` | Unit, integration, fuzz, and smoke tests mirroring `src/`. |

## Development guide

See [`CLAUDE.md`/`AGENTS.md`](./CLAUDE.md) for development guidelines and architectural rules, and [`docs/design.md`](./docs/design.md) for the as-built specification. The short version:

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

The license covers this code, not the data it serves. KEV entries are US Government work in the public domain and Vulnrichment is CC0-1.0, but the CSAF repository declares no license and many advisories republish vendor text, so check reuse rights at each advisory's `url` before redistributing it. This project is not affiliated with or endorsed by CISA or the Department of Homeland Security.
