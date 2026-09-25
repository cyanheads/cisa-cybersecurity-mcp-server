# Developer Protocol

**Server:** cisa-cybersecurity-mcp-server
**Version:** 0.3.0
**Framework:** [@cyanheads/mcp-ts-core](https://www.npmjs.com/package/@cyanheads/mcp-ts-core) `^0.13.6`
**Engines:** Bun ≥1.4.0, Node ≥24.0.0
**MCP SDK:** `@modelcontextprotocol/server` ^2.0.0
**Zod:** ^4.6.5

> **Read the framework docs first:** `node_modules/@cyanheads/mcp-ts-core/CLAUDE.md` contains the full API reference — builders, Context, error codes, exports, patterns. This file covers server-specific conventions only.

---

## This Server

Four keyless CISA datasets, all read-only, served over seven tools and two resources. `docs/design.md` is the as-built specification — upstream shapes, per-tool contracts, storage tiers, and the numbered decisions log. Read it before changing a handler; every count and field name in it was verified against the live sources.

**Surface**

| Primitive | Backed by |
|:----------|:----------|
| `cisa_list_reference` | Static reference tables in `src/reference/` plus live service state. No network call — it is the routing target of every recovery hint on this surface, so `openWorldHint` is `false`. |
| `cisa_check_cve_status` | `kev-catalog`. Up to 200 CVE IDs, zero upstream requests. |
| `cisa_search_kev` | `kev-catalog`. Filters AND together against the whole snapshot, never a page. |
| `cisa_get_ssvc` | `vulnrichment` + `kev-catalog`. Computes the BOD 26-04 timeline from three published decision points plus the caller's `assetExposure`. |
| `cisa_search_ics_advisories` | `csaf-mirror` + `kev-catalog`. FTS5 plus indexed filters over the local index; KEV membership joins the in-memory snapshot and is awaited only under `inKev` — otherwise best-effort, so a KEV outage never fails an advisory search. |
| `cisa_get_advisory` | `csaf-mirror`. `outlineOnOverflow` at `ADVISORY_OUTLINE_BUDGET` (24 KB), `selectSections` on the re-call, and `cves` narrowing `vulnerabilities` below the section level. |
| `cisa_get_alerts` | `cisa-feeds`. A 30-item rolling window; the cap is upstream's, not a server choice. |
| `cisa://kev/{cveId}` | `kev-catalog`. Same record shape `cisa_check_cve_status` returns. |
| `cisa://advisory/{advisoryId}` | `csaf-mirror`. The same overflow treatment as the tool's no-`sections` call. |

No prompts: every workflow here is a direct lookup or a filtered search the tool schema already describes.

**Services** — all four are init/accessor, constructed in `createApp({ setup })` and reached at request time through `getKevCatalog()` / `getVulnrichment()` / `getCsafMirror()` / `getCisaFeeds()`.

| Service | Tier | Refresh |
|:--------|:-----|:--------|
| `kev-catalog` | In-memory process-level snapshot with derived indexes | `If-Modified-Since` poll on `CISA_KEV_REFRESH_CRON`, on every transport. `If-None-Match` is deliberately unused — the origin serves an ETag and ignores it. |
| `csaf-mirror` | `MirrorService` over embedded SQLite + FTS5 | One archive seeds it; refresh diffs `changes.csv` and fetches only the documents whose revision date moved. `maintain()` runs once at boot and on `CISA_CSAF_REFRESH_CRON` (`src/services/refresh-schedule.ts`), on every transport: seed or re-ingest (older `INGEST_CONTENT_VERSION`) under auto-init, else refresh. Every sync takes a cross-process lease (`sync-lease.ts`). |
| `vulnrichment` | Per-CVE fetch with a `ctx.state` TTL cache | On demand. A 404 caches as a negative at one sixth of the TTL. |
| `cisa-feeds` | Timer cache | Unconditional — the feeds serve no `etag` and no `last-modified`, so nothing can make a request conditional. |

**Invariants worth keeping**

- Boot never depends on the advisory corpus. KEV, SSVC, and alert tools serve from the first request; the index seeds in the background and reports `mirror_not_ready` until it lands.
- An HTML body on a JSON or XML route is `ServiceUnavailable`, never `SerializationError` — cisa.gov serves a Drupal error page transiently, and a parse-error classification makes a recoverable outage look like a data-shape defect.
- A not-yet-seeded index throws rather than returning an empty result: an empty page asserts that nothing matches.
- An index store that cannot be opened is `mirror_unavailable` (`ConfigurationError`, non-retryable), never the raw filesystem error: caller-facing text never carries the index path, and resource listing and completion degrade to empty so `resources/list` keeps serving the KEV entries.
- Two processes never sync one index at once. Seed and refresh go through `CsafMirrorService.sync()`, which holds the `mirror_meta` lease (`sync-lease.ts`) — never call `mirrorInstance.runSync()` directly outside tests.
- Raise `INGEST_CONTENT_VERSION` (`src/services/csaf-mirror/ingest.ts`) whenever ingest would store different content for a document upstream has not revised — a row field, the stored document, a junction table. `refresh` never revisits an unchanged document, so without the bump the change never reaches an existing index. A new auxiliary table also needs a migration and a raised store-spec `version`.
- A computed BOD 26-04 timeline and CISA's assigned KEV due date are two separate facts, reported side by side and never reconciled.
- No DHS seal, CISA logo, or implied endorsement on any surface. Advisory responses always carry `url`, `csafUrl`, and `attribution` — the CSAF repository declares no license and many advisories republish vendor text.

**Mirror scripts** — `scripts/csaf-mirror-{init,refresh,verify}.ts`, sharing `scripts/_mirror-context.ts`. They ship in `package.json` `files[]` and in the Docker image, for `docker exec`, CI, and operators who drive seeding or refreshes themselves (`CISA_CSAF_MIRROR_AUTO_INIT=false`, `CISA_CSAF_REFRESH_CRON=off`). They resolve the server's index path and take its sync lease, so a run that finds a server syncing skips.

```sh
bun run mirror:init      # full build from the repository archive; idempotent
bun run mirror:refresh   # incremental, driven by the changes.csv diff
bun run mirror:verify    # readiness, status, checkpoint, count, content version, SQLite integrity; non-zero on failure
```

---

## What's Next?

When the user asks what's next or needs direction, suggest options based on the current project state. Common next steps:

1. **Re-run the `setup` skill** — ensures CLAUDE.md, skills, structure, and metadata are populated and up to date with the current codebase
2. **Run the `design-mcp-server` skill** — if the tool/resource surface hasn't been mapped yet, work through domain design
3. **Add tools/resources/prompts** — scaffold new definitions using the `add-tool`, `add-app-tool`, `add-resource`, `add-prompt` skills
4. **Add services** — scaffold domain service integrations using the `add-service` skill
5. **Add tests** — scaffold tests for existing definitions using the `add-test` skill
6. **Field-test definitions** — exercise tools/resources/prompts with real inputs using the `field-test` skill, get a report of issues and pain points
7. **Run `devcheck`** — lint, format, typecheck, and security audit
8. **Run the `security-pass` skill** — audit handlers for MCP-specific security gaps: output injection, scope blast radius, input sinks, tenant isolation
9. **Run the `polish-docs-meta` skill** — finalize README, CHANGELOG, metadata, and agent protocol for shipping
10. **Run the `maintenance` skill** — investigate changelogs, adopt upstream changes, and sync skills after `bun update --latest`

Tailor suggestions to what's actually missing or stale — don't recite the full list every time.

---

## Core Rules

- **Logic throws, framework catches.** Tool/resource handlers are pure — throw on failure, no `try/catch`. Plain `Error` is fine; the framework catches, classifies, and formats. Use error factories (`notFound()`, `validationError()`, etc.) when the error code matters.
- **Use `ctx.log`** for request-scoped logging. No `console` calls.
- **Use `ctx.state`** for tenant-scoped storage. Never access persistence directly.
- **Need input the caller didn't supply?** `return ctx.requestInput(...)` and read `ctx.inputs` when the handler is re-entered. Never `await` for user input mid-handler.
- **Secrets in env vars only** — never hardcoded.
- **Cut noise.** Add only what earns its place: no speculative generality, no guards for states the framework already prevents (Zod-validated params, classified errors), no abstraction until a third caller proves it, no option nothing sets.
- **Close the loop on issues.** When implementing work tracked by a GitHub issue, comment on the issue with what landed and close it. Do both — a comment without a close leaves stale issues open; a close without a comment leaves no record of what shipped. The comment is for future readers — state the concrete changes, not the conversation that produced them.

---

## Patterns

### Tool

`src/mcp-server/tools/definitions/check-cve-status.tool.ts`, trimmed to its shape:

```ts
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { CveIdInputSchema, KevRecordSchema, renderKevRecord, toKevRecordOutput, toKevRecordSummary, toMissingKevOutput } from '@/mcp-server/schemas/kev-record.js';
import { getKevCatalog } from '@/services/kev-catalog/kev-catalog-service.js';

export const checkCveStatusTool = tool('cisa_check_cve_status', {
  title: 'cisa_check_cve_status',
  description: 'Check CVE IDs against the CISA Known Exploited Vulnerabilities catalog — up to 200 per call, …',
  annotations: { readOnlyHint: true, idempotentHint: true },

  input: z.object({
    cveIds: z.array(CveIdInputSchema.describe('One CVE identifier, e.g. CVE-2025-39964.')).min(1).max(200)
      .describe('CVE identifiers to check, up to 200 per call. The whole batch costs zero upstream requests.'),
    detail: z.enum(['full', 'summary']).default('full')
      .describe('full returns every field of each in-KEV entry. summary returns only the triage fields …'),
  }),
  output: z.object({
    results: z.array(KevRecordSchema).describe('One result per requested CVE, in the order supplied.'),
    foundCount: z.number().int().describe('How many of the requested CVEs are in the catalog.'),
    notFoundCount: z.number().int().describe('How many of the requested CVEs are not in the catalog.'),
  }),

  // Success-path agent context. Lands only because it is declared here.
  enrichment: {
    asOf: z.string().describe('The UTC date daysUntilDue and overdue were computed against.'),
    summaryNote: z.string().optional().describe('Present only under detail "summary": which fields each in-KEV result omits …'),
    notice: z.string().optional().describe('Guidance when none of the supplied CVE IDs are in the catalog.'),
  },

  errors: [
    { reason: 'catalog_unavailable', code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'No KEV catalog snapshot is held and the fetch from cisa.gov failed.',
      retryable: true, thrownBy: 'service',
      recovery: 'The KEV catalog snapshot is not loaded yet; retry in a few seconds, or call cisa_list_reference with topic sources to see the current catalog state.' },
  ],

  async handler(input, ctx) {
    const catalog = getKevCatalog();
    const snapshot = await catalog.snapshot(ctx);
    const asOf = catalog.asOf();
    const project = input.detail === 'summary' ? toKevRecordSummary : toKevRecordOutput;
    /* CveIdInputSchema already trimmed and uppercased each ID. */
    const results = input.cveIds.map((cveId) => {
      const record = snapshot.byId.get(cveId);
      return record ? project(record, asOf) : toMissingKevOutput(cveId);
    });
    const foundCount = results.filter((result) => result.inKev).length;
    ctx.enrich({ asOf });
    if (input.detail === 'summary') ctx.enrich({ summaryNote: 'summary — in-KEV results omit … Call again with detail "full" to restore them.' });
    return { results, foundCount, notFoundCount: results.length - foundCount };
  },

  // format() populates content[] — the markdown twin of structuredContent.
  // Different clients read different surfaces (Claude Code → structuredContent,
  // Claude Desktop → content[]); both must carry the same data.
  // Enforced at lint time: every field in `output` must appear in the rendered text.
  format: (result) => [{ type: 'text', text: result.results.flatMap(renderKevRecord).join('\n') }],
});
```

Shared output shapes and their renderers live in `src/mcp-server/schemas/` — `kev-record.ts` and `advisory.ts` — because a tool and its resource twin must serialize identically. Add a field to the schema and the renderer in the same edit, or `format-parity` fails.

### Resource

`src/mcp-server/resources/definitions/kev-entry.resource.ts`, trimmed:

```ts
import { resource, z } from '@cyanheads/mcp-ts-core';
import { notFound } from '@cyanheads/mcp-ts-core/errors';
import { CveIdInputSchema, KevRecordSchema, toKevRecordOutput } from '@/mcp-server/schemas/kev-record.js';
import { getKevCatalog } from '@/services/kev-catalog/kev-catalog-service.js';

export const kevEntryResource = resource('cisa://kev/{cveId}', {
  name: 'kev-entry',
  title: 'KEV catalog entry',
  description: 'One entry from the CISA Known Exploited Vulnerabilities catalog, addressed by CVE ID — …',
  mimeType: 'application/json',
  /* Public-domain data, byte-identical per tenant, refreshed on a 30-minute poll. */
  cacheHint: { ttlMs: 1_800_000, cacheScope: 'public' },

  params: z.object({ cveId: CveIdInputSchema.describe('The CVE identifier to look up.') }),
  output: KevRecordSchema,

  async handler(params, ctx) {
    const catalog = getKevCatalog();
    const snapshot = await catalog.snapshot(ctx);
    const record = snapshot.byId.get(params.cveId);
    if (!record) throw notFound(`${params.cveId} is not in the KEV catalog. …`, { cveId: params.cveId });
    return toKevRecordOutput(record, catalog.asOf());
  },

  list: () => ({ resources: /* the 30 most recently added entries */ [] }),
  complete: { cveId: /* up to 100 CVE IDs from the snapshot */ () => [] },
});
```

### Server config

```ts
// src/config/server-config.ts — lazy-parsed, separate from framework config
import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';

const ServerConfigSchema = z.object({
  kevRefreshCron: refreshCron('*/30 * * * *')   // 'off' disables; any other non-cron value fails startup
    .describe('Cron for the KEV conditional-refresh poll, on every transport; "off" disables it.'),
  csafMirrorPath: z.string().optional()           // unset → defaultCsafMirrorPath(): the per-user cache dir
    .describe('Filesystem path to the ICS advisory SQLite index; unset, the per-user cache directory.'),
  csafMirrorAutoInit: z.stringbool().default(true)
    .describe('Seed the advisory mirror in the background at startup when it has never synced.'),
  httpTimeoutMs: z.coerce.number().int().positive().default(30_000)
    .describe('Per-request timeout for every upstream fetch, in milliseconds.'),
});

let _config: ServerConfig | undefined;
export function getServerConfig(): ServerConfig {
  if (_config) return _config;
  const parsed = parseEnvConfig(ServerConfigSchema, {
    kevRefreshCron: 'CISA_KEV_REFRESH_CRON',
    csafMirrorPath: 'CISA_CSAF_MIRROR_PATH',
    csafMirrorAutoInit: 'CISA_CSAF_MIRROR_AUTO_INIT',
    httpTimeoutMs: 'CISA_HTTP_TIMEOUT_MS',
  });
  _config = {
    ...parsed,
    csafMirrorPath: parsed.csafMirrorPath ??
      defaultCsafMirrorPath({ env: process.env, homedir: homedir(), platform: process.platform }),
  };
  return _config;
}
```

The index default is never relative to the working directory: some clients start stdio servers at `/`. `defaultCsafMirrorPath()` takes the host as an argument so tests resolve it without touching the real user cache. A refresh cron's empty value keeps meaning the default — the `.mcpb` host forwards `""` for every option left blank — so `off` is the disable value.

All seven `CISA_*` variables are optional — every source is keyless and every tunable has a working default, so the server runs correctly with none of them set. Adding one means editing four files together: the schema above, `.env.example`, `server.json` `environmentVariables[]` (both package entries), and `manifest.json` (`mcp_config.env` + `user_config`). `lint:packaging` fails on a mismatch.

`parseEnvConfig` maps Zod schema paths → env var names so errors name the variable (`CISA_CSAF_MIRROR_PATH`) not the path (`csafMirrorPath`). Throws `ConfigurationError`, which the framework prints as a clean startup banner.

For env booleans use `z.stringbool()`, never `z.coerce.boolean()` — `Boolean("false")` is `true`, so a coerced flag can't be disabled through the environment. `z.stringbool()` parses `true/false/1/0/yes/no/on/off` and rejects anything else, so `=false` actually disables.

### Server identity and instructions

`createApp()` accepts optional identity fields forwarded to the SDK's `initialize` response and the server manifest (`/.well-known/mcp.json`):

```ts
await createApp({
  // Display identity is the machine name on every surface — name and title are
  // both the unscoped package name, never a Title Case prose label.
  name: 'cisa-cybersecurity-mcp-server',
  title: 'cisa-cybersecurity-mcp-server',
  websiteUrl: 'https://github.com/cyanheads/cisa-cybersecurity-mcp-server',
  instructions: 'This server serves four CISA datasets, all keyless and all read-only. …',
});
```

`description` is deliberately absent: `package.json` is its canonical source and the framework derives the served description from it, so an explicit copy here is drift. `lint:packaging` enforces the `name`/`title` pair against the unscoped package name.

`instructions` is optional server-level orientation, sent on every `initialize` as session-level context. Here it routes the caller to the right entry point per dataset, states that the computed BOD 26-04 timeline is not a compliance determination, and warns that the index seeds on first run — guidance that would otherwise be repeated across seven tool descriptions. Client adoption is uneven, but there's no downside when set.

### Session posture and shutdown

Two more `createApp()` options shape how the server runs rather than how it presents itself:

```ts
await createApp({
  sessionMode: 'stateless',          // or { default: 'stateful', require: 'stateful' }
  setup(core) { startMyWatcher(core.config); },
  async teardown() { await stopMyWatcher(); },
});
```

`sessionMode` declares the HTTP session posture in `src/` instead of leaving it to a deployment's `MCP_SESSION_MODE`, which still wins whenever it carries a meaningful value (an empty string and an unsubstituted `${…}` placeholder read as unset and fall through to the option). Add `require: 'stateful'` when a tool asks the caller for input mid-handler via `ctx.requestInput`: startup then fails with a `ConfigurationError` rather than serving a mode in which a 2025-era client can never answer the prompt. Stdio is never refused.

`teardown(core)` is the `setup()` counterpart — release a watcher, socket, or non-`unref()`'d timer there. It runs after the transport stops and before the logger closes, on every shutdown path, and a signal-triggered shutdown then exits the process explicitly (0, or 1 if a step never settles within the framework's 10 s ceiling).

---

## Context

Handlers receive a unified `ctx` object. Key properties:

| Property | Description |
|:---------|:------------|
| `ctx.log` | Request-scoped logger — `.debug()`, `.info()`, `.notice()`, `.warning()`, `.error()`. Auto-correlates requestId, traceId, tenantId. Dual-sink: Pino **and** `notifications/message` to the client, so treat it as client-visible. |
| `ctx.state` | Tenant-scoped KV — `.get(key)`, `.set(key, value, { ttl? })`, `.delete(key)`, `.getMany(keys)`, `.list(prefix, { cursor, limit })`. Used here for the `ssvc/<CVE-ID>` enrichment cache, best-effort in both directions: a miss or a storage failure falls through to a fetch, so correctness never depends on it. |
| `ctx.enrich` | Success-path agent context (empty-result notices, query echo, pagination totals) — `ctx.enrich(...)` or `.notice()` / `.total()` / `.echo()` / `.truncated()`. Reaches `structuredContent` and `content[]`; lands only when the definition declares an `enrichment` block (no-op otherwise). Note the written field names: `.total()` writes `totalCount`, `.truncated()` writes `truncated` / `shown` / `cap` as three flat fields, `.echo()` writes `effectiveQuery`. |
| `ctx.signal` | `AbortSignal` for cancellation. Forwarded to every upstream fetch. |
| `ctx.requestId` | Unique request ID. |
| `ctx.tenantId` | Tenant ID from JWT; `'default'` for stdio or HTTP with auth off. |

---

## Errors

Handlers throw — the framework catches, classifies, and formats.

**Recommended: typed error contract.** Declare `errors: [{ reason, code, when, recovery, retryable?, severity?, thrownBy? }]` on `tool()` / `resource()` to receive `ctx.fail(reason, …)` typed against the reason union. TypeScript catches typos at compile time, `data.reason` is auto-populated for observability, linter enforces conformance against the handler body. `recovery` is required (≥ 5 words, lint-validated) — the single source of truth for the agent's next move. Pass `ctx.recoveryFor('reason')` as the throw's data to put it on the wire (`data.recovery.hint`, mirrored into `content[]` text unless the message already contains it verbatim); override with an explicit `{ recovery: { hint: '...' } }` when dynamic runtime context matters. Forwarding it is lint-enforced per throw site (`error-contract-recovery-unforwarded`). Mark an entry the service layer throws with `thrownBy: 'service'` so `error-contract-unthrown` skips it — lint-only metadata, nothing at runtime reads it. Baseline codes (`InternalError`, `ServiceUnavailable`, `Timeout`, `ValidationError`, `SerializationError`, `RequestCancelled`) bubble freely and don't need declaring.

```ts
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';

errors: [
  { reason: 'no_match', code: JsonRpcErrorCode.NotFound,
    when: 'No item matched the query',
    recovery: 'Broaden the query or check the spelling and try again.' },
],
async handler(input, ctx) {
  const item = await db.find(input.id);
  if (!item) throw ctx.fail('no_match', `No item ${input.id}`, ctx.recoveryFor('no_match'));
  return item;
}
```

**Declare contracts inline on each tool.** The contract is part of the tool's public surface — one file should give the full picture. Don't extract a shared `errors[]` constant; per-tool repetition is the intended cost of locality.

**Fallback (no contract entry fits):** throw via factories or plain `Error`.

```ts
// Error factories — explicit code
import { notFound, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
throw notFound('Item not found', { itemId });
throw serviceUnavailable('API unavailable', { url }, { cause: err });

// Plain Error — framework auto-classifies from message patterns
throw new Error('Item not found');           // → NotFound
throw new Error('Invalid query format');     // → ValidationError

// McpError — when no factory exists for the code
import { McpError, JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
throw new McpError(JsonRpcErrorCode.InitializationFailed, 'Connection failed', { pool: 'primary' });
```

See framework CLAUDE.md and the `api-errors` skill for the full auto-classification table, all available factories, and the contract reference.

---

## Structure

```text
src/
  index.ts                              # createApp() — services, background refresh, surface registration
  config/
    server-config.ts                    # The seven CISA_* vars (Zod schema, lazy-parsed) and the per-user index default
  reference/
    bod-2604.ts                         # Table 1, its definitions, and the timeline resolver
    cvss.ts                             # Severity bands and the CVSS v2 band derivation
    sectors.ts                          # The 16 canonical sectors and the longest-match extractor
    tables.ts                           # The cisa_list_reference topic blocks
  services/
    kev-catalog/                        # kev-catalog-service.ts, parse.ts, types.ts
    vulnrichment/                       # vulnrichment-service.ts, paths.ts, types.ts
    csaf-mirror/                        # csaf-mirror-service.ts, ingest.ts, normalize.ts, schema.ts, sync-lease.ts, tar.ts, types.ts
    refresh-schedule.ts                 # Boot pass over the index and the two refresh cron jobs, every transport
    upstream-http.ts                    # The single fetch boundary every service reaches the network through
  mcp-server/
    schemas/
      kev-record.ts                     # KEV output schema + renderer, shared by tool and resource
      advisory.ts                       # Advisory output shape, section list, renderers
    tools/definitions/
      [tool-name].tool.ts               # Seven tools, registered via index.ts
    resources/definitions/
      [resource-name].resource.ts       # Two resources, registered via index.ts
```

No `prompts/` directory — this server ships none.

---

## Naming

| What | Convention | Example |
|:-----|:-----------|:--------|
| Files | kebab-case with suffix | `search-docs.tool.ts` |
| Tool/resource/prompt names | snake_case | `search_docs` |
| Directories | kebab-case | `src/services/doc-search/` |
| Descriptions | Single string or template literal, no `+` concatenation | `'Search items by query and filter.'` |

---

## Skills

Skills are modular instructions in `framework-skills/` at the project root. Read them directly when a task matches — e.g., `framework-skills/add-tool/SKILL.md` when adding a tool. `bun run list-skills` prints the full registry. The directory is deliberately not `skills/`: Claude Code and Codex auto-load a plugin's root `skills/`, so a server that ships `.claude-plugin/` or `.codex-plugin/` would hand these development skills to every agent that installs it. Keep `skills/` free for skills meant for those agents.

**Agent skill directory:** Copy skills into the directory your agent discovers (Claude Code: `.claude/skills/`, others: equivalent). Skills then load as context without referencing `framework-skills/` paths. After framework updates, run the `maintenance` skill — Phase B re-syncs the agent directory.

Available skills:

| Skill | Purpose |
|:------|:--------|
| `setup` | Post-init project orientation |
| `design-mcp-server` | Design tool surface, resources, and services for a new server |
| `add-tool` | Scaffold a new tool definition |
| `add-app-tool` | Scaffold an MCP App tool + paired UI resource |
| `add-resource` | Scaffold a new resource definition |
| `add-prompt` | Scaffold a new prompt definition |
| `add-service` | Scaffold a new service integration |
| `add-test` | Scaffold test file for a tool, resource, or service |
| `field-test` | Exercise tools/resources/prompts with real inputs, verify behavior, report issues |
| `tool-defs-analysis` | Read-only audit of MCP definition language across the surface — voice, leaks, defaults, recovery hints, output descriptions |
| `security-pass` | Audit server for MCP-flavored security gaps: output injection, scope blast radius, input sinks, tenant isolation |
| `code-simplifier` | Post-session cleanup against `git diff` — modernize syntax, consolidate duplication, align with the codebase |
| `polish-docs-meta` | Finalize docs, README, metadata, and agent protocol for shipping |
| `git-wrapup` | Land working-tree changes as a commit stack — version bump, changelog, verify, commit by concern, release commit on top. No tag, no push to main; opens the release PR when the project declares release PR mode |
| `release-pr-review` | Review pass on an open release PR — simplifier + correctness review, fixes as ordinary commits on top of the stack, PR body kept in sync. Release PR mode only |
| `release-and-publish` | Fast-forward merge (release PR mode) + tag + push + npm + MCP Registry + GH Release + Docker. Picks up from `git-wrapup` |
| `maintenance` | Investigate changelogs, adopt upstream changes, sync skills to agent dirs |
| `orchestrations` | Chain task skills into a gated multi-phase pipeline — build-out, QA-fix, update-ship — when you can spawn sub-agents |
| `report-issue-framework` | File a bug or feature request against `@cyanheads/mcp-ts-core` via `gh` CLI |
| `report-issue-local` | File a bug or feature request against this server's own repo via `gh` CLI |
| `techniques` | Catalog of response/data-shaping techniques — overflow handling, payload shaping, retrieval patterns |
| `api-auth` | Auth modes, scopes, JWT/OAuth |
| `api-canvas` | DataCanvas: register tabular data, run SQL, export, plus the `spillover()` helper for big result sets — Tier 3 opt-in |
| `api-config` | AppConfig, parseConfig, env vars |
| `api-context` | Context interface, RequestContext, logger, state, multi-round-trip input |
| `api-errors` | McpError, JsonRpcErrorCode, error patterns |
| `api-linter` | Definition linter rule catalog — invoked by `bun run lint:mcp` and `devcheck` |
| `api-mirror` | MirrorService: persistent self-refreshing local mirror (embedded SQLite + FTS5) of a bulk upstream dataset — Tier 3 opt-in |
| `api-services` | LLM, Speech, Graph services |
| `api-testing` | createMockContext, test patterns |
| `api-utils` | Formatting, parsing, security, pagination, scheduling, telemetry helpers |
| `api-telemetry` | OTel catalog: spans, metrics, completion logs, env config, cardinality rules |
| `api-workers` | Cloudflare Workers runtime |

**Chaining skills into pipelines.** When the user wants a multi-phase effort — build this server out, QA-and-fix the surface, update-and-ship — *and you can spawn sub-agents*, `framework-skills/orchestrations/SKILL.md` sequences the task skills above into a gated pipeline with verification at each step. Read it to drive the run. Optional: skip it if you can't orchestrate sub-agents, and ignore it entirely if you were *spawned* as one — you've already been scoped to a single phase.

When you complete a skill's checklist, check the boxes and add a completion timestamp at the end (e.g., `Completed: 2026-03-11`).

---

## Commands

**Runtime:** Scripts use Bun's native TypeScript execution — `bun run <cmd>` is the standard invocation. `npm run <cmd>` also works (npm delegates to bun).

| Command | Purpose |
|:--------|:--------|
| `bun run build` | Compile TypeScript |
| `bun run rebuild` | Clean + build |
| `bun run clean` | Remove build artifacts |
| `bun run devcheck` | Lint + format + typecheck + security + changelog sync |
| `bun run audit:fix` | `bun audit fix` — upgrade vulnerable packages to the lowest safe version within existing ranges (`--dry-run` previews, `--latest` rewrites ranges). First response when `devcheck` flags a transitive advisory; then `bun update <name>`, then `bun dedupe` |
| `bun run audit:refresh` | Delete `bun.lock` and reinstall. Last resort after `audit:fix`, `bun update <name>`, and `bun dedupe` — re-resolves every ranged dep (the framework pin included) and rewrites the lockfile as `lockfileVersion: 2` |
| `bun run lint:mcp` | Run the MCP definition linter standalone (rule catalog: `api-linter` skill) |
| `bun run lint:packaging` | Packaging surface checks — `server.json`/`manifest.json` env-var parity (run by devcheck) |
| `bun run list-skills` | Print the skill registry |
| `bun run tree` | Generate directory structure doc |
| `bun run format` | Auto-fix formatting (safe fixes only) |
| `bun run format:unsafe` | Also apply Biome's unsafe autofixes — review the diff; they can change behavior |
| `bun run test` | Run tests (Vitest — use `bun run test`, not `bun test`) |
| `bun run test:coverage` | Run tests with Istanbul coverage |
| `bun run mirror:init` | Full out-of-band build of the ICS advisory index; idempotent |
| `bun run mirror:refresh` | Incremental advisory refresh, driven by the `changes.csv` diff |
| `bun run mirror:verify` | Index health — readiness, status, checkpoint, count, content version (stale is a warning), SQLite integrity. Non-zero exit on failure |
| `bun run start:stdio` | Production mode (stdio) |
| `bun run start:http` | Production mode (HTTP) |
| `bun run changelog:build` | Regenerate `CHANGELOG.md` from `changelog/*.md` |
| `bun run changelog:check` | Verify `CHANGELOG.md` is in sync (used by devcheck) |
| `bun run bundle` | Build, pack, and clean a `.mcpb` for one-click Claude Desktop install |
| `bun run release:github` | Create the GitHub release from the pushed tag |
| `bun run publish-mcp` | Publish `server.json` to the MCP Registry |

**CI is one file.** `.github/workflows/codeql.yml` (scaffolded) is the only GitHub Actions workflow: CodeQL is GitHub-owned end to end, and the file runs only while the repo's CodeQL *default setup* is turned off. Verification — `devcheck`, tests, the release gates — runs locally; don't add a workflow that re-runs it.

---

## Bundling

`npm run bundle` produces a `.mcpb` extension bundle for one-click install in Claude Desktop. The pack step is followed by `scripts/clean-mcpb.ts`, which prunes dev dependencies (`mcpb clean`) and strips three classes of `node_modules/**` content that root-anchored `.mcpbignore` patterns cannot reach: dependency-shipped agent docs (`framework-skills/`, `skills/`, `.claude/`, `.agents/`, `SKILL.md`), platform-specific native bindings that would lock the bundle to the platform it was packed on (`NATIVE_BINDING_ENTRY`), and build-only sources (`BUILD_ONLY_ENTRY`).

`better-sqlite3` is a regular dependency here and the bundle **carries it**: the npm tarball ships all eight platform prebuilds and `lib/binding.js` picks one at runtime, so the bundle stays cross-platform with no install script and no node-gyp step. `BUILD_ONLY_ENTRY` strips only its `deps/` and `src/` trees — 9.8 MB of SQLite C source used solely for a source build — and never `prebuilds/`, which must survive. That is why it is a separate literal from `NATIVE_BINDING_ENTRY`, whose whole job is removing platform-locked natives. The regexes are duplicated in `scripts/lint-packaging.ts`; the files' own comments require editing them together. Under Bun the driver is never loaded at all — `openSqliteHandle` uses the built-in `bun:sqlite`.

An `.mcpb` user has no shell into the bundle, which is why the advisory index seeds itself in the background rather than requiring `mirror:init`. MCPB is stdio-only — HTTP and Docker deployments are unaffected, and this server has no Cloudflare Workers deployment (the index needs embedded SQLite and a persistent filesystem).

**Adding an env var requires both files:** `server.json` (registry discovery, `environmentVariables[]`) and `manifest.json` (bundle install UX, `mcp_config.env` + `user_config`). `lint:packaging` (run by `devcheck`) verifies the env var names match, that every `user_config` option is wired into `mcp_config.env` as `"X": "${user_config.X}"` (the host substitutes nothing else — `"${X}"` reaches the server as that literal string), and that an optional string option carries `"default": ""`.

**README install badges** (Claude Desktop `.mcpb`, Cursor, VS Code) and the `base64` / `encodeURIComponent` config-generation commands are ship-time concerns — run the `polish-docs-meta` skill, which carries the badge format, layout, and generation snippets in `framework-skills/polish-docs-meta/references/readme.md`.

---

## Changelog

Directory-based, grouped by minor series via the `.x` semver-wildcard convention. Source of truth: `changelog/<major.minor>.x/<version>.md` (e.g. `changelog/0.1.x/0.1.0.md`) — one file per release, shipped in the npm package. At release, author the per-version file with a concrete version and date, then run `npm run changelog:build` to regenerate the rollup. `changelog/template.md` is a **pristine format reference** — never edited or moved; read it for the frontmatter + section layout when scaffolding. `CHANGELOG.md` is a **navigation index** (header + link + summary per version), regenerated by `npm run changelog:build` — devcheck hard-fails on drift; never hand-edit it.

Each per-version file opens with YAML frontmatter:

```markdown
---
summary: "One-line headline, ≤350 chars"  # required — powers the rollup index
breaking: false                            # optional — true flags breaking changes
security: false                            # optional — true ONLY for a source-code security fix, never a dependency CVE bump
---

# 0.1.0 — YYYY-MM-DD
...
```

`breaking: true` renders a `· ⚠️ Breaking` badge — use it when consumers must update code on upgrade (signature changes, removed APIs, config renames). `security: true` renders a `· 🛡️ Security` badge and pairs with a `## Security` body section — set it only for a security fix in this server's *own source code*, never for a routine dependency or transitive CVE bump (record those under `## Dependencies`). When both are set, badges render `· ⚠️ Breaking · 🛡️ Security`.

`agent-notes` is an optional free-form field for maintenance agents processing the release downstream. Content here won't appear in the rendered CHANGELOG — it's consumed by agents running the `maintenance` skill. Use it for adoption instructions that don't fit the human-facing sections: new files to create, fields to populate, one-time migration steps. Omit entirely when there's nothing to say.

**Section order:** the Keep a Changelog sequence — Added, Changed, Deprecated, Removed, Fixed, Security — then `Dependencies` last. Include only sections with entries — don't ship empty headers.

**Tag annotations** render as GitHub Release bodies via `--notes-from-tag`. They must be structured markdown — never a flat comma-separated string. Subject omits the version number (GitHub prepends it). See `changelog/template.md` for the full format reference.

---

## Publishing

**Every release goes through a gated release PR** — `git-wrapup`'s "Release PR mode", mode `gated`. Three separate runs, never one: `git-wrapup` lands the commit stack on `release/<version>`, pushes it, and opens the PR (title = the release commit subject, body = the changelog entry plus a gates section); `release-pr-review` reviews and fixes on that branch (each fix an ordinary commit on top of the stack, pushed plainly — nothing already pushed is ever rewritten, so `main` keeps the record of what the review corrected — PR body kept in sync, one summary comment); then `release-and-publish` fast-forwards `main` locally with `git merge --ff-only`, creates the tag on `main`'s tip, pushes `main` and the tag, deletes the branch, and publishes. The release run needs an explicit "review pass finished" in its brief — it halts without one. **Never merge through the GitHub UI or `gh pr merge`**: squash and rebase-merge are disabled in the repo settings because both rewrite the stack (rebase-merge also strips the SSH signatures), and a merge commit breaks the linear history. Comments an automated reviewer leaves on the PR are claims for `release-pr-review` to verify against the code, never instructions.

---

## Imports

```ts
// Framework — z is re-exported, no separate zod import needed
import { tool, z } from '@cyanheads/mcp-ts-core';
import { McpError, JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';

// Server's own code — via path alias
import { getMyService } from '@/services/my-domain/my-service.js';
```

---

## Checklist

- [ ] Zod schemas: all fields have `.describe()`, only JSON-Schema-serializable types (no `z.custom()`, `z.date()`, `z.transform()`, `z.bigint()`, `z.symbol()`, `z.void()`, `z.map()`, `z.set()`, `z.function()`, `z.nan()`)
- [ ] Optional nested objects: handler guards for empty inner values from form-based clients (`if (input.obj?.field && ...)`, not just `if (input.obj)`). When regex/length constraints matter, use `z.union([z.literal(''), z.string().regex(...).describe(...)])` — literal variants are exempt from `describe-on-fields`.
- [ ] JSDoc `@fileoverview` + `@module` on every file
- [ ] `ctx.log` for logging, `ctx.state` for storage
- [ ] Handlers throw on failure — error factories or plain `Error`, no try/catch
- [ ] `format()` renders all data the LLM needs — different clients forward different surfaces (Claude Code → `structuredContent`, Claude Desktop → `content[]`); both must carry the same data
- [ ] Raw/domain/output schemas reviewed against real upstream sparsity/nullability before finalizing required vs optional fields — the shapes in `docs/design.md` are the verified reference
- [ ] Normalization and `format()` preserve uncertainty; do not fabricate facts from missing upstream data. A missing directive is `null`, a derived CVSS band is flagged `severityDerived`, and a verbatim `sectorsRaw` survives normalization
- [ ] Tests include at least one sparse payload case with omitted upstream fields (empty `cwes`, no sector note, `cvss_v2`-only, no CISA-ADP container)
- [ ] A shared output schema in `src/mcp-server/schemas/` and its renderer changed together — `format-parity` fails otherwise
- [ ] A new `CISA_*` variable added to all four surfaces: `server-config.ts`, `.env.example`, `server.json` (both package entries), `manifest.json` (`mcp_config.env` + `user_config` with `"default": ""`)
- [ ] Advisory output still carries `url`, `csafUrl`, and `attribution`; no DHS seal, CISA logo, or implied endorsement anywhere
- [ ] Registered in `createApp()` arrays (directly or via barrel exports)
- [ ] Tests use `createMockContext()` from `@cyanheads/mcp-ts-core/testing`
- [ ] `.codex-plugin/plugin.json` populated — `name`, `version`, `description`, `repository`, `license` from `package.json`; `interface.displayName` = the unscoped repo name (never the npm scope — `lint:packaging` enforces this); `interface.shortDescription` from `package.json` description
- [ ] `.codex-plugin/mcp.json` updated — server name key is the unscoped repo name; every user-supplied variable (API key, contact email, instance URL) is listed in `env_vars` so Codex forwards it from the user's environment. Never write `"KEY": ""` into `env` — an empty value replaces the user's exported key and is read as unset
- [ ] `.claude-plugin/plugin.json` populated — `name`, `version`, `description`, `author`, `repository`, `license`, `keywords` from `package.json`; inline `mcpServers` entry keyed by the unscoped repo name. Every user-supplied variable is declared under `userConfig` (`type`, `title`, `description`; `sensitive: true` for keys and tokens; `required: true` or `default: ""`) and referenced from `env` as `"KEY": "${user_config.<option>}"` — mirror the `user_config` block in `manifest.json`. Never write `"KEY": ""` into `env`
- [ ] `npm run devcheck` passes
