# cisa-cybersecurity-mcp-server — Design

Package `@cyanheads/cisa-cybersecurity-mcp-server` · registry `io.github.cyanheads/cisa-cybersecurity-mcp-server` · display and machine identity `cisa-cybersecurity-mcp-server` · tool prefix `cisa_`.

Upstream shapes in this document were verified against the live sources on 2026-09-19. Every count, field name, header behavior, and size is an observation, not a restatement of upstream documentation.

---

## MCP Surface

### Tools

| Name | Description | Key Inputs | Annotations |
|:-----|:------------|:-----------|:------------|
| `cisa_list_reference` | Decode the vocabulary the rest of the surface takes as input: BOD 26-04 remediation timelines, KEV field meanings, SSVC decision-point values, critical-infrastructure sector names, advisory ID formats, CVSS severity bands, and live data provenance. | `topic` | `readOnlyHint`, `openWorldHint: false` |
| `cisa_check_cve_status` | Check up to 200 CVE IDs against the CISA Known Exploited Vulnerabilities catalog in one call, returning federal remediation deadlines, overdue status, ransomware and forensic-triage flags, and the directive each entry cites. | `cveIds[]`, `detail` | `readOnlyHint` |
| `cisa_search_kev` | Search the KEV catalog by vendor, product, CWE, date added, due date, overdue status, ransomware use, forensic-triage tier, or directive. | filters, `sortBy`, `limit`, `cursor` | `readOnlyHint` |
| `cisa_get_ssvc` | Fetch the SSVC decision points CISA publishes per CVE — Exploitation, Automatable, Technical Impact — and compute the BOD 26-04 remediation timeline they imply for a stated asset exposure. | `cveIds[]`, `assetExposure` | `readOnlyHint` |
| `cisa_search_ics_advisories` | Search the CISA industrial control system advisory corpus by vendor, product, CVE, CWE, KEV membership, CVSS range, severity, sector, series, or free text over advisory titles and product names. | `q`, filters, `sortBy`, `limit`, `cursor` | `readOnlyHint` |
| `cisa_get_advisory` | Read one ICS advisory in full: affected products with version ranges, per-CVE CVSS and CWE, remediations, sectors, and revision history — or only the vulnerability entries for named CVEs. | `advisoryId`, `sections[]`, `cves[]` | `readOnlyHint` |
| `cisa_get_alerts` | List what CISA has published recently from its advisory and alert feeds. | `feed`, `limit`, `since` | `readOnlyHint` |

### Resources

| URI Template | Name / Title | Description | Pagination |
|:-------------|:-------------|:------------|:-----------|
| `cisa://kev/{cveId}` | `kev-entry` / "KEV catalog entry" | One KEV record, same shape as a `cisa_check_cve_status` result. `list()` returns the 30 most recently added entries. | `list()` capped at 30, no cursor |
| `cisa://advisory/{advisoryId}` | `ics-advisory` / "ICS advisory (CSAF)" | One flattened ICS advisory, same shape as `cisa_get_advisory`'s full arm. `list()` returns the 30 most recently revised advisories. | `list()` capped at 30, no cursor |

Both are fully covered by tools; a tool-only client loses nothing.

### Prompts

None. Every workflow this server serves is a direct lookup or a filtered search; a prompt template would add a surface nothing reaches for.

---

## Overview

CISA publishes four operational vulnerability datasets as free, keyless, machine-readable files. This server turns them into a queryable surface:

- **Known Exploited Vulnerabilities (KEV)** — the catalog of CVEs CISA has confirmed are exploited in the wild, each carrying a federal remediation deadline.
- **BOD 26-04 remediation timelines** — the binding operational directive that sets those deadlines from four decision points. It supersedes and revokes BOD 22-01 and BOD 19-02.
- **Vulnrichment SSVC** — the Exploitation / Automatable / Technical Impact values CISA publishes per CVE as a CVE Authorized Data Publisher.
- **ICS advisories in CSAF 2.0** — machine-readable advisories (3,937 at the 2026-09-24 index checkpoint) covering PLC, HMI, SCADA, building-automation, and medical-device products, spanning 2010 to today.

Audience: security engineers, AppSec reviewers, compliance officers, incident responders, enterprise patch managers, OT/ICS asset owners, and automated triage agents deciding what to fix first.

Scope boundary: official CISA open outputs only. No packet capture, no payloads, no proprietary or closed feeds, no interactive scanning, and no Automated Indicator Sharing (AIS needs a signed agreement, a Federal Bridge PKI certificate, and a TAXII client — it is neither keyless nor hostable).

---

## Requirements

- Keyless and free. No account, no API key, no registration on any source.
- No upstream search API exists for any source. Every filter, sort, and full-text query is executed locally against data this server holds.
- Boot must not depend on the ICS advisory corpus. KEV, SSVC, and alert tools serve from the first request; the CSAF mirror becomes available when it finishes seeding.
- Read-only end to end. Every tool is `readOnlyHint: true`; no tool mutates anything, locally or upstream.
- Self-imposed polling discipline. No source publishes a rate limit or a `Retry-After`, and `robots.txt` sets no crawl-delay. Poll on a timer with conditional GET where the origin honors it.
- Runs on Bun and on Node ≥ 24, over stdio and Streamable HTTP, in Docker, and as an `.mcpb` bundle. Not Cloudflare Workers — the SQLite mirror has no Workers backend.
- No DHS seal, CISA logo, or implied endorsement on any surface (README, marketplace entries, icons, tool output).

---

## User Goals

1. Is this CVE — or this list of 200 CVEs from a scan — in KEV? Added when, due when, ransomware-linked, forensic-triage tier?
2. What is overdue right now, or coming due in the next N days, for a given vendor or product?
3. What has been added to KEV since date D?
4. How should I prioritize this CVE under BOD 26-04 given my own asset exposure?
5. Which ICS advisories affect vendor V or product P, at CVSS ≥ 7, in the Water or Energy sector?
6. What does one advisory actually say — affected version ranges, CVEs, CVSS vectors, remediations, sectors?
7. What has CISA published this week?

Every tool traces to at least one of these: 1 → `cisa_check_cve_status`; 2, 3 → `cisa_search_kev`; 4 → `cisa_get_ssvc`; 5 → `cisa_search_ics_advisories`; 6 → `cisa_get_advisory`; 7 → `cisa_get_alerts`. `cisa_list_reference` serves all of them by decoding the vocabulary the others take as input.

---

## Upstream sources — verified shapes

### KEV JSON feed

`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

Measured on catalog `2026.09.18` (1,716 entries) unless a row names another version. Every count here drifts with each release; none of them belongs in a tool or field description.

| Property | Observed |
|:---|:---|
| Size | 1,735,385 bytes raw; 191,922 bytes with `Accept-Encoding: gzip` (`content-encoding: gzip`, `vary: Accept-Encoding`) |
| Envelope | `{ title, catalogVersion, dateReleased, count, vulnerabilities[] }` — `catalogVersion "2026.09.18"`, `count 1716` |
| Record fields | `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `forensicTriage`, `notes`, `cwes` — all 12 present on 100% of 1,716 records |
| Published schema | `…/known_exploited_vulnerabilities_schema.json`, 3,623 bytes, draft-07. Marks only 8 fields `required`; the other 4 are schema-optional but universal in practice. **It now documents `forensicTriage`.** No `additionalProperties: false` |
| `knownRansomwareCampaignUse` | `Known` 360 / `Unknown` 1,356 |
| `forensicTriage` | `Yes` 58 / `No` 1,658 |
| `cwes` | Empty array on 175 records; up to 4 entries; pattern `^CWE-([0-9])+$` |
| `notes` | Never empty. `;`-delimited. 100% carry an `https://nvd.nist.gov/vuln/detail/<CVE>` URL. Median 2 URLs, max 11. 116 records open with prose. Labeled segments observed: `BOD 26-04:` (99), `Forensics Triage Requirements:` (99), `CISA Mitigation Instructions:` (13), `Additional References:` (3). On catalog `2026.09.24` (1,723 entries), URLs also appear outside the lone-URL and `Label: URL` shapes — 52 entries join URLs with commas, and 160 entries gain or correct a reference under the full parse: comma runs (`url, url`, `url,url`, a trailing comma), URLs inside prose (`please see: <url>`, `(<url>)`, `<url> and <url>`, prose continuing after the URL), a `;` inside one URL (CVE-2023-4911's gitweb link), and trailing `",`, `"`, `.`, or an unbalanced `)`. The 15 ED 20-xx / 21-xx entries hold their NVD URL inside a prose segment |
| Directive citation | `BOD 26-04` in `requiredAction`/`notes` on 99 records, `BOD 22-01` on 340, **neither on 1,277**, both on 0 |
| `dueDate` − `dateAdded` | Under 26-04: 3 days ×76, 14 days ×23. Pre-26-04: 21 ×1,025, 14 ×254, 181 ×238, plus a tail |
| Coverage | 472 distinct `dateAdded` values, oldest 2021-11-03; 283 distinct `vendorProject`, 694 distinct `product` |
| Caching | `etag`, `last-modified`, `cache-control: max-age=~450–500` |
| **Conditional GET** | **`If-Modified-Since` → `304`, zero bytes. `If-None-Match` with the exact live ETag → `200` plus the full body.** The ETag is served but not honored |
| Wrong path | `404` with `content-type: text/html`, 46,886 bytes |

### Vulnrichment (cisagov/vulnrichment)

`https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{YYYY}/{block}/{CVE-ID}.json`

| Property | Observed |
|:---|:---|
| Default branch | **`develop`. `main` returns 404** |
| Directory layout | `<year>/<block>/` where `<block>` is the CVE numeric part with its last three characters replaced by `xxx` — `CVE-2025-39964` → `2025/39xxx/`, `CVE-2026-8452` → `2026/8xxx/` |
| License | CC0-1.0 |
| Repo size | ~343 MB — too large to mirror |
| Record | Full CVE JSON 5.2 (`dataType`, `dataVersion`, `cveMetadata`, `containers`). 3–15 KB typical |
| CISA data location | `containers.adp[]` entry where `providerMetadata.shortName === "CISA-ADP"`. Other ADP containers coexist (a vendor SADP was present on one sample) |
| SSVC | `metrics[].other.type === "ssvc"` → `content.options[]`, an array of single-key objects: `{"Exploitation": …}`, `{"Automatable": …}`, `{"Technical Impact": …}`. **The third key contains a space.** Plus `content.version` (`2.0.3`), `content.timestamp`, `content.role` |
| KEV echo | `metrics[].other.type === "kev"` → `content.dateAdded`, `content.reference` |
| CVSS | `metrics[].cvssV3_1` / `cvssV4_0` from the CISA-ADP container, when present |
| CWE | `problemTypes[].descriptions[]` with `cweId` and `description` |
| Miss | `404` with body `404: Not Found`, 14 bytes, `text/plain` |
| Caching | `etag` honored — `If-None-Match` → `304`. `cache-control: max-age=300` |
| Coverage gaps | Not every KEV CVE has a record (`CVE-2026-87886` is in KEV and 404s here). Published SSVC can lag KEV: `CVE-2026-42018` carries `Exploitation: none` with a timestamp of 2026-08-13 while KEV added it 2026-09-11 |

### CSAF ICS advisories (cisagov/CSAF)

Branch `develop`. **No license file, and none declared in repo metadata.**

Measured at index checkpoint 2026-09-17 (3,926 documents) unless a row names another. Every count here drifts with each refresh; none of them belongs in a tool or field description (Decision 34).

| Property | Observed |
|:---|:---|
| Distributions | `csaf_files/OT/white/` (ICS: `icsa-`, `icsma-`), `csaf_files/IT/white/` (`va-`, 89 docs), `csaf_files/VA/white/` (`va-`, 3 docs) |
| OT corpus | 3,926 documents — 3,738 `icsa-` + 188 `icsma-` — spanning 2010–2026, 94.6 MB of raw JSON |
| Whole-repo archive | `https://codeload.github.com/cisagov/CSAF/tar.gz/refs/heads/develop` → 11,394,643 bytes, fetched in ~1.5 s |
| Manifests | `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/index.txt` (98,460 B, 3,926 lines, `YYYY/<lowercase-id>.json`) and `…/csaf_files/OT/white/changes.csv` (228,018 B, 3,926 rows, no header, newest-first) — both live under the OT distribution directory, not the repo root |
| Document filenames | `icsa-<id>.json` / `icsma-<id>.json` — always start with the series prefix, never a digit. Each ships two sidecars in the same directory, `<name>.json.asc` (signature) and `<name>.json.sha512` (hash); a suffix match on `.json` excludes both automatically, since neither ends in `.json` |
| `changes.csv` quoting | **Inconsistent across distributions:** OT and VA quote both fields and use microsecond timestamps (`"2026/icsa-26-260-07.json","2026-09-17T06:00:00.000000Z"`); IT is unquoted with second precision |
| Checkpoint fidelity | `changes.csv` timestamp equals `document.tracking.current_release_date` byte for byte, on both fresh and legacy-converted documents |
| Caching | `raw.githubusercontent.com` honors `If-None-Match` → `304`; `cache-control: max-age=300` |
| Advisory IDs | `tracking.id` is uppercase (`ICSA-10-316-01A`); the filename is lowercase. Suffix forms: none (3,805), a letter `A`–`F` (120: 88 A, 23 B, 6 C, one each of D–F), and **one numeric form, `ICSA-16-231-01-0`** |
| Document sizes | min 4,373 / median 13,717 / p90 37,135 / p99 204,315 / **max 1,379,416** (`icsa-26-209-04.json`). 783 exceed 24 KB; 102 exceed 100 KB |
| `document.publisher.category` | `coordinator` 2,863 (CISA-authored) / **`other` 1,063 (republished vendor advisories)** |
| `document.aggregate_severity` | Present on only 52 of 3,926 |
| CVSS | `cvss_v3` 13,381 occurrences (version `3.1` 9,083, `3.0` 4,298), `cvss_v2` 697. **No structured `cvss_v4` anywhere** — CVSS v4 appears only as prose in a `details` note. `cvss_v3` always carries `baseSeverity`; `cvss_v2` never does. 431 vulnerability objects carry no `scores[]`; 392 documents are v2-only; 2 have no CVSS at all |
| `vulnerabilities[].cwe` | Always a single object `{id, name}` — never an array (14,461 occurrences) |
| Remediation categories | `mitigation` 31,289 / `vendor_fix` 18,403 / `none_available` 1,084 / `workaround` 674 / `no_fix_planned` 531 |
| `product_status` keys | `known_affected` 14,031 / `known_not_affected` 699 / `fixed` 559 / `recommended` 14 |
| Vulnerabilities per document | mean 3.7, **max 544**. Every document carries at least one CVE; 12,321 distinct CVEs across the corpus |
| `product_tree` | Nested `branches` with categories `vendor` 3,965 / `product_name` 26,036 / `product_version_range` 23,153 / `product_version` 3,709 / `product_family` 83 / `specification` 4 / `service_pack` 2 / `patch_level` 1. Depth ≤ 4. Products per document: median 2, p90 11, max 585. 15,929 distinct product names, 895 distinct vendor names — unnormalized (`GE` and `General Electric (GE)` both appear) |
| Sector | `document.notes[]` entry with `title === "Critical infrastructure sectors"`. Present on 3,197 of 3,926 (81%). **Zero coverage before 2017**, partial 2017–2022, complete from 2023. Free-form prose, not an enum |
| Note title drift | Titles vary in case and spacing across generator versions — `CVE Description` / `CVE description`, `CVSS v4.0 Score` / `CVSS v4.0  Score` |
| Canonical web URL | From the `self` reference: `/news-events/ics-advisories/{id}` for ICSA, `/news-events/ics-medical-advisories/{id}` for ICSMA |

### RSS feeds

`https://www.cisa.gov/cybersecurity-advisories/{all,alerts,ics-advisories}.xml`

| Property | Observed |
|:---|:---|
| Item count | Exactly 30 per feed, always |
| Item fields | `title`, `link`, `description`, `pubDate`, `dc:creator`, `guid` |
| `guid` | A node path (`/node/25513`), not a URL and not a permalink |
| `title` | Carries trailing whitespace |
| `description` | HTML. Up to 14,161 bytes per item on `ics-advisories.xml`, which is why that feed is 531,251 bytes |
| `pubDate` | RFC 822 with a **two-digit year** (`Fri, 18 Sep 26 12:00:00 +0000`). `new Date()` resolves it correctly to 2026 |
| Channel | No `lastBuildDate` |
| **Caching** | **No `etag`, no `last-modified`.** `cache-control: private, no-cache, must-revalidate` — conditional GET is impossible |
| Window span | The 30-item window covers very different periods per feed: `all.xml` ~8 days, `ics-advisories.xml` ~2.5 weeks, `alerts.xml` ~8 weeks |
| Sizes | `all.xml` 427,927 B / `alerts.xml` 100,227 B / `ics-advisories.xml` 531,251 B |

### BOD 26-04 Table 1 — Remediation Timelines

Extracted from the directive's published table image at `/sites/default/files/2026-06/BOD_26-04_Table_1_Remediation_Timelines_0.png`. Days are calendar days. "& forensic triage" means remediate or mitigate within three days *and* carry out a forensic triage of the asset.

| # | Publicly Exposed? | In the KEV? | Automatable by Adversary? | Technical Impact | Agency timeline |
|--:|:---|:---|:---|:---|:---|
| 1 | Yes | Yes | Yes | Total control | 3 days & forensic triage |
| 2 | Yes | Yes | Yes | Partial control | 3 days |
| 3 | Yes | Yes | No | Total control | 3 days & forensic triage |
| 4 | Yes | Yes | No | Partial control | 14 days |
| 5 | Yes | No | Yes | Total control | 3 days |
| 6 | Yes | No | Yes | Partial control | 14 days |
| 7 | Yes | No | No | Total control | 14 days |
| 8 | Yes | No | No | Partial control | 60 days |
| 9 | No | Yes | Yes | Total control | 3 days & forensic triage |
| 10 | No | Yes | Yes | Partial control | 14 days |
| 11 | No | Yes | No | Total control | 14 days |
| 12 | No | Yes | No | Partial control | 14 days |
| 13 | No | No | Yes | Total control | 60 days |
| 14 | No | No | Yes | Partial control | 60 days |
| 15 | No | No | No | Total control | Fix on system upgrade |
| 16 | No | No | No | Partial control | Fix on system upgrade |

Supporting definitions from the directive text, carried into `cisa_list_reference` topic `directives`:

- **Publicly exposed** — any agency-owned or agency-managed IT resource accessible to unauthenticated or untrusted entities via public networks, regardless of physical or logical location.
- **Partial control** — the exploit gives limited control over, or information exposure about, the behavior of the vulnerable software; or a low stochastic opportunity for total control. A denial-of-service attack is a form of limited control.
- **Total control** — the exploit gives the adversary total control over the software's behavior, including reliably revealing log-in credentials.
- **Clock start** — the earlier of CISA adding the CVE to KEV, or the agency enumerating the vulnerability on an asset and updating the CDM dashboard.
- **Timelines are dynamic** — removing a system from the internet flips Publicly Exposed to No and shifts the timeline back; a KEV addition shortens it.
- **Fix on system upgrade** — remediate at the vulnerable asset's next scheduled major upgrade or rebuild.

BOD 26-04 supersedes and revokes BOD 22-01 (2021-11-03) and BOD 19-02 (2019-04-29).

**Table 1 does not reproduce the KEV-assigned `dueDate`.** Across a 24-CVE sample of 26-04-era KEV entries reconciled against their published SSVC, 14 agreed with Table 1 under a publicly-exposed assumption, 9 disagreed, and 1 had no Vulnrichment record. CISA's own assignment reflects values at the time of addition and judgment this server cannot observe. The design treats the computed timeline and the assigned `dueDate` as two separate facts.

---

## Tools — detail

### `cisa_list_reference`

Implement first. No service dependency beyond in-process state, no network call, and it is the routing target for every recovery string, zero-hit notice, and resolver miss on this surface.

**Description**

> Decode the vocabulary the other CISA tools take as input. Topics cover the BOD 26-04 remediation timeline table and what each tier means, the KEV record fields and their value domains, the SSVC decision points CISA publishes, the critical-infrastructure sector names as the advisory corpus spells them, advisory ID formats, CVSS severity bands, and the freshness of the data this server currently holds. Call this before constructing filters for cisa_search_kev or cisa_search_ics_advisories, and whenever another tool's recovery hint points here.

| Param | Type | Notes |
|:---|:---|:---|
| `topic` | `z.enum(['directives','kev_fields','ssvc_values','sectors','advisory_id_formats','severity_bands','sources'])` | Required. Selects which reference block is returned. |

**Output**

`topic`, `title`, `summary`, `entries[]` (`{ key, label, description, values? }`), plus a topic-specific arm rendered on presence:

- `directives` → `timelineTable[]` (the 16 Table 1 rows, each `{ row, publiclyExposed, inKev, automatable, technicalImpact, timelineLabel, remediationTimelineDays, forensicTriageRequired }`), `definitions[]`, `supersedes[]`.
- `sources` → `kev` (`catalogVersion`, `dateReleased`, `count`, `lastCheckedAt`, `lastModified`, `refreshCron`), `csafMirror` (`ready`, `documentCount`, `checkpoint`, `syncStatus`, `lastCompletedAt`, and `unavailableReason` — `not_writable`, `read_only`, `missing_directory`, `not_a_directory`, or `not_a_database` — only when the store cannot be opened; never the path), `vulnrichment` (`mode: 'on_demand'`, `cacheTtlSeconds`), `feeds` (`windowItems: 30`, per-feed `oldest`/`newest` when cached).

`sources` reads in-process state only — the KEV snapshot, the mirror's `status()`, and cached feed windows. It makes no network call, which is what keeps it callable while another tool is failing. That is why `openWorldHint` is `false` for the whole tool.

**Errors** — none declared. Every topic is answerable from local state; a cold `sources` reports `ready: false` and `catalogVersion: null` rather than failing.

---

### `cisa_check_cve_status`

**Description**

> Check CVE IDs against the CISA Known Exploited Vulnerabilities catalog — up to 200 per call, served from a cached catalog snapshot at no upstream cost. Returns, per CVE, whether it is in KEV and if so the date added, the federal remediation due date, days remaining or days overdue, which binding operational directive the entry cites, the required action text, whether it is linked to ransomware campaigns, whether it falls in the three-day forensic-triage tier, CISA's own vendor and product labels, associated CWEs, and the reference URLs parsed from the entry's notes. A CVE that is not in KEV is a normal result, not an error. For a large batch, detail "summary" keeps only the triage fields — the deadline and overdue status, directive, ransomware and forensic-triage flags, and vendor and product labels — and drops the descriptive text, CWEs, and references, so a full batch stays compact. The CWE IDs returned chain directly into the cwe filter of cisa_search_kev and cisa_search_ics_advisories, and the parsed NVD reference gives the canonical record for scoring detail. For the reverse direction — which ICS advisories cover a CVE — pass it as cve to cisa_search_ics_advisories, or set inKev there to list the advisories covering any KEV CVE.

| Param | Type | Maps to | Notes |
|:---|:---|:---|:---|
| `cveIds` | `z.array(CveIdInputSchema).min(1).max(200)` — `z.string().trim().toUpperCase().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/)` | local index lookup | Pattern is the one the published KEV schema declares. The schema trims surrounding whitespace and uppercases before the pattern check — both one-to-one and meaning-preserving, and neither emits a JSON Schema keyword. Nothing else is repaired. |
| `detail` | `z.enum(['full','summary']).default('full')` | output projection | `full` is the complete record and the default, byte-identical to the output before the parameter existed. `summary` keeps eleven fields per in-KEV record (Decision 24). Not-in-KEV results, the counts, and the `catalog`/`asOf` enrichment are the same under both. |

**Output**

```
results[]:
  cveId, inKev
  # present when inKev
  dateAdded, dueDate, daysUntilDue, overdue
  directive            'BOD 26-04' | 'BOD 22-01' | null
  requiredAction, vulnerabilityName, shortDescription        # full only
  vendorProject, product
  knownRansomwareCampaignUse   'Known' | 'Unknown'
  forensicTriage               'Yes' | 'No'
  cwes[]                                                     # full only
  references[]: { kind: 'nvd'|'cisa'|'bod_guidance'|'forensic_triage'|'vendor'|'other',
                  label?, url }                              # full only
  notesCommentary?     prose segments of notes, verbatim     # full only
  kevUrl                                                     # full only
foundCount, notFoundCount
```

`directive` is three-state on purpose: most entries (1,277 of 1,716 at catalog `2026.09.18`) cite no directive at all in their `requiredAction` or `notes`, and `null` is the honest value for those. Never infer 22-01 from an entry's age.

`notes` parsing (Decision 25): split on `;`, except a `;` that follows a URL with no space and does not open another URL — that one belongs to the URL (`…glibc.git;a=commitdiff;h=…`). A segment matching `^<Label>:\s*<url>` with a single URL yields `{ label, url }` with `kind` from the label (`BOD 26-04` → `bod_guidance`, `Forensics Triage Requirements` → `forensic_triage`, `CISA Mitigation Instructions` → `cisa`). From every other segment each URL becomes an unlabeled reference classified by host (`nvd.nist.gov/vuln/detail/` → `nvd`, `*.cisa.gov` → `cisa`, else `vendor`): comma runs split at a comma that opens another URL, and trailing `,` `.` `"` and an unbalanced `)` are trimmed. References keep notes order. A segment holding anything besides URLs, commas, and whitespace is also kept whole, URLs included, in `notesCommentary`.

**Enrichment**

| Key | Kind | When |
|:---|:---|:---|
| `catalog` | `echo` | Always — `{ catalogVersion, dateReleased, count, fetchedAt }` |
| `asOf` | `echo` | Always — the UTC date `daysUntilDue` and `overdue` were computed against |
| `summaryNote` | label `Detail` | Only under `detail: "summary"` — "summary — in-KEV results omit requiredAction, vulnerabilityName, shortDescription, cwes, references, notesCommentary, and kevUrl. Call again with detail "full" to restore them." |
| `notice` | `notice` | When `foundCount === 0` — "None of the N CVE IDs supplied are in the KEV catalog. KEV lists only vulnerabilities CISA has confirmed are exploited in the wild; absence is not a statement about severity. Call cisa_get_ssvc for the SSVC decision points CISA publishes for CVEs regardless of KEV status." |

**Errors**

| reason | code | when | recovery |
|:---|:---|:---|:---|
| `catalog_unavailable` | `ServiceUnavailable` (`retryable: true`) | No KEV snapshot is held and the fetch from cisa.gov failed | `The KEV catalog snapshot is not loaded yet; retry in a few seconds, or call cisa_list_reference with topic sources to see the current catalog state.` |

---

### `cisa_search_kev`

**Description**

> Search the CISA Known Exploited Vulnerabilities catalog across every entry in the cached snapshot. Filter by vendor or product using CISA's own labels, by name substring, by CWE, by the date an entry was added, by due date, by overdue status, by ransomware linkage, by the three-day forensic-triage tier, or by which binding operational directive the entry cites. Results are paged and sortable by due date or date added. Vendor and product values are CISA's free-text labels, not CPE names — call cisa_list_reference for the field vocabulary before guessing one. The catalog records additions but carries no per-record modified timestamp, so dateAddedFrom answers "what is new since D" while a revised due date on an existing entry is not detectable from the feed.

| Param | Type | Notes |
|:---|:---|:---|
| `vendorProject` | `z.string().min(2).optional()` | Case-insensitive substring match on CISA's own vendor label. |
| `product` | `z.string().min(2).optional()` | Case-insensitive substring match on CISA's own product label. |
| `nameContains` | `z.string().min(2).optional()` | Strict token match over `vulnerabilityName` + `shortDescription`: normalize both sides (lowercase; the fifteen Latin-1/Latin Extended-A letters NFKD cannot decompose spelled the CLDR Latin-ASCII way, `ß`→`ss`, `æ`→`ae`, `ø`→`o`, `þ`→`th`, `ł`→`l` and the rest (Decision 35); NFKD with combining marks stripped; every character outside `a-z0-9` becomes a separator), require every query token to appear. A value that leaves no token — punctuation, whitespace, only letters that fold to nothing in `a-z` — throws `empty_search_text` from the service after the length check (Decision 26). When some tokens survive, `queryTokens` also reports each word that lost a letter or digit to the fold (a word in another script, a Latin letter outside the table such as `ƒ`, digits outside 0-9), and the search runs on the survivors with a notice naming what was dropped and what was searched. No fuzzy fallback — an LLM caller does not need typo tolerance, and a wrong record is worse than a miss. |
| `cwe` | `CweIdInputSchema.optional()` — `z.string().trim().toUpperCase().regex(/^CWE-[0-9]+$/)` | Exact match against any member of `cwes[]`. Case and surrounding whitespace normalize at the schema, so the service compares canonical values. |
| `cveIdPrefix` | `z.string().trim().toUpperCase().regex(/^CVE-[0-9]{4}$/).optional()` | Year scope, e.g. `CVE-2026`; `cve-2026` is the same filter. |
| `dateAddedFrom` / `dateAddedTo` | `z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional()` | Inclusive. |
| `dueBefore` / `dueAfter` | `z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional()` | Inclusive. |
| `overdue` | `z.boolean().optional()` | `dueDate` strictly before the echoed `asOf` date. |
| `ransomware` | `z.boolean().optional()` | `true` selects `knownRansomwareCampaignUse === 'Known'`. |
| `forensicTriage` | `z.boolean().optional()` | `true` selects `forensicTriage === 'Yes'`, the BOD 26-04 three-day forensic-triage tier. |
| `directive` | `z.enum(['BOD 26-04','BOD 22-01','none']).optional()` | `none` selects entries citing neither. |
| `sortBy` | `z.enum(['dueDate','dateAdded']).default('dateAdded')` | |
| `order` | `z.enum(['asc','desc']).default('desc')` | |
| `limit` | `z.number().int().min(1).max(100).default(25)` | |
| `cursor` | `z.string().optional()` | Opaque, from `extractCursor`/`paginateArray`. |

All filters AND together. Every one is applied against the complete snapshot, never a page.

**Output** — `results[]` (the same record shape as `cisa_check_cve_status`), `cursor?`, `hasMore`.

**Enrichment**

| Key | Kind | When |
|:---|:---|:---|
| `totalCount` | `total` | Always — matches before paging. `ctx.enrich.total()` writes `totalCount`, not `total` |
| `truncated`, `shown`, `cap` | `truncated` | When the `limit` cap was hit. `ctx.enrich.truncated()` writes these three fields, not a single nested `{ shown, cap }` object |
| `catalog` | `echo` | Always |
| `asOf` | `echo` | Always — a server-applied default that changes what `overdue` and `daysUntilDue` mean |
| `appliedFilters` | `echo` | Always — the filters as the server parsed them |
| `snapshotCaveat` | `notice` | When `dateAddedFrom` is set — "Additions are queryable by dateAdded. The KEV feed carries no per-record modified timestamp, so an entry whose dueDate or requiredAction changed after it was added is indistinguishable from an unchanged one. This result covers additions in the window, not revisions." |
| `notice` | `notice` | Composed once, because `notice` is last-wins across enrich calls (`truncated()` included): the dropped-word notice when `nameContains` lost a word to the fold ("nameContains dropped the characters of "漏洞" outside the letters a-z and the digits 0-9 — … Searched for: siemens."), then the zero-hit fragments (below). A capped page prefixes the framework's cap sentence and passes the whole string as `truncated()`'s `guidance`. |

Zero-hit notice fragments (Decision 26). On a zero-hit result only, `KevCatalogService.filterCounts` makes one extra pass over the snapshot recording, per applied filter, the entries it matches alone and the entries that fail it and nothing else — what dropping it restores. Fragments key on those counts, the loaded snapshot, and the echoed `asOf`; the counts they print come from the snapshot:

| Condition | Fragment |
|:---|:---|
| `vendorProject` or `product` matches nothing alone | "vendorProject=X matches no entry on its own. Vendor and product are CISA's own free-text labels, not CPE names — call cisa_list_reference with topic kev_fields for the value domain, or drop the filter and match on nameContains instead." — both unmatched: "vendorProject=X and product=Y each match no entry on their own. … or drop the filters …" |
| `cwe` matches nothing alone | "No KEV entry carries CWE-X. N of M entries carry an empty cwes array, so a CWE filter excludes them regardless of relevance." — N and M from the snapshot |
| Any other filter matches nothing alone | "cveIdPrefix=CVE-2099 matches no entry on its own — relax or drop it." |
| Exactly one filter matches nothing alone, beside other filters | "Dropping cveIdPrefix restores N entries." — or, when the other filters also match nothing together, "Dropping cveIdPrefix alone restores nothing: the other filters match no entry together either." Every entry fails that filter, so its drop-one count is exactly what the rest match together |
| `overdue: true` with `dueAfter` on or after `asOf` | "overdue and dueAfter are contradictory as given: overdue selects due dates before ASOF, and dueAfter=D excludes all of them — relax one." |
| `directive` with a `dateAdded` window outside the dateAdded range of the entries citing it | "Entries citing BOD 26-04 were added from FIRST through LAST; the dateAdded window falls outside that range." — FIRST and LAST from the snapshot |
| Every filter matches alone; at least one removal restores results | "Every filter matches entries on its own; dropping overdue restores N entries, dropping vendorProject restores M entries." |
| Every filter matches alone; no single removal restores a result | "Every filter matches entries on its own, but no single filter explains the miss — only relaxing two or more of them together restores a result." |
| No filter applied (an empty snapshot) | "The loaded KEV catalog snapshot holds no entries. Call cisa_list_reference with topic sources to check its state." |

**Errors**

| reason | code | when | recovery |
|:---|:---|:---|:---|
| `catalog_unavailable` | `ServiceUnavailable` (`retryable: true`) | No snapshot held and the fetch failed | `The KEV catalog snapshot is not loaded yet; retry in a few seconds, or call cisa_list_reference with topic sources to see the current catalog state.` |
| `invalid_date_range` | `ValidationError` | A `From` bound is later than its `To` bound | `Swap the range bounds so the From date is not later than the To date, then call this tool again.` |
| `empty_search_text` | `ValidationError` (thrown by `queryTokens`) | `nameContains` holds no letter a-z or digit 0-9 once case, accents, and letters such as `ß` and `ø` are folded and punctuation is removed | `Put at least one word or number in nameContains that uses the letters a-z, accented or not, or the digits 0-9, such as a product or vulnerability term, or omit nameContains to search by the other filters alone.` |

---

### `cisa_get_ssvc`

**Description**

> Fetch the SSVC decision points CISA publishes per CVE as a CVE Authorized Data Publisher — Exploitation, Automatable, and Technical Impact — along with the CVSS score and CWE CISA contributes where present, and compute the BOD 26-04 remediation timeline those values imply for the asset exposure you supply. The computed timeline applies CISA's published decision table to CISA's published decision points and your stated exposure; it is not a compliance determination and it is not CISA's own due-date assignment, which is reported separately when the CVE is in KEV and can differ. Not every CVE is enriched — a miss returns found false with guidance rather than an error. Call cisa_list_reference with topic ssvc_values for the decision-point vocabulary.

| Param | Type | Notes |
|:---|:---|:---|
| `cveIds` | `z.array(CveIdInputSchema).min(1).max(50)` | Case and whitespace normalize as in `cisa_check_cve_status`. Cap 50, not 200: each CVE is a separate upstream file fetch. Fetched with a concurrency limit of 6 and `Promise.allSettled`. |
| `assetExposure` | `z.enum(['publicly_exposed','not_publicly_exposed','unknown']).default('unknown')` | The one decision point only the caller can answer. `unknown` returns both arms so the agent can see the spread without guessing. |

`In the KEV` is read from this server's local KEV snapshot, never from the caller. `Automatable` and `Technical Impact` come from Vulnrichment. Those three plus `assetExposure` are the complete input set for the Table 1 lookup.

**Output**

```
results[]:
  cveId, found
  # present when found
  exploitation          'none' | 'poc' | 'active' | <other, passed through>
  automatable           'yes' | 'no'
  technicalImpact       'partial' | 'total'
  ssvcVersion, ssvcTimestamp, ssvcRole
  cvss?: { version, baseScore, baseSeverity, vectorString }
  cwes[]: { cweId, description }
  inKev
  bod2604:
    timelines[]: { assetExposure, tableRow, timelineLabel,
                   remediationTimelineDays,      # 3 | 14 | 60 | null
                   forensicTriageRequired }
    basis        # 'CISA BOD 26-04 Appendix A, Table 1'
    caveat       # fixed disclaimer string, see below
  kevAssigned?: { dateAdded, dueDate, daysFromAdd, forensicTriage, directive }
  assignmentAgrees?     # bool, only when inKev and assetExposure !== 'unknown'
  sourceUrl
  # present when not found
  guidance
foundCount, notFoundCount
```

`remediationTimelineDays` is `null` for rows 15 and 16, whose timeline is "Fix on system upgrade" — a condition, not a day count. `timelineLabel` carries the directive's own wording verbatim.

`caveat`, fixed text: *"This timeline is CISA's published decision table applied to CISA's published decision points and the asset exposure supplied in the request. It is not a compliance determination, and it is not CISA's assigned KEV due date."*

`assignmentAgrees` is reported, never reconciled. When it is `false`, the two facts stand side by side: 9 of 24 sampled 26-04 KEV entries disagreed with the table under a publicly-exposed assumption.

Miss `guidance`, per outcome:

| Outcome | Guidance |
|:---|:---|
| 404 from Vulnrichment | "CISA has published no enrichment record for this CVE. Call cisa_check_cve_status to see whether it is in KEV, which carries its own remediation deadline independent of SSVC." |
| Record exists, no CISA-ADP container | "The CVE record exists but carries no CISA-authored enrichment container, so no SSVC decision points are available. Call cisa_check_cve_status for KEV status." |
| CISA-ADP container with no SSVC metric | "CISA has enriched this CVE with CVSS or CWE data but has not published SSVC decision points for it. The CVSS and CWE values returned are what is available." |

**Enrichment**

| Key | Kind | When |
|:---|:---|:---|
| `echo` | `echo` | Always — `{ assetExposure, requested }` |
| `notice` | `notice` | When `foundCount === 0`, or when any returned `ssvcTimestamp` predates that CVE's KEV `dateAdded` — "SSVC decision points for N of the CVEs were published before CISA added them to KEV and may not reflect current exploitation status." |

**Errors**

| reason | code | when | recovery |
|:---|:---|:---|:---|
| `enrichment_source_unavailable` | `ServiceUnavailable` (`retryable: true`) | Every per-CVE fetch failed with a transport or 5xx error | `The CISA enrichment source is unreachable; retry in a few minutes, or call cisa_check_cve_status which serves from a cached catalog and needs no network.` |

A partial failure is not an error: CVEs that fetched successfully return normally and the failed ones report `found: false` with guidance naming the transport failure.

---

### `cisa_search_ics_advisories`

**Description**

> Search the CISA industrial control system advisory corpus — every CSAF 2.0 advisory covering PLC, HMI, SCADA, building-automation, and medical-device products from 2010 onward. Filter by vendor, product, CVE, CWE, CVSS range, severity band, critical-infrastructure sector, advisory series, publication date, revision date, or whether an advisory covers a CVE in the CISA Known Exploited Vulnerabilities catalog, and run full-text search over advisory titles and product names. Sector filtering reaches only advisories that carry a sector note, which begins in 2017; the response reports how many documents a sector filter can never match. Returns advisory IDs for cisa_get_advisory, the CVEs each advisory covers and which of them are in KEV, and the source URL and attribution every advisory response carries.

| Param | Type | Notes |
|:---|:---|:---|
| `q` | `z.string().min(2).optional()` | Full text over `title`, `vendorsText`, `productsText`. Translated to an FTS5 `MATCH` expression: tokens are quoted and AND-joined, so reserved FTS5 syntax in caller input cannot alter the query. A token with no letter or digit is dropped, and a `q` left with no token throws `empty_search_text` from the service (Decision 20). |
| `vendor` | `z.string().min(2).optional()` | Case-insensitive substring over the `vendorsText` column: `LOWER(vendorsText) GLOB ?` with the pattern from `toSubstringGlob`, which lowers A-Z to meet SQLite's ASCII-only `LOWER()` and turns every other cased letter into a class of both forms, so a label with a non-ASCII capital matches as served (Decision 36). `%`, `_`, and `\` are ordinary characters under GLOB and `*`, `?`, `[` are bracketed, so every character matches literally (Decision 21). Capped at 512 characters, `search_text_too_long`. Vendor names are unnormalized upstream — `GE` and `General Electric (GE)` are distinct labels — so this is substring, not exact. |
| `product` | `z.string().min(2).optional()` | Case-insensitive, literally-matched substring over `productsText`, built the same way and under the same cap. |
| `cve` | `CveIdInputSchema.optional()` | Exact membership in the advisory's CVE set, via an indexed junction table. Case and surrounding whitespace normalize at the schema. |
| `cwe` | `CweIdInputSchema.optional()` | Exact membership in `advisory_cwes`, the same schema as `cisa_search_kev`'s `cwe`; case and surrounding whitespace normalize at the schema, and ingest stores the uppercase form. On an index an older ingest built, a `cwe` result is disclosed as possibly incomplete (Decision 19). |
| `inKev` | `z.boolean().optional()` | `true` keeps advisories covering at least one CVE in the KEV snapshot, `false` those covering none — evaluated in SQL over full `advisory_cves` membership, so paging and `totalCount` stay correct (Decision 22). |
| `cvssMin` / `cvssMax` | `z.number().min(0).max(10).optional()` | Against the advisory's computed `maxCvss`. |
| `severity` | `z.enum(['NONE','LOW','MEDIUM','HIGH','CRITICAL']).optional()` | Band of `maxCvss`. |
| `sector` | `z.enum([…16 canonical sectors…, 'Multiple']).optional()` | Matches the normalized sector set. |
| `series` | `z.enum(['ICSA','ICSMA']).optional()` | ICSA, or ICSMA medical-device advisories, a small minority (188 of 3,937 at the 2026-09-24 checkpoint). The description states no count (Decision 34). |
| `publisher` | `z.enum(['coordinator','other']).optional()` | `coordinator` = CISA-authored, `other` = republished vendor advisory, over a quarter of the corpus (1,069 of 3,937 at the 2026-09-24 checkpoint). |
| `publishedFrom` / `publishedTo` | `z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional()` | Against `initial_release_date`. |
| `revisedFrom` / `revisedTo` | same | Against `current_release_date`. |
| `sortBy` | `z.enum(['relevance','published','revised','maxCvss']).default('revised')` | `relevance` requires `q` and uses FTS5 bm25. |
| `order` | `z.enum(['asc','desc']).default('desc')` | |
| `limit` | `z.number().int().min(1).max(50).default(20)` | |
| `cursor` | `z.string().optional()` | Opaque offset cursor over the mirror query. |

**Output**

```
results[]:
  advisoryId, title, series
  vendors[]                  # up to 10, plus vendorCount
  vendorCount, productCount
  cves[]                     # up to 20, plus cveCount
  cveCount
  kevCves?[]                 # every KEV-listed CVE, from full membership; [] when
                             # none, absent when KEV could not be evaluated
  maxCvss?: { score, severity, version, severityDerived }
  sectors[]                  # normalized canonical names
  sectorsRaw?                # the note text verbatim, when present
  published, revised, revision, publisherCategory
  url                        # cisa.gov web version
  csafUrl                    # raw CSAF JSON
  attribution                # see Licensing
cursor?, hasMore
```

`maxCvss` is computed as the maximum `baseScore` across every `vulnerabilities[].scores[].cvss_v3|cvss_v2` entry — `document.aggregate_severity` exists on only 52 of 3,926 documents (2026-09-17 checkpoint) and is never relied on. For a `cvss_v2`-only advisory the upstream carries no `baseSeverity`, so the band is derived from the CVSS v2 thresholds and flagged `severityDerived: true`. An advisory with no CVSS at all has no `maxCvss` (3 at the 2026-09-24 checkpoint; `cvssCoverage` reports the live figure).

**KEV membership.** 117 KEV CVEs appear in 108 of the 3,926 advisories (catalog `2026.09.21`). `kevCves` comes from each result's complete `advisory_cves` rows — the same rows the 20-CVE preview is cut from, so it costs no extra query — which matters: 16 of the 108 carry a KEV CVE past their 20th CVE alphabetically (ICSA-25-226-07's four sit at positions 358–391 of 486). With `inKev` set the handler awaits the KEV snapshot and a load failure throws `catalog_unavailable`. Without it the handler reads only a snapshot already in memory: when none is held, results omit `kevCves` (never `[]`) and a notice says KEV membership was not evaluated — the search never fails, and never waits, on a KEV outage it did not ask about (Decision 22).

**Enrichment**

| Key | Kind | When |
|:---|:---|:---|
| `totalCount` | `total` | Always — `ctx.enrich.total()` writes `totalCount`, not `total` |
| `truncated`, `shown`, `cap` | `truncated` | Cap hit — `ctx.enrich.truncated()` writes these three fields separately |
| `appliedFilters` | `echo` | Always. With `inKev` set it also carries `kevCatalogVersion`, the KEV snapshot the filter ran against |
| `mirror` | `echo` | Always — `{ documentCount, checkpoint, lastRefreshedAt }` |
| `sectorCoverage` | `notice` | Whenever `sector` is set — "729 of 3,937 advisories carry no sector note and cannot match a sector filter. Coverage begins in 2017 and is complete from 2023; every advisory published before 2017 is excluded by this filter regardless of which sectors it affects." The figures come from `coverageCounts()`, thousands-grouped, and follow the index after every completed sync (Decision 34); these are the 2026-09-24 checkpoint's |
| `cvssCoverage` | `notice` | Whenever `cvssMin`, `cvssMax`, or `severity` is set — "392 advisories score only in CVSS v2, where the upstream publishes no severity label and the band is derived. 3 advisories carry no CVSS score and cannot match a score filter." — read the same way |
| `notice` | `notice` | Composed once from every source that applies, in this order, because `notice` is last-wins across enrich calls (`truncated()` included): the zero-hit fragments; the incomplete-`cwe` disclosure when `cwe` is set and `contentState().stale`; "KEV membership was not evaluated…" when no KEV snapshot is held and the page is non-empty. A capped page prefixes the framework's cap sentence and passes the whole string as `truncated()`'s `guidance`. |

Zero-hit notice fragments (Decision 33). On a zero-hit result only, `CsafMirrorService.filterCounts` runs one aggregate query over `ics_advisories` recording, per applied filter, the advisories it matches alone and those that fail it and nothing else — what dropping it restores. Each predicate comes from `filterClauses`, the builder `search()` uses: `q`'s FTS `MATCH`, the junction subqueries, the `GLOB` text filters, and `inKev` against the same KEV set. Every figure a fragment prints comes from those counts:

| Condition | Fragment |
|:---|:---|
| `vendor` matches nothing alone | "vendor=X matches no advisory on its own. Vendor names are the advisory's own labels and are not normalized — the same company appears under several spellings. Try a shorter substring, or search with q instead." |
| `sector` matches nothing alone | "sector=X matches no advisory on its own. Sector coverage begins in 2017, and an advisory with no sector note never matches a sector filter; sectorCoverage gives the count." |
| `series: 'ICSMA'` matches nothing alone | "ICSMA covers medical devices, and no advisory in the index is in that series. Drop the series filter to include ICSA." |
| `cve` matches nothing alone | "No ICS advisory covers that CVE; call cisa_check_cve_status to see whether it is in KEV instead." |
| `cwe` matches nothing alone, index current | "No ICS advisory lists that CWE on any of its vulnerabilities. CWE IDs match exactly — a parent class such as CWE-20 does not match its children. Call cisa_search_kev with the same cwe to check the KEV side." |
| `inKev: true` matches nothing alone | "No advisory in the index covers a CVE in the loaded KEV catalog snapshot; drop inKev to see advisories regardless of KEV status." |
| Any other filter matches nothing alone | "cvssMax=1 matches no advisory on its own — relax or drop it." — several: "q=X, product=Y each match no advisory on their own — relax or drop them." |
| Exactly one filter matches nothing alone, beside other filters | "Dropping cve restores 1,046 advisories." — or, when the other filters also match nothing together, "Dropping cve alone restores nothing: the other filters match no advisory together either." |
| Every filter matches alone; at least one removal restores results | "Every filter matches advisories on its own; dropping cwe restores 6 advisories, dropping publishedTo restores 282 advisories." |
| Every filter matches alone; no single removal restores a result | "Every filter matches advisories on its own, but no single filter explains the miss — only relaxing two or more of them together restores a result." |
| `cwe` matches nothing alone on a stale index | Withheld: `cwe` is never named, and neither count sentence is printed, because a partial `advisory_cwes` makes both unreliable. Other filters that match nothing are still named; the incomplete-`cwe` disclosure explains the rest. |
| Nothing else applies | "No advisory matches. Relax the narrowest filter, or call cisa_list_reference with topic sources to check the state of the index." |

Measured at the 2026-09-24 checkpoint (3,937 advisories), the count query adds to a zero-hit search, on better-sqlite3 3.53 under Node / `bun:sqlite` 3.54: `cve` alone (the fastest zero-hit, 0.06 ms of search) +0.6 / +0.6 ms; `{ cwe, publishedTo }` +1.8 / +4.7 ms; `{ vendor, cve }` +1.4 / +4.2 ms; all sixteen filters +17 / +23 ms. `vendor`/`product` text matching dominates; a non-zero search never runs it.

**Errors**

| reason | code | when | recovery |
|:---|:---|:---|:---|
| `mirror_not_ready` | `ServiceUnavailable` (`retryable: true`) | The advisory mirror has never completed a full sync | `The ICS advisory index is still building; call cisa_list_reference with topic sources to check its progress, then retry this search.` |
| `mirror_unavailable` | `ConfigurationError` | The index store cannot be opened: not writable, read-only, a missing directory, a path through a file, or a file that is not a SQLite database | `The ICS advisory index cannot be opened at its configured location; the server operator must set CISA_CSAF_MIRROR_PATH to a writable path and restart. Retrying will not help, but cisa_check_cve_status, cisa_search_kev, cisa_get_ssvc, and cisa_get_alerts still work.` |
| `invalid_cvss_range` | `ValidationError` | `cvssMin` exceeds `cvssMax` | `Set cvssMin to a value no greater than cvssMax, then call this tool again.` |
| `invalid_date_range` | `ValidationError` | A `From` bound is later than its `To` bound | `Swap the range bounds so the From date is not later than the To date, then call this tool again.` |
| `relevance_sort_without_query` | `ValidationError` | `sortBy` is `relevance` but `q` was not supplied — there is no bm25 rank to sort by | `Add a q value to sort by relevance, or choose a different sortBy such as revised, published, or maxCvss.` |
| `empty_search_text` | `ValidationError` (thrown by `toFtsMatch`) | `q` holds no word or number once quotes and punctuation are removed | `Put at least one word or number in q, such as a vendor, product, or title term, or omit q to search by filters alone.` |
| `catalog_unavailable` | `ServiceUnavailable` (`retryable: true`, thrown by the KEV service) | `inKev` is set, no KEV snapshot is held, and the fetch from cisa.gov failed | `The KEV catalog snapshot is not loaded yet; retry in a few seconds, drop inKev to search without it, or call cisa_list_reference with topic sources to see the catalog state.` |

---

### `cisa_get_advisory`

**Description**

> Read one CISA industrial control system advisory in full: affected products flattened from the CSAF product tree into vendor, product, and version ranges; per-CVE CVSS score, vector, and CWE; remediations with their category and vendor instructions; critical-infrastructure sectors; and the revision history. Large advisories return a section outline instead of the whole document, listing each section's size and the CVE IDs the vulnerabilities section holds — re-call with the sections you need, or with cves to read only those vulnerability entries. Republished vendor advisories carry the originating vendor's text; every response reports the source URL and attribution. Find advisory IDs with cisa_search_ics_advisories.

| Param | Type | Notes |
|:---|:---|:---|
| `advisoryId` | `AdvisoryIdInputSchema` — `z.string().overwrite(normalizeAdvisoryId).regex(/^ICS(A\|MA)-\d{2}-\d{3}-\d{2}(?:[A-Z]\|-\d+)?$/)` | **The suffix arm covers both real forms.** 120 advisories carry a letter suffix (`A`–`F` observed) and one carries a numeric suffix (`ICSA-16-231-01-0`). `normalizeAdvisoryId` trims, strips a trailing `.json`, and uppercases before the flag-free canonical pattern is checked, so every spelling the lowercase filename or a stray extension produces still resolves (Decision 11). |
| `sections` | `z.array(z.enum(['advisory','summary','products','vulnerabilities','revisionHistory','references','acknowledgments'])).optional()` | Omit for the whole document, or the outline when it overflows. |
| `cves` | `z.array(CveIdInputSchema).optional()` | Narrows `vulnerabilities` to the entries carrying these CVEs, in document order (Decision 23). Alone it selects `vulnerabilities`; with `sections`, the list must include it or the handler throws `cves_need_vulnerabilities_section`. An ID the advisory does not cover throws `unknown_cve` naming it. Case and whitespace normalize as in `cisa_check_cve_status`; duplicates collapse; an empty array behaves as omitted, like an empty `sections`. |

**Output** — one flat `z.object` per the outline-on-overflow contract, with presence-based arms:

```
found, kind?          'full' | 'outline'
advisory?     { advisoryId, title, series, status, csafVersion,
                published, revised, revision, publisherCategory,
                publisherName, url, csafUrl, attribution }
summary?      { riskEvaluation?, exploitability?, summaryText?,
                sectors[], sectorsRaw?, countriesDeployed?, headquarters? }
products?     { vendorCount, productCount,
                vendors[]: { name, products[]: { name, family?,
                             versions[]: { kind, value, productId } } },
                truncated?, shownProducts }   # shownProducts === productCount;
                                              # truncated only on a copy an older,
                                              # capped build stored
vulnerabilities? [ { cve, cweId?, cweName?, title?,
                     scores[]: { version, baseScore, baseSeverity,
                                 severityDerived, vectorString, productIds[] },
                     remediations[]: { category, details, url?, productIds[],
                                       restartRequired? },
                     productStatus: { known_affected[], fixed[],
                                      known_not_affected[], recommended[] },
                     notes[]: { category, title?, text } } ]
revisionHistory? [ { number, date, summary, legacyVersion? } ]
references?      [ { category, summary?, url } ]
acknowledgments? [ { organization?, names[], summary? } ]
sections?        # outline arm: [ { name, bytes, cves?[] } ] — cves on the
                 # vulnerabilities entry only. The element schema extends the
                 # framework's strip-mode OUTLINE_VARIANT element, which would
                 # otherwise drop cves from both surfaces
outlineNotice?   # outline arm. Named outlineNotice, not notice — a bare `notice`
                 # key would read as agent-facing enrichment rather than the
                 # outline arm's own payload
guidance?        # present when found is false
indexCheckpoint?, indexLastSyncedAt?   # present when found is false (Decision 32)
```

`format()` renders each arm on field presence with independent `if` blocks — never a branch on `kind` — so parity holds against the linter's all-fields-populated sample.

**Outline behavior.** `outlineOnOverflow(doc, { budget: 24_000 })` on the disclosure path; `selectSections(doc, input.sections, { alwaysKeep: ['advisory'] })` on the selection path. 783 of 3,926 advisories exceed 24 KB and 102 exceed 100 KB, with the largest at 1.38 MB (544 vulnerability entries, 585 products) — truncating those silently is not an option and returning them whole burns the caller's context. The re-call is stateless: the mirror lookup is deterministic, so the handler re-reads the row and projects it. The tool and the resource share one extractor, `extractAdvisorySections` in `src/mcp-server/schemas/advisory.ts`, so both outline arms size and list sections identically.

**`cves` narrowing.** `vulnerabilities` is one section, and 182 advisories carry one over the 24 KB budget, 29 over 100 KB — the largest (`ICSA-26-209-04`, 352 CVEs) is 905,159 bytes. The outline's vulnerabilities entry therefore lists the section's CVE IDs, and when that section alone overflows the budget, the outline notice points at `cves`. The listing is what the outline costs: measured on the built server, `ICSA-23-348-10` (544 CVEs) grows from 612 to 9,869 bytes of `structuredContent` and 617 to 9,369 bytes of `content[]`; `ICSA-26-209-04` from 606 to 6,738 and 611 to 6,430 — still well inside the budget the outline exists to respect. A re-call naming one of `ICSA-26-209-04`'s CVEs returns 3,628 bytes instead of 905,159.

The `products` arm carries every flattened version row. The outline treats `products` as one indivisible section, so a row cap would drop rows no re-call can reach — and the product names past it would fall out of `productsText` and the FTS index too. Serving every row changes no inline/outline decision: the ten advisories over 200 products stored 47–77 KB of document at 200 rows, already past the 24 KB budget, so only their `sections: ["products"]` re-call grows (the largest, `ICSA-22-167-14`, returns 585 rows in a ~92 KB products section). `shownProducts` equals `productCount`; `truncated` appears only on a copy stored by an older build that capped rows, until the ingest-content re-ingest (Decision 19) replaces it.

**Product-tree flattening.** Walk `product_tree.branches` recursively, carrying the branch-category path. `vendor` opens a vendor; `product_family` and `product_name` build the product label; `product_version` and `product_version_range` become version entries tagged with their `kind`; `specification`, `service_pack`, and `patch_level` (7 occurrences total) append to the version label. A leaf's `product.product_id` is the `CSAFPID-*` token the vulnerability entries reference, so it is kept — it is how a caller maps a CVE to the exact affected versions.

**Sector extraction.** Read `document.notes[]` for the entry whose title, lowercased with whitespace collapsed, is `critical infrastructure sectors`. Match the raw text against the 16 canonical sector names plus a small alias table, longest-name-first, consuming each match. This is the only correct approach: the note is free-form prose, two canonical names contain the word "and", and `Nuclear Reactors, Materials, and Waste` contains commas — so splitting on separators produces garbage tokens. The alias table covers generator drift, upstream typos, and the one-to-one short forms `Water`, `Transportation`, `Healthcare`, `Healthcare, Public Health`, and `Health, Public Health`. Validated against the whole corpus: of the 3,197 documents with a sector note, 2,403 resolve to at least one canonical name, 793 carry only the `Multiple` sentinel, and 1 — `Critical Facilities`, which has no one-to-one reading — resolves to nothing. `sectorsRaw` retains the verbatim text in every case.

**Errors**

| reason | code | when | recovery |
|:---|:---|:---|:---|
| `mirror_not_ready` | `ServiceUnavailable` (`retryable: true`) | The advisory mirror has never completed a full sync | `The ICS advisory index is still building; call cisa_list_reference with topic sources to check its progress, then retry this lookup.` |
| `mirror_unavailable` | `ConfigurationError` | The index store cannot be opened: not writable, read-only, a missing directory, a path through a file, or a file that is not a SQLite database | `The ICS advisory index cannot be opened at its configured location; the server operator must set CISA_CSAF_MIRROR_PATH to a writable path and restart. Retrying will not help, but cisa_check_cve_status, cisa_search_kev, cisa_get_ssvc, and cisa_get_alerts still work.` |
| `unknown_section` | `ValidationError` | `sections` names a key this advisory does not carry | `Call this tool without sections to get the outline of the sections this advisory actually has, then request those by name.` |
| `cves_need_vulnerabilities_section` | `ValidationError` | `cves` is set but `sections` lacks `"vulnerabilities"` — nothing to narrow. Thrown in the handler before the index read, so the recovery hint reaches the caller | `Add "vulnerabilities" to sections, or omit sections so cves selects the vulnerabilities section on its own.` |
| `unknown_cve` | `ValidationError` | A `cves` entry names a CVE this advisory does not cover; the message names only the unknown IDs | `Call this tool without cves to see which CVE IDs the advisory holds — the outline lists them — then pass only those; to find the advisory that covers a CVE, call cisa_search_ics_advisories with cve.` |

A miss is a result, not an error: `{ found: false, guidance, indexCheckpoint, indexLastSyncedAt }`. `guidance` opens with "No advisory with that ID is in the index. IDs look like ICSA-26-260-07 or ICSMA-26-253-02, with an optional revision suffix. Call cisa_search_ics_advisories to find the right ID, or cisa_list_reference with topic advisory_id_formats for the format.", then states the index checkpoint and last completed sync, and — when the date the ID encodes is later than that sync's UTC date and not later than today — says the advisory may be newer than the index, with its cisa.gov URL (Decision 32). The `cisa://advisory/{advisoryId}` not-found carries the same sentences and fields.

---

### `cisa_get_alerts`

**Description**

> List what CISA has published recently — its combined advisory feed, its alerts feed, or its ICS advisory feed. Each feed is a rolling window of exactly 30 items with no history, no pagination, and no date-range query, so the window's coverage varies from about a week to about two months depending on the feed. For ICS advisory history beyond the window, use cisa_search_ics_advisories, which covers the full corpus back to 2010.

| Param | Type | Notes |
|:---|:---|:---|
| `feed` | `z.enum(['advisories','alerts','ics']).default('advisories')` | `advisories` → `all.xml`, `alerts` → `alerts.xml`, `ics` → `ics-advisories.xml`. |
| `limit` | `z.number().int().min(1).max(30).default(30)` | The upstream window is 30; the cap is the real ceiling, not a server choice. |
| `since` | `z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional()` | Filters *within* the fetched window. It cannot reach back beyond it. |

**Output**

```
feed, feedUrl, feedTitle
items[]: { title, link, pubDate, summary, summaryTruncated,
           guid, advisoryId? }
window: { itemCount, oldest, newest, upstreamWindowSize: 30 }
```

`title` is trimmed — upstream carries trailing whitespace. `summary` is the item `description` with HTML stripped and entities decoded, capped at 1,200 characters with `summaryTruncated` disclosed: ICS advisory descriptions run to 14 KB each, and thirty of them unstripped is 420 KB of markup. `advisoryId` is parsed from an `/ics-advisories/` or `/ics-medical-advisories/` link and uppercased, so it chains straight into `cisa_get_advisory`. `guid` is passed through as the upstream node path — it is not a URL and is not presented as one.

**Enrichment**

| Key | Kind | When |
|:---|:---|:---|
| `windowCaveat` | `notice` | Always — "This feed is a rolling window of the 30 most recent items. There is no history, no pagination, and no server-side date filter; anything older than the oldest item shown is unreachable from this feed. For ICS advisory history use cisa_search_ics_advisories." |
| `effectiveQuery` | `echo` | When `since` is set — the applied value and how many of the 30 it excluded. `ctx.enrich.echo()` writes `effectiveQuery`, not `echo` |
| `truncated`, `shown`, `cap` | `truncated` | When `limit` < window size — `ctx.enrich.truncated()` writes these three fields separately |
| `notice` | `notice` | When `since` excludes every item — "No item in the current 30-item window is on or after the since date. The window's oldest item is <date>; anything earlier is not in this feed." |

**Errors**

| reason | code | when | recovery |
|:---|:---|:---|:---|
| `feed_unavailable` | `ServiceUnavailable` (`retryable: true`) | The feed fetch failed or returned a non-XML body | `The CISA feed is unreachable; retry in a few minutes, or use cisa_search_ics_advisories for ICS advisory history, which serves from a local index.` |

---

## Resources — detail

| URI template | Params | Handler | Cache hint | Tool coverage |
|:---|:---|:---|:---|:---|
| `cisa://kev/{cveId}` | `cveId` (same regex as the tools) | Returns one KEV record from the in-memory snapshot, identical in shape to a `cisa_check_cve_status` result. Throws `notFound` when absent. `list()` → the 30 most recently added entries. | `{ ttlMs: 1_800_000, cacheScope: 'public' }` — public-domain data, byte-identical per tenant | `cisa_check_cve_status` |
| `cisa://advisory/{advisoryId}` | `advisoryId` (same regex as `cisa_get_advisory`) | Returns one flattened advisory. Applies the same `outlineOnOverflow(doc, { budget: 24_000 })` treatment as `cisa_get_advisory`'s no-`sections` call — a resource template has no `sections` or `cves` parameter to request a follow-up with, so a caller who lands on the outline arm for the largest advisories (up to 1.38 MB) uses `cisa_get_advisory` to pull named sections or vulnerability entries; the outline lists the vulnerabilities section's CVE IDs, through the same shared extractor. `list()` → the 30 most recently revised advisories. | `{ ttlMs: 21_600_000, cacheScope: 'public' }` | `cisa_get_advisory` |

Both templates get argument completion over a bounded vocabulary: the advisory template completes from the mirror's advisory IDs, the KEV template from the snapshot's CVE IDs, each capped at 100 suggestions.

---

## Services

| Service | Wraps | Used by |
|:---|:---|:---|
| `kev-catalog` (`src/services/kev-catalog/`) | The KEV JSON feed. Holds the parsed snapshot, the derived indexes, and the conditional-refresh loop. | `cisa_check_cve_status`, `cisa_search_kev`, `cisa_get_ssvc` (for `inKev`), `cisa_list_reference` (topic `sources`), `kev-entry` resource |
| `vulnrichment` (`src/services/vulnrichment/`) | Per-CVE fetch from `raw.githubusercontent.com` with a TTL cache. | `cisa_get_ssvc` |
| `csaf-mirror` (`src/services/csaf-mirror/`) | `MirrorService` over the ICS advisory corpus — `schema.ts`, `ingest.ts`, `normalize.ts`, `csaf-mirror-service.ts`. | `cisa_search_ics_advisories`, `cisa_get_advisory`, `cisa_list_reference` (topic `sources`), `ics-advisory` resource |
| `cisa-feeds` (`src/services/cisa-feeds/`) | The three RSS feeds, parsed and cached on a TTL. | `cisa_get_alerts` |

All four are init/accessor: constructed in `createApp({ setup })`, reached at request time through `getKevCatalog()` / `getVulnrichment()` / `getCsafMirror()` / `getCisaFeeds()`.

### Resilience

| Concern | Decision |
|:---|:---|
| Retry boundary | The service method wraps the full pipeline — fetch, decompress, parse, normalize — via `withRetry` from `/utils`, not the network call alone. |
| Backoff | 1 s base for cisa.gov (a Drupal front end under load), 500 ms for `raw.githubusercontent.com`. Three attempts, exponential. |
| Parse-failure classification | Before parsing, check the `content-type` and the first non-whitespace byte. A `text/html` body or a leading `<` on a JSON or XML route throws `serviceUnavailable` with `{ reason: 'upstream_html_response' }` — **never `SerializationError`**. cisa.gov serves a 46 KB HTML error page on a wrong path and can serve the same body transiently under load; classifying that as a parse bug would make a recoverable outage look like a data-shape defect. |
| Pacing | KEV refresh every 30 min, CSAF refresh every 6 h, feeds on a 15-min TTL, Vulnrichment per request with a 6 h TTL and a concurrency cap of 6. No source publishes a rate limit, so the ceiling is self-imposed and documented here. |
| Caller-supplied URLs | None. Every URL is a module constant composed with a schema-validated identifier. There is no SSRF sink on this surface. |
| Upstream-supplied paths | A `changes.csv` row or archive entry becomes a fetch URL and a published `csafUrl` only when its path matches `isCsafSourcePath` (`^\d{4}/[A-Za-z0-9][A-Za-z0-9._-]*\.json$`); anything else is dropped. An advisory's own `self` reference is preferred over the composed cisa.gov URL only when it is `https` on a `cisa.gov` host. |
| Timeouts | `fetchUpstream` in `src/services/upstream-http.ts`, default 30 s, `CISA_HTTP_TIMEOUT_MS` overridable. Every fetch forwards `ctx.signal`. |
| Body ceilings | `readUpstreamText` counts decompressed bytes and throws `serviceUnavailable` `{ reason: 'upstream_body_too_large' }` past the ceiling: KEV 64 MiB, `changes.csv` 16 MiB, one CSAF document 16 MiB, Vulnrichment 16 MiB, an RSS feed 32 MiB. A tar entry whose header declares more than 64 MiB is refused before any buffering read; non-matching entries are discarded in 64 KiB chunks. |
| Caller text ceilings | `q`, `nameContains`, `vendor`, and `product` are capped at 512 characters (`assertSearchTextLength`, a `ValidationError` with reason `search_text_too_long`) before they reach FTS5, the per-record tokenizer, or a `GLOB` pattern. The `vendor`/`product` cap is not about cost — a longer needle only makes the comparison cheaper — but about SQLite, which refuses a `LIKE` or `GLOB` pattern over 50,000 bytes with a raw `SqliteError`; a class per non-ASCII letter reaches that at about 8,300 characters (Decision 36). |
| Upstream-shape tolerance | A KEV record is admitted only when its `cveID`, `dateAdded`, and `dueDate` match the advertised shapes, and its `cwes` are filtered to `^CWE-[0-9]+$`; a feed link yields an `advisoryId` only when the slug matches `ADVISORY_ID_PATTERN`. One malformed upstream record drops that record, never the whole page. |

### API efficiency

There is no upstream search, batch, or field-selection endpoint anywhere. Efficiency comes from the storage tiers, not from query shaping:

- KEV: one file serves every membership check, filter, and sort. A 200-CVE batch costs zero upstream requests.
- CSAF: one archive seeds the whole corpus; refresh reads one 228 KB manifest and fetches only the documents whose timestamp moved.
- Vulnrichment: one file per CVE is the only access path the source offers; the TTL cache is what keeps a repeated triage loop from re-fetching.
- Feeds: one fetch per feed per TTL window, shared across all callers.

---

## Storage tiers and refresh

### Tier 1 — KEV, in-memory, process-level

The catalog — 1,716 records and 1.74 MB at catalog `2026.09.18` — sits far below the mirror tier's floor, and the data is public and byte-identical for every tenant, so one process-level snapshot is shared — no `ctx.state`, no tenant scoping.

Held per refresh: the parsed records, the raw envelope metadata (`catalogVersion`, `dateReleased`, `count`), `fetchedAt`, the upstream `last-modified`, and derived indexes — `Map<cveId, record>`, plus sorted arrays by `dateAdded` and `dueDate`.

**Refresh** uses `If-Modified-Since` with the stored `last-modified`, sent with `Accept-Encoding: gzip`. A no-change poll is a 304 with zero bytes; a change costs 192 KB on the wire. **`If-None-Match` is not used**: the origin serves an ETag but ignores it on conditional requests and returns the full body (1.74 MB at catalog `2026.09.18`) every time. Scheduled via `schedulerService` in `setup()`, default `*/30 * * * *`. The catalog updates on business days, so 48 polls a day is ~2 changed fetches and 46 empty ones.

**Cold start** is single-flight: `setup()` kicks the first load off without awaiting it, and a request arriving before it lands awaits the same in-flight promise rather than starting a second fetch. The observed fetch is ~80 ms, so the first request blocks briefly rather than failing. If the load fails and no snapshot is held, the tools throw `catalog_unavailable`; if a snapshot is held, a failed refresh logs a warning and the previous snapshot keeps serving — a stale catalog beats no catalog, and `cisa_list_reference` topic `sources` exposes `lastCheckedAt` so the staleness is visible rather than silent.

### Tier 2 — CSAF advisories, SQLite mirror

3,926 documents and 94.6 MB at the 2026-09-17 checkpoint land squarely in the `MirrorService` tier. One table, FTS5 over the searchable text, and junction tables for CVE, sector, and CWE membership.

```ts
{
  path: config.csafMirrorPath,
  table: 'ics_advisories',
  primaryKey: 'advisoryId',
  version: 2,              // must cover the highest migration's version
  columns: {
    advisoryId: 'TEXT', series: 'TEXT', title: 'TEXT',
    vendorsText: 'TEXT', productsText: 'TEXT',
    vendorCount: 'INTEGER', productCount: 'INTEGER',
    cveCount: 'INTEGER',
    maxCvss: 'REAL', maxCvssSeverity: 'TEXT', maxCvssVersion: 'TEXT',
    sectorsText: 'TEXT', sectorsRaw: 'TEXT',
    published: 'TEXT', revised: 'TEXT', revision: 'TEXT',
    publisherCategory: 'TEXT',
    sourcePath: 'TEXT', url: 'TEXT', csafUrl: 'TEXT',
    attribution: 'TEXT',     // the attribution string; a search-result column
                             // rather than a per-read parse of `document`
    document: 'TEXT',        // the normalized advisory, JSON
  },
  fts: ['title', 'vendorsText', 'productsText'],
  indexes: [
    { columns: ['series'] }, { columns: ['maxCvss'] },
    { columns: ['published'] }, { columns: ['revised'] },
    { columns: ['publisherCategory'] }, { columns: ['sourcePath'] },
  ],
}
```

Four auxiliary tables via `migrations` (`CREATE TABLE IF NOT EXISTS`, so a fresh database and an upgrade run identically). Migration 1: `advisory_cves(advisoryId, cve)` and `advisory_sectors(advisoryId, sector)`, each indexed on the second column, and `mirror_meta(key, value)`. Migration 2: `advisory_cwes(advisoryId, cweId)`, indexed on `cweId` — one row per distinct CWE across an advisory's vulnerability entries (9,075 rows, 465 distinct CWEs, every one of the 3,926 advisories carries at least one). The framework runner applies a migration only when `stored < migration.version <= spec.version`, so the spec's top-level `version` moved to 2 with it; an entry added without that bump never runs. Exact membership is what the junctions buy — scanning a delimited text column is both slow and wrong (`Water` is a substring of `Wastewater`). They are maintained from the ingester's mapping, reached through `mirror.raw()`. `mirror_meta` holds two values the framework's own sync state has no slot for: the `changes.csv` ETag between refresh runs, and `ingest_content_version`, the content version of the last completed `init` (Decision 19). An upgraded index gets an empty `advisory_cwes` from the migration; its rows arrive with the content-version re-ingest.

`document` holds the normalized advisory JSON rather than the raw CSAF: the flattening, sector extraction, and CVSS computation run once at ingest, not per read. It also means `cisa_get_advisory`'s section outline measures what it actually returns.

**Ingest (`mode: 'init'`).** One `GET` of the repository tar.gz (11.4 MB, ~1.5 s), streamed and decompressed in memory, entries under `csaf_files/OT/white/*/*.json` parsed and normalized, yielded in pages of 200 with `checkpoint` set to the maximum `current_release_date` seen so far. Filenames are `icsa-*.json` / `icsma-*.json` — never digit-led — so the entry filter is a `.json` suffix match, which also excludes the `.json.asc` and `.json.sha512` sidecars every document ships alongside without any extra exclusion rule. The archive is the seeding path because 3,926 individual `raw.githubusercontent.com` requests is the alternative. Once the last page is applied, the ingester writes `INGEST_CONTENT_VERSION` to `mirror_meta`; an archive that yields no OT documents fails the run instead, so an existing index is never marked current without having been re-derived.

**Refresh (`mode: 'refresh'`).** Conditional `GET` of `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv` with `If-None-Match` — `raw.githubusercontent.com` honors it, so an unchanged poll is a 304 on a 228 KB file. When it changes, parse all 3,926 rows (accepting both the quoted-with-microseconds and unquoted-with-seconds forms the distributions use), diff against the stored `revised` values, fetch only the documents whose timestamp moved, and emit tombstones for paths present in the store but absent from the manifest. `changes.csv` is a full manifest rather than an append-only log, which makes deletions detectable — the reason it is the refresh source instead of the checkpoint alone. It runs once at boot and at `17 */6 * * *`, on every transport, and never against an index that has never completed a sync (Decision 29); every seed and refresh holds the cross-process sync lease (Decision 30).

**KEV join.** KEV is never mirrored into this index. `inKev` binds the in-memory snapshot's CVE set as one JSON array read through `json_each(?)` inside an `advisory_cves` subquery; per-result `kevCves` intersects the page's CVE rows with the same set in memory (Decision 22).

**Read gating.** Every mirror read is gated on `await mirror.ready()`, which is true once a full sync has *ever* completed — so a mirror mid-refresh, or one whose last refresh failed, keeps serving. There is no live fallback: the corpus only exists as 3,926 individual files, and fanning out per query is not a serving strategy. A never-seeded mirror throws `mirror_not_ready`; a store that cannot be opened at all throws `mirror_unavailable` (Decision 28). Both gates read `availability()`, which classifies the open failure.

### Tier 3 — Vulnrichment, per-CVE fetch with TTL cache

The repository is ~343 MB and a triage session touches tens of CVEs, so mirroring it would cost three orders of magnitude more than it saves. Per-CVE `GET` against `raw.githubusercontent.com` (path composed from the CVE's year and numeric block), with the normalized SSVC result cached in `ctx.state` under `ssvc/<CVE-ID>` at a 6 h TTL. Cache reads and writes are best-effort — a miss or a storage failure falls through to a fetch, so correctness never depends on the cache. The cached value is a deterministic public-identifier-to-record map, so the shared `default` tenant is benign.

A 404 is cached as a negative result at a shorter 1 h TTL: CISA enriches CVEs continuously, and a permanent negative cache would hide a record that appeared an hour later.

### Tier 4 — RSS feeds, timer cache

No conditional-GET mechanism exists, so each feed is fetched at most once per 15 min per process and the parsed window is held in memory. `cisa_get_alerts` serves from the cache and triggers a refresh when it is stale. Worst case is three unconditional fetches per 15 min totalling ~1 MB — acceptable against a source that publishes no rate limit, and far better than a fetch per call.

---

## Config

`src/config/server-config.ts`, its own Zod schema, lazy-parsed via `parseEnvConfig`. Every variable is optional; the server runs correctly with none of them set.

| Env Var | Required | Default | Description |
|:---|:---|:---|:---|
| `CISA_KEV_REFRESH_CRON` | No | `*/30 * * * *` | Cron for the KEV conditional-refresh poll, on every transport. `off` (any case) disables it; any other value `node-cron` rejects fails startup with a `ConfigurationError` naming the variable (Decision 31). |
| `CISA_CSAF_MIRROR_PATH` | No | `<cache>/cisa-cybersecurity-mcp-server/csaf.sqlite3` | Filesystem path to the ICS advisory index. `<cache>` is `~/Library/Caches` on macOS, `%LOCALAPPDATA%` on Windows, and an absolute `$XDG_CACHE_HOME` else `~/.cache` elsewhere — never the working directory (Decision 28). The Docker image sets `/usr/src/app/.mirror/csaf.sqlite3`. |
| `CISA_CSAF_MIRROR_AUTO_INIT` | No | `true` | `z.stringbool()`. When true, seed a mirror that has never completed a sync, and re-ingest one an older ingest-content version built (Decision 19), both in the background at startup. Set false where seeding runs out of band. |
| `CISA_CSAF_REFRESH_CRON` | No | `17 */6 * * *` | Cron for the incremental advisory refresh, on every transport; the same pass also runs once at boot (Decision 29). `off` disables both; an invalid value fails startup as above. |
| `CISA_VULNRICHMENT_CACHE_TTL_SECONDS` | No | `21600` | TTL for a cached SSVC record. Negative results use one sixth of this. |
| `CISA_FEED_CACHE_TTL_SECONDS` | No | `900` | TTL for a parsed RSS window. |
| `CISA_HTTP_TIMEOUT_MS` | No | `30000` | Per-request timeout for every upstream fetch. |

`z.stringbool()` for the boolean, never `z.coerce.boolean()` — `Boolean("false")` is `true`, so a coerced flag cannot be turned off from the environment.

**Packaging parity.** `lint:packaging` requires the same names in `server.json` `environmentVariables[]` and `manifest.json` `mcp_config.env` + `user_config`. All seven are optional strings, so each `user_config` entry carries `"default": ""` and each is wired as `"CISA_X": "${user_config.cisa_x}"`.

**Dependencies.** `better-sqlite3` is added to `dependencies` (see Decision 2), and `scripts/_mirror-context.ts` plus the three `csaf-mirror-*.ts` lifecycle scripts are added to `package.json` `files[]` so the npm tarball and the bundle carry them.

**Session posture.** `createApp({ sessionMode: 'stateless' })`. No handler returns `ctx.requestInput`, so nothing needs a durable session.

---

## Server Instructions

As shipped in `createApp({ instructions })`:

> This server serves four CISA datasets, all keyless and all read-only. Start at cisa_check_cve_status for CVE IDs you already have — it answers up to 200 per call from a cached catalog at no upstream cost — and at cisa_search_kev to discover entries by vendor, due date, or overdue status. cisa_get_ssvc adds the SSVC decision points CISA publishes per CVE and computes the BOD 26-04 remediation timeline they imply for an asset exposure you supply; that computation is CISA's published decision logic applied to CISA's published inputs, not a compliance determination. ICS advisories are served from a local index of the full CSAF corpus back to 2010 — search it with cisa_search_ics_advisories, which can also narrow to the advisories covering a KEV-listed CVE, and read one with cisa_get_advisory. The index seeds itself on first run; until it finishes, the two ICS tools report that state and every other tool works normally. For what CISA published most recently, cisa_get_alerts reads a 30-item rolling window of its advisory, alert, or ICS advisory feed with no history beyond that window — reach for cisa_search_ics_advisories instead for ICS advisory history. cisa_list_reference decodes the vocabulary the rest of the surface takes as input and reports what data this server currently holds. The KEV catalog records additions but no per-record modification timestamp, so "what changed" questions are answerable for additions only.

---

## Test seams

| Seam | What it enables |
|:---|:---|
| `createFetchMock(routes)` from `/testing` | Every upstream boundary. Each service reaches the network only through `fetchWithTimeout`, so one fake covers all four. |
| `initKevCatalog({ now })` | An injected clock. `overdue`, `daysUntilDue`, and the echoed `asOf` are the only time-dependent outputs on the surface; without this they are untestable. |
| `initCsafMirror({ mirrorPath })` | A per-test temporary file. `openSqliteHandle` creates the parent directory, so a `tmpdir()` path is enough; no shared fixture database. Two `new CsafMirrorService()` instances on one file stand in for two processes sharing an index — each owns its own handle, so only the lease row connects them. |
| `defaultCsafMirrorPath({ platform, env, homedir })` | The default index path for any platform from injected host facts, so no test resolves — or creates — anything in the real user cache. |
| Pure functions, no I/O | `parseKevNotes`, `classifyReference`, `resolveBod2604Timeline` (the Table 1 lookup), `extractSectors`, `flattenProductTree`, `computeMaxCvss`, `deriveCvssV2Severity`, `normalizeAdvisoryId`, `parseChangesCsv`, `stripFeedHtml`, `cveToVulnrichmentPath`. Each is unit-testable against a fixture with no network and no database. |
| `runToolContract(definition, input)` | Production-shaped success and error envelopes per tool without transport, auth, or telemetry. |

Required sparse-payload cases, one per external shape:

- KEV record with `cwes: []` and a single-segment `notes` holding only the NVD URL (just over 100 of the 175 empty-`cwes` records at catalog `2026.09.18` look like this).
- KEV record citing no directive at all — `directive` must be `null`, not inferred.
- KEV `notes` shapes beyond `url` and `Label: url`: comma runs, URLs inside prose, a `;` inside a URL, trailing punctuation — each URL a reference, the prose kept.
- CSAF advisory with no sector note and `cvss_v2`-only scores (a pre-2017 converted advisory) — `sectors` empty, `severityDerived: true`.
- CSAF advisory with a vulnerability object carrying no `scores[]` (431 exist) and one carrying no CVSS anywhere (2 documents).
- CSAF advisory over the outline budget, asserting the outline arm and a subsequent `sections` selection.
- Vulnrichment record whose `containers.adp[]` holds a non-CISA provider but no `CISA-ADP` entry.
- Vulnrichment record with a `CISA-ADP` container carrying CVSS and CWE but no SSVC metric.
- A 404 from Vulnrichment for a CVE that *is* in KEV — `found: false` plus guidance, never a throw.
- An HTML body on the KEV JSON route — must classify as `ServiceUnavailable`, and the assertion should pin that it is not `SerializationError`.
- `changes.csv` in both the quoted-microsecond and unquoted-second forms.
- An RSS item with a two-digit-year `pubDate` and a trailing-whitespace title.

`fuzzTool` on all seven definitions, asserting no crashes, no prototype pollution, and no stack-trace leaks.

---

## Implementation Order

1. `src/config/server-config.ts` and `createApp()` wiring in `src/index.ts` (`sessionMode`, `setup`, `teardown`). Remove the scaffold echo definitions and their tests.
2. `kev-catalog` service — fetch, conditional refresh, snapshot, indexes, notes parser.
3. `cisa_list_reference` — static tables plus the `sources` topic over live in-process state. No service dependency beyond the accessors; it grounds field-testing for everything after it.
4. `cisa_check_cve_status`, then `cisa_search_kev`.
5. `vulnrichment` service, then `cisa_get_ssvc` — including the Table 1 resolver as a standalone pure function with its own test file.
6. `csaf-mirror` service — `schema.ts`, `normalize.ts` (the flattener, sector extractor, CVSS computation), `ingest.ts` (archive init and `changes.csv` refresh), the service wrapper.
7. `scripts/csaf-mirror-init.ts`, `csaf-mirror-refresh.ts`, `csaf-mirror-verify.ts`, and `scripts/_mirror-context.ts`; the Dockerfile runtime-stage stanzas and the `files[]` additions.
8. `cisa_search_ics_advisories`, then `cisa_get_advisory` (including the outline path).
9. `cisa-feeds` service, then `cisa_get_alerts`.
10. Resources `cisa://kev/{cveId}` and `cisa://advisory/{advisoryId}`, with completion.
11. Packaging: `server.json`, `manifest.json`, both plugin manifests, README, `clean-mcpb.ts` native-strip extension (Decision 2).

Each step is independently testable; steps 2–5 need no SQLite at all.

---

## Known Limitations

Inherent to the sources. None is solvable by this server, and each is stated in the tool description or output of the tool it affects.

1. **KEV modifications are invisible.** The feed carries `dateAdded` but no per-record modified timestamp. A revised `dueDate` or `requiredAction` on an existing entry is indistinguishable from an unchanged one. A retained-snapshot diff would close this and is deliberately not in v1.
2. **Most KEV entries cite no directive.** 1,277 of 1,716 at catalog `2026.09.18` name neither BOD 22-01 nor BOD 26-04; `directive` is `null` for them rather than inferred from age.
3. **The KEV due date is not reproducible from published SSVC.** In a 24-CVE sample, 9 disagreed with Table 1 under a publicly-exposed assumption and 1 CVE had no enrichment record at all. The two facts are reported side by side and never reconciled.
4. **Vulnrichment coverage is incomplete and can lag.** Not every CVE — including some in KEV — has a record, and a published `Exploitation` value can predate the KEV addition that contradicts it.
5. **Advisory sector coverage begins in 2017.** 729 of 3,937 documents carry no sector note at the 2026-09-24 checkpoint; a sector filter cannot reach them. The gap is disclosed, with the live count, on every filtered call.
6. **No structured CVSS v4 in the advisory corpus.** 392 advisories score only in CVSS v2 at the 2026-09-24 checkpoint, where the upstream publishes no severity label and the band must be derived.
7. **The RSS feeds have no history and no conditional GET.** Thirty items, no pagination, no date query, no ETag or Last-Modified — a timer-cached unconditional poll is the only available strategy.
8. **Advisory vendor names are unnormalized.** 895 distinct vendor labels across 3,926 documents at the 2026-09-17 checkpoint, with the same company under several spellings, and a few double-encoded upstream (`GeutebrÃ¼ck`, `LeÃ£o`), so `Geutebrück` does not match them. Vendor filtering is substring matching, not an enum.
9. **The KEV feed ignores `If-None-Match`.** Only `If-Modified-Since` yields a 304; a client that trusts the served ETag re-downloads the whole feed (1.74 MB at catalog `2026.09.18`) on every poll.
10. **No Cloudflare Workers deployment.** The mirror needs embedded SQLite and a persistent filesystem; neither exists in an isolate. stdio, HTTP, Docker, and `.mcpb` are the supported surfaces.

---

## Decisions Log

**1. The CSAF mirror seeds itself in the background at startup; out-of-band scripts are the escape hatch; nothing is baked at container build.**
The corpus is one 11.4 MB archive fetched in ~1.5 s, not an API pagination run — so the usual "init out of band, never on startup" posture is calibrated for a cost this source does not have. Requiring a CLI step before a headline capability works is bad DX for `npx` and impossible for an `.mcpb` user, who has no shell into the bundle. `setup()` therefore starts a background `init` without awaiting it when `CISA_CSAF_MIRROR_AUTO_INIT` is true and the mirror has never completed — or was built by an older ingest-content version (Decision 19); KEV, SSVC, and alert tools serve from the first request regardless. `mirror:init` / `mirror:refresh` / `mirror:verify` ship for Docker `exec`, CI, and operators who want explicit control. Build-time baking is rejected on two counts: it adds ~60 MB to the image and ships a snapshot that is stale the day it is built. In Docker the index lives on a named volume at `CISA_CSAF_MIRROR_PATH`, which the image sets to `/usr/src/app/.mirror/csaf.sqlite3`, so a container recreation does not re-seed. Default path: the per-user cache directory (Decision 28).

**2. `better-sqlite3` is a regular dependency, and the `.mcpb` bundle carries it.**
The open question was whether shipping the SQLite driver locks the bundle to the packing platform. It does not. `better-sqlite3@13.0.3` ships all eight platform prebuilds inside the npm tarball — `darwin-{arm64,x64}`, `linux-{arm64,x64}`, `linuxmusl-{arm64,x64}`, `win32-{arm64,x64}`, 16.1 MB total — and `lib/binding.js` selects one at runtime from `process.platform`, `process.arch`, and a musl check. There is no install script, no `prebuild-install` download, and no node-gyp step, so a clean `npx` install on Node needs no build toolchain. Because the prebuilds are all present, the bundle stays cross-platform, and the `NATIVE_BINDING_ENTRY` regex in `clean-mcpb.ts` only targets `@duckdb/node-bindings-*`, so nothing strips it today. Size is the only real constraint: unpacked the package is 26.0 MB, of which `deps/` is 9.8 MB of SQLite C source used solely for a source build. Add a third entry class — `BUILD_ONLY_ENTRY = /^node_modules\/better-sqlite3\/(?:deps|src)\//` — to `clean-mcpb.ts` and the matching literal in `lint-packaging.ts`, which the files' own comments require to be edited together. A separate literal rather than widening `NATIVE_BINDING_ENTRY`: `prebuilds/` is a native binding that must *survive*, and overloading the regex that exists to remove platform-locked natives would invite exactly the deletion that breaks the bundle. Stripped, the zipped contribution is 8.2 MB against 10.7 MB unstripped — comfortably inside the 25 MB registry cap. Under Bun and in the `oven/bun` Docker image the driver is never loaded at all: `openSqliteHandle` uses the built-in `bun:sqlite`.
*Residual risk, deliberately carried:* Node 24+ ships `node:sqlite`, and on Node 26.5.0 it exposes SQLite 3.53.4 with FTS5 and `bm25()` working — a zero-byte driver already inside the Node binary this server pins. The framework's `openSqliteHandle` has no arm for it, so adopting it is a framework change, not a server one. Worth filing upstream; not a blocker, since the prebuild finding removes the portability problem it would have solved.

**3. KEV is an in-memory process-level index refreshed with `If-Modified-Since`, and an HTML body is a transient upstream failure.**
1,716 records and 1.74 MB at catalog `2026.09.18` sit below the mirror tier's floor, and the data is public and byte-identical per tenant, so one shared snapshot with no tenant scoping is correct. Refresh every 30 min conditionally: a no-change poll is a 304 with zero bytes, a change costs 192 KB gzipped. **`If-None-Match` is deliberately unused** — the origin serves an ETag but ignores it on conditional requests and returns the full body, verified against the live ETag in strong, weak, and wildcard forms. Cold start is single-flight and blocking: `setup()` starts the load without awaiting it, and an early request awaits the same promise rather than racing a second fetch; the observed fetch is ~80 ms. A failed refresh with a snapshot in hand logs and keeps serving the old snapshot, with the staleness visible through `cisa_list_reference` topic `sources`; a failed first load throws `catalog_unavailable`, retryable. An HTML body on the JSON route — 46 KB from a Drupal error page — is classified `ServiceUnavailable`, never `SerializationError`: it signals a routing or availability problem the caller can retry past, and labelling it a parse error would make a recoverable outage read as a data-shape defect.

**4. Vulnrichment is fetched per CVE on demand with a TTL cache, not mirrored.**
The repository is ~343 MB against a corpus this server touches tens of records from per session — three orders of magnitude of cost for no gain. Path shape verified: `{YYYY}/{block}/{CVE-ID}.json` on branch **`develop`** (`main` 404s), where `block` is the CVE numeric part with its last three characters replaced by `xxx`. Normalized results cache under `ctx.state` at `ssvc/<CVE-ID>` for 6 h, best-effort in both directions so correctness never depends on the cache. A 404 caches as a negative for 1 h rather than indefinitely, because CISA enriches continuously. A miss is `{ found: false, guidance }` — a result the agent reasons about, not a throw — with distinct guidance for a 404, a record with no CISA-ADP container, and a CISA-ADP container carrying no SSVC metric.

**5. RSS feeds are polled unconditionally on a 15-minute timer, because no conditional-GET mechanism exists.**
The feeds serve no `etag` and no `last-modified`, and set `cache-control: private, no-cache, must-revalidate`, so there is nothing to make a request conditional on. Fetching per call would mean up to 531 KB per invocation; a 15-min shared TTL caps it at three fetches and ~1 MB per window across all callers. The 30-item ceiling is the upstream's, not a server choice, so `limit` maxes at 30 and `cisa_get_alerts` always carries a `windowCaveat` stating there is no history, no pagination, and no server-side date filter, routing ICS history to `cisa_search_ics_advisories`. `since` filters within the fetched window and says so.

**6. `cisa_get_ssvc` computes the BOD 26-04 timeline from three published decision points plus one caller input, and reports CISA's own assignment separately.**
Inputs: `Automatable` and `Technical Impact` from Vulnrichment, `In the KEV` from this server's local snapshot, and `Publicly Exposed` from the caller's `assetExposure` — the one decision point CISA cannot publish because it is a property of the caller's estate. Output is the Table 1 row number, `timelineLabel` in the directive's own wording, `remediationTimelineDays` (3, 14, 60, or `null` for "Fix on system upgrade"), and `forensicTriageRequired`. With `assetExposure: 'unknown'` both arms are returned rather than a guess. Every result carries a fixed caveat: this is CISA's published decision logic applied to CISA's published decision points and the exposure the caller stated — not a compliance determination, and not CISA's assigned KEV due date. The two are reported side by side because they demonstrably differ: in a 24-CVE sample, 9 disagreed and 1 had no enrichment record. `assignmentAgrees` surfaces the disagreement as a fact; nothing reconciles it.

**7. Snapshot honesty is stated in three places, not one.**
The KEV feed has no per-record modified timestamp, so a revised `dueDate` is undetectable. This appears in `cisa_search_kev`'s description ("the catalog records additions but carries no per-record modified timestamp"), in a `snapshotCaveat` enrichment notice on every call that sets `dateAddedFrom` — where the caller is explicitly asking a "what changed" question and the answer is narrower than the question — and in `cisa_list_reference` topic `kev_fields`. A retained-snapshot diff would close the gap and is explicitly not a v1 promise.

**8. No DataCanvas.**
The surface is discovery metadata and find-the-record-then-drill-in: advisory titles, vendor and product labels, CVE IDs, dates, severity bands. An agent filters and reads these; it does not run aggregate SQL over them. Row count does not change that — the gate is analytical shape, and this surface fails it. A `canvas_id` with no `dataframe_query` tool would be dead output, and adding the pair would be two tools serving a workflow nobody has.

**9. Every advisory response carries its source URL and attribution; nothing claims public domain for CSAF; no DHS or CISA branding anywhere.**
KEV is a US Government work in the public domain under 17 U.S.C. §105 and Vulnrichment is CC0-1.0 — both clean. The CSAF repository declares **no license** (confirmed against repository metadata), and 1,063 of its 3,926 ICS advisories have `publisher.category: "other"`, meaning CISA republished a vendor's advisory with the vendor's own text and revision history. That is not uniformly a US Government work. So `cisa_search_ics_advisories` and `cisa_get_advisory` both return `url` (the cisa.gov web version), `csafUrl` (the raw CSAF JSON), and an `attribution` string naming the publisher and, for a republication, the originating vendor from the revision history. The attribution is unconditional rather than conditional on `publisher.category`, because the caller should not have to branch on a field to know whether the text is safe to redistribute. Separately, CISA's terms forbid use of the DHS seal, the CISA logo, or any implied endorsement — this constrains the README, both plugin marketplace entries, the icon, and any hosted landing page.

**10. Composition surfaces are named in tool description text, not left for the caller to discover.**
Three chaining points are load-bearing and each is stated where the agent reads it. `cisa_check_cve_status` says its returned CWE IDs chain into the `cwe` filter of both search tools, that the reverse direction — which ICS advisories cover a CVE — is `cisa_search_ics_advisories` with `cve` or `inKev`, and that the parsed NVD reference gives the canonical scoring record. `cisa_search_kev` says vendor and product are CISA's free-text labels rather than CPE names, so a CPE-shaped query belongs elsewhere. `cisa_check_cve_status` accepts a 200-CVE batch precisely so a CVE alias list from a dependency audit can be checked in one call, and says the call costs nothing upstream. No other server is named — the description tells the caller what the value is and what shape it takes, which is what a caller who installed only this server can act on.

**11. The advisory ID pattern accepts `ICSMA` and both suffix forms.**
The pattern carried in the brief, `^ICS[AM]-\d{2}-\d{3}-\d{2}[a-z]?$`, rejects every one of the 188 `ICSMA-` advisories — `ICS[AM]` matches a single character, so it spells `ICSA` or `ICSM`, never `ICSMA` — and rejects `ICSA-16-231-01-0`, a real document with a numeric rather than alphabetic revision suffix. The design uses `^ICS(A|MA)-\d{2}-\d{3}-\d{2}(?:[A-Z]|-\d+)?$`, with no flag: every pattern on this surface is advertised in JSON Schema, which carries no flags, and a `/i` pattern once told strict clients that `ICSA-10-316-01A` — a stored, emitted ID — was invalid, so they rejected whole search pages. The pattern matches the canonical uppercase form every stored and emitted ID takes; input tolerance lives in normalization, which trims, strips a trailing `.json`, and uppercases before the check. Letter suffixes `A` through `F` are observed across 120 documents. Every regex in an advertised schema is flag-free, which the surface smoke test enforces.

**12. The mirror covers the OT distribution only.**
`csaf_files/` holds three distributions: OT (3,926 `icsa-`/`icsma-` documents, the ICS corpus this server is for), IT (89 `va-` documents), and VA (3 `va-` documents, overlapping IT's paths). Mirroring IT and VA would broaden the server past the ICS scope its name and tool surface promise, for 92 documents whose recent members are already reachable through `cisa_get_alerts`. Adding them later is a `series` enum extension plus a second ingest source, not a redesign. The two `va-` distributions also overlap on path, which would need a distribution-qualified primary key — another reason not to take it on for 92 documents.

**13. Sectors are extracted by longest-match against canonical names, with the raw text always retained.**
The sector note is free-form prose, not an enum. Splitting on commas or "and" is definitively wrong: `Healthcare and Public Health` and `Water and Wastewater Systems` contain "and", and `Nuclear Reactors, Materials, and Waste` contains commas — separator splitting produces tokens like `and Water` and `Facilities`. The design matches the 16 canonical sector names plus a small alias table, longest-first, consuming each hit. The table includes the one-to-one short forms `Water`, `Transportation`, `Healthcare`, `Healthcare, Public Health`, and `Health, Public Health`: longest-first consumption already stops a bare `Water` or `Transportation` from matching inside `Water and Wastewater Systems` or `Transportation Systems`, and adding them resolved 30 advisories that had previously lost a named sector — 8 that resolved to nothing, and 22 compound notes such as `Energy, Healthcare, and Transportation` that resolved only partially. `Critical Facilities` stays unaliased because it has no one-to-one reading. Validated across the corpus: of the 3,197 documents with a sector note, 2,403 resolve to at least one canonical name, 793 carry only the `Multiple` sentinel, and 1 (`Critical Facilities`) resolves to nothing. `sectorsRaw` carries the verbatim text in every case, so nothing the caller might need is lost to normalization.

**14. Maximum CVSS is computed from per-vulnerability scores, and a v2-only band is flagged as derived.**
`document.aggregate_severity` exists on only 52 of 3,926 documents, so it cannot back a severity filter. `maxCvss` is the maximum `baseScore` across every `vulnerabilities[].scores[].cvss_v3|cvss_v2`. `cvss_v3` always carries `baseSeverity`; `cvss_v2` never does across all 697 occurrences, so the band is derived from the CVSS v2 thresholds and marked `severityDerived: true` rather than presented as upstream's. No `cvss_v4` exists anywhere in the corpus as a structured score — where CVSS v4 appears it is prose inside a `details` note, and it is surfaced as a note, never parsed into a score field.

**15. `cisa_get_advisory` uses outline-on-overflow, not truncation.**
783 of 3,926 advisories exceed the 24 KB default budget, 102 exceed 100 KB, and the largest is 1.38 MB with 544 vulnerability entries and 585 products. Returning those whole burns the caller's context; truncating them either hides data or desyncs `content[]` from `structuredContent`. `outlineOnOverflow` returns a complete, honest section outline with per-section byte sizes and a re-call contract, and `selectSections` serves the selection. The re-call is stateless — the mirror lookup is deterministic, so the handler re-reads the row. The `products` arm is not capped: the outline treats `products` as one indivisible section, so a cap would drop rows no re-call can recover and take their product names out of the search index. A caller who asks for `sections: ["products"]` on a 585-product advisory has asked for all 585.

**16. A not-yet-seeded mirror is a typed retryable error, not an empty result.**
An empty search result would be a lie — it asserts that nothing matches when the index simply does not exist yet. `mirror_not_ready` carries `ServiceUnavailable`, `retryable: true`, and a recovery naming `cisa_list_reference` topic `sources`, which reports the sync status and document count. That routing target is deliberately ungated and network-free: it is callable precisely in the situation the agent is recovering from.

**17. No prompts.**
Every workflow this server serves is a direct lookup or a filtered search whose parameters the tool schema already describes. A prompt template would restate tool descriptions in a surface fewer clients expose.

**18. The `cisa://advisory/{advisoryId}` resource carries the same outline-on-overflow treatment as the tool, not a bare full read.**
An earlier draft of this design had the resource always return `cisa_get_advisory`'s full arm on the reasoning that a resource read is a single fixed shape. That contradicts Decision 15's own reasoning: nothing about reading an advisory through a resource template makes a 1.38 MB, 585-product document any cheaper to hand back whole, and a resource client has no `sections` parameter to opt out with the way a tool caller does. The resource now runs the identical `outlineOnOverflow(doc, { budget: 24_000 })` the tool's no-`sections` call uses; a caller who lands on the outline arm follows up with `cisa_get_advisory` to name the sections it needs.

**19. The index records the ingest-content version it was built with, and an older index re-ingests itself in place on boot.**
`refresh` reprocesses only documents whose upstream revision date moved, so a change to what ingest derives from an unchanged document — a lifted product cap, a new sector alias, a new junction table — would otherwise never reach an existing local or hosted index. `INGEST_CONTENT_VERSION` in `ingest.ts` is written to `mirror_meta` once a full `init` has applied its last page; an index with a lower or absent value is stale. At boot, on stdio and HTTP alike and gated by `CISA_CSAF_MIRROR_AUTO_INIT`, `autoInit()` runs a background `init` over a stale index. That needs no readiness gap: the framework runner keeps `completed_at` across an in-progress run, so `ready()` stays true and every existing row keeps serving until its upsert lands, and a failed or interrupted run leaves the version stale for the next boot to retry. Measured on the full corpus: the 11.4 MB archive and all 3,926 advisories re-ingest in about 2 s, changing the stored content of 40 documents (10 over the former product cap, 30 with newly resolved sectors) and filling `advisory_cwes`. Two side effects while it runs: the sync checkpoint resets when the run starts and climbs back to its prior value as pages land (the runner seeds a from-scratch `init` with no checkpoint), and a CWE search may miss matches because `advisory_cwes` is still filling, so `cisa_search_ics_advisories` reads `contentState()` on every `cwe` search and discloses the result as possibly incomplete while the index is stale, withholding its confident zero-hit fragment. `mirror:verify` reports a stale version as a warning rather than a failure, because the index still serves. Rejected: re-deriving content inside a migration, which cannot re-read documents the index stores only in normalized form, and requiring an operator `mirror:init`, which an `.mcpb` user has no shell to run. Raise the constant whenever ingest would store different content for an unrevised document.

**20. A `q` with nothing to search is an error, and an unsearchable token is dropped.**
Dropping the `MATCH` clause for a whitespace or bare-quote `q` answered the whole corpus under a filter the caller believed applied, and a punctuation token inside an AND chain (`siemens --`) became an empty FTS5 phrase that matched nothing. `toFtsMatch` now keeps only tokens with a letter, digit, or private-use character — the categories the `unicode61` tokenizer indexes by default (its Unicode 6.1 tables differ only on characters assigned or recategorized since, none of which appear in the index's vocabulary) — and throws `empty_search_text` when none remain. The throw is service-side rather than a schema refine, because a schema rejection surfaces as `-32602` before the handler and loses the recovery hint.

**21. Every caller-supplied pattern matches literally.**
The resource's advisory-ID completion prefix escapes `\`, `%`, and `_` and runs under `LIKE … ESCAPE '\'`, and `vendor` and `product` match through `GLOB` (Decision 36), where `%`, `_`, and `\` are ordinary characters and `*`, `?`, `[` are bracketed — so `Siem_ns` does not match Siemens and `OpenPLC_V3` still matches its literal underscore. The one remaining `LIKE` in the service (`maxCvssVersion LIKE '2%'`) is a constant. FTS5 input is neutralized by quoting (Decision 20), and `cisa_search_kev`'s substring filters are plain `includes()` with no pattern syntax.

**22. KEV membership joins the in-memory snapshot to `advisory_cves`; it is required only when the caller asks for it.**
`inKev` binds the snapshot's ~1.7k CVE IDs as a single JSON array through `json_each(?)`: measured on the full index, 1.1 ms for the count against 1.4 ms with 1,717 bound parameters and 1.9 ms with a temp table per call, and it has no bound-variable ceiling or connection-scoped state. `kevCves` reuses the full CVE rows the page's 20-CVE preview is already cut from, so it adds no query — 0.04 ms on the heaviest possible page (4,875 membership rows) and 682 bytes of `structuredContent` / 1,646 of `content[]` on a blank 50-result page. Availability is split: `inKev` awaits the snapshot and fails retryably (`catalog_unavailable`), while an unrelated search reads only a snapshot already in memory and, without one, omits `kevCves` with a notice. Awaiting the snapshot there would put a KEV outage — up to a retried 30 s timeout — in front of every advisory search. Rejected: mirroring KEV into the SQLite index, which would add a second refresh path for data the process already holds.

**23. `cves` is the sub-section selector for `vulnerabilities`, and the outline lists the IDs to choose from.**
The framework's `selectSections` stops at top-level keys by design and leaves sub-section selection to the server. `cves` narrows `vulnerabilities` to the named entries and is validated against the advisory's own CVE list, both errors thrown in the handler so their recovery hints reach the caller. Listing the CVE IDs in both outline arms is what makes the selector usable; it costs up to ~9.3 KB per surface on the 544-CVE advisory, still under the budget. The outline element extends the framework's strip-mode schema instead of reusing it — reused verbatim, the parse would silently drop `cves`. Narrowing `products` the same way is separate work.

**24. `cisa_check_cve_status` shrinks a batch with a `detail: "summary"` projection, never a cap.**
A scan-result check needs every requested CVE back, so capping the list would drop answers, and lowering the 200 maximum would remove the batch the tool exists for. `summary` keeps the eleven triage fields (`cveId`, `inKev`, dates, `daysUntilDue`, `overdue`, `directive`, vendor and product labels, the ransomware and forensic-triage flags) and reuses `KevRecordSchema`, whose dropped fields were already optional. Measured on catalog `2026.09.24` over the 200 most recently added CVEs: `structuredContent` 308,063 → 52,734 bytes, `content[]` 298,391 → 60,958 bytes. `full` stays the default and byte-identical; the "this is a summary" disclosure rides a `summaryNote` enrichment written only under `summary`, so it never touches `full` output on either surface.

**25. Every URL in KEV `notes` becomes a reference; the prose around them stays whole.**
Upstream puts URLs in `notes` comma-joined, inside prose, in parentheses, and once with a `;` inside the URL — shapes the original `url` / `Label: url` split never read, which left 15 ED-era entries with no reference at all. The parser now extracts every URL, keeps notes order, trims sentence punctuation, and leaves prose segments verbatim with their URLs, because stripping the URLs would strand `()` and `please see:`. Labels attach only to the exact `Label: url` shape. Against catalog `2026.09.24`: references 2,947 → 3,252, entries with no `nvd` reference 15 → 0, entries with `notesCommentary` 166 → 122, and no existing reference lost. The parse stays linear in the length of `notes`, because `notes` is upstream text parsed on every catalog load: the `;` rejoin carries whether the last segment ends in a URL rather than rescanning the growing segment, and the punctuation trim is one backward pass against a paren balance counted once.

**26. The KEV zero-hit notice is computed from per-filter counts, and a `nameContains` with nothing to search is an error.**
Choosing fragments by which filters were present blamed filters that matched on their own, such as the vendor-label and CWE fragments on any call that set them. On a zero-hit result only, one pass over the snapshot counts each filter alone and what dropping it would restore; the notice names the filter that matches nothing — and, when it is the only one, what dropping it restores, which is nothing when the other filters also miss together — or else the filters whose removal restores results and how many. The directive and `overdue`/`dueAfter` fragments read the snapshot and the echoed `asOf` rather than a fixed 2026 threshold or the wall clock. A `nameContains` that folds to no token throws `empty_search_text` from the service, mirroring Decision 20: an empty result would claim nothing matched when nothing was searched. One that folds only part of the query away — `漏洞 siemens` — searches the surviving tokens and says so in a notice naming the dropped words and the tokens searched: the results are unchanged, since folded record text can never contain the dropped characters, but a silent drop let a widened query read as if every word had matched.

**27. Agent-facing text states no KEV count that changes with a catalog release.**
Static descriptions and `cisa_list_reference` topic `kev_fields` had carried figures like "58 entries" and "of 1,716" that went wrong with the next release. They now say "most" or "some" or nothing, and runtime text that needs a figure computes it from the loaded snapshot — the empty-`cwes` count in the zero-hit notice, for one. `kev_fields` drops its figures rather than reading the snapshot so the tool stays free of service dependencies (Decision 16); topic `sources` already reports the live `count`. Counts in this document are labeled with the catalog version they were measured on.

**28. The index defaults to the per-user cache directory, and a store that cannot be opened is a non-retryable `mirror_unavailable`.**
The old default, `.mirror/csaf.sqlite3`, resolved against the working directory, and some desktop clients start stdio servers at `/`: the seed failed, and every index read surfaced the raw `mkdir` errno — `NotFound`, `Forbidden`, or `InternalError` depending on the errno, the path in the message, and `resources/list` failing outright, KEV entries included. Unset, the path is now `csaf.sqlite3` under `cisa-cybersecurity-mcp-server` in `~/Library/Caches` (macOS), `%LOCALAPPDATA%` (Windows), or an absolute `$XDG_CACHE_HOME` else `~/.cache` — writable for the invoking user from any working directory, and "cache" is the right class because the index re-derives from one archive (measured from `cd /` with a temp `HOME`: seeded in 1.9 s). `defaultCsafMirrorPath()` takes the host as an argument, so tests never touch the real cache. The Docker image sets `CISA_CSAF_MIRROR_PATH` to its `.mirror` volume, which would otherwise stop persisting the index. No fallback reads an old `<cwd>/.mirror`: that would keep the cwd dependence, and a background re-seed costs nothing but time. The framework raises an open failure in three shapes — the raw `mkdir` errno (its `mkdir` runs outside its try), a `DatabaseError` whose cause is the driver error, and a raw SQLite error from the connection pragmas — so `classifyStoreOpenFailure` reads every `code` on the cause chain and maps it to `not_writable`, `read_only`, `missing_directory`, `not_a_directory` (`mkdir -p` reports `EEXIST` for a path through a file), or `not_a_database` (`SQLITE_NOTADB`, a file at the path that is not a SQLite database, which otherwise failed `resources/list` too); anything else, a busy lock included, rethrows rather than being reported as misconfiguration. `CsafMirrorService.availability()` is the catch point, so both tools and the resource throw one declared `ConfigurationError`, non-retryable because only an operator can fix it, whose recovery names `CISA_CSAF_MIRROR_PATH` and the tools that still work; `list()` and completion degrade to empty; `sources` carries `unavailableReason`. The path appears only in the server log. Rejected: anchoring on the package directory as the framework does for logs — per-version under `npx`, root-owned under a global install, wiped on `.mcpb` update — and `os.tmpdir()`, which re-seeds after every reboot.

**29. The advisory index refreshes once at boot and on schedule, on every transport, through one `maintain()` pass.**
Cron jobs were gated to HTTP on the theory that a stdio server is short-lived, but a desktop client keeps a stdio child up for its whole session, and under stdio nothing ever refreshed the index or the KEV snapshot after the first load: IDs from `cisa_get_alerts` missed in `cisa_get_advisory` indefinitely. Both jobs now register on every transport; the framework destroys them on every shutdown path, stdin EOF included (measured exit 20–60 ms after EOF). Boot and the scheduled job run the same `maintain({ autoInit, refresh })`: a never-synced or content-stale index seeds or re-ingests under auto-init and nothing otherwise — a refresh on an empty store would fetch all 3,937 documents one by one — and a synced, current index refreshes. The boot refresh covers the short launch that never reaches a tick. It runs in the background and costs one conditional request: measured over five interleaved stdio launches each, `initialize` answered at a median 324 ms with it and 313 ms with the cron `off` (ranges overlap), and the 304 refresh completed 48–63 ms after scheduling. The first refresh after a seed downloads the full manifest once (445 ms, nothing changed), because `init` does not record the manifest ETag. An index last synced 2026-09-19 applied 13 advisories in about 0.6 s at boot. Running the seed from the schedule too means a seed that failed or was skipped at boot is retried on the next tick instead of on the next start. `CISA_CSAF_MIRROR_AUTO_INIT` still gates only seed and re-ingest; the refresh cron's `off` disables both the schedule and the boot refresh. Rejected: refreshing only when the index is older than the interval — a cron is a schedule, not an interval, and `node-cron` exposes no previous fire time — for a saving of one 304.

**30. Two processes sharing one index never sync at once: a lease row, claimed under `BEGIN IMMEDIATE`, until the framework ships one.**
The per-user default puts every stdio session on one file, and `defineMirror`'s overlap guard is an in-process flag. `sync-lease.ts` keeps a `mirror_meta` row `sync_lease` holding `{ owner, mode, expiresAt }`; claim, renewal, and release each read and write it inside `BEGIN IMMEDIATE`, which takes SQLite's write lock before the read, so the check and the write are atomic across processes. The owner is `<hostname>/<pid>/<random>` per service instance. The TTL is 120 s and the holder renews every 30 s on an unref'd timer; a renewal that finds another owner aborts the holder's sync rather than letting two writers run, and a lease whose holder crashed is taken over once it expires. A process that finds a live lease — or its own sync already running, which replaces the framework's `Conflict` — logs one line, skips, and keeps serving reads; the scheduled pass retries a skipped seed. `close()` aborts an in-flight sync and releases the lease before the handle closes, so a stdio process that exits mid-refresh does not block the next launch for a TTL. The `mirror:init` and `mirror:refresh` scripts take the same lease and exit 0 when skipped. Measured with two stdio processes on one temp file: on an empty index one seeded (1.9 s) while the other logged the skip; on a synced one, one refreshed and the other skipped. The whole seed is shorter than the TTL, so the event loop never stalls long enough to miss a renewal. The row lives in the existing `mirror_meta` table, so no migration. Replace it with the primitive cyanheads/mcp-ts-core#517 tracks. Rejected: a lockfile beside the database, which goes stale on a crash and needs its own path handling.

**31. `off` disables a refresh cron; empty means the default; anything else `node-cron` rejects fails startup.**
The docs said an empty value disabled a schedule, but `parseEnvConfig` reads empty, whitespace-only, and unsubstituted `${…}` values as unset — deliberately, because the `.mcpb` host forwards `""` for every option left blank — so the default applied and the `trim() === ''` guard in the scheduler was unreachable. Meanwhile `off`, `none`, and a mistyped expression all "disabled" a job the same way: a warning and a server running without it. The cron schema now trims, reads `off` in any case as the disable value (matching the `on`/`off` vocabulary `z.stringbool()` accepts), and refines everything else against `node-cron`'s own `validate()` — the check `schedulerService.schedule` applies — so an invalid value fails startup with a `ConfigurationError` naming the variable. Keeping empty as the default matters more once schedules run on stdio (Decision 29): "empty disables" would switch refresh off for every `.mcpb` user who left the field blank.

**32. An advisory miss reports how current the index is, and says the advisory may be newer only when the date its ID encodes is after the last sync.**
A miss used to read as "no such advisory" even when the index was simply behind. `cisa_get_advisory`'s miss now carries `indexCheckpoint` and `indexLastSyncedAt`, and its guidance, like the resource's not-found, states both. The "may be newer than the index" note keys on the ID's own date — `20YY` plus day-of-year `DDD`, via `advisoryIdDate` — being strictly later than the UTC date of the last completed sync and not later than today; an out-of-range day gets no note. Not the checkpoint: it is the newest revision timestamp ingested, which trails the last sync (2026-09-17 against a 2026-09-19 sync on the probed index), so an ID dated between the two was published before a sync that did not find it. Not the document's `published` date either: a republished vendor advisory carries the vendor's earlier date there (the ID date is later for 873 of 1,063 republications). A same-day ID gets no note, which errs toward not claiming something new. The note links the advisory's cisa.gov page.

**33. The ICS zero-hit notice is computed from per-filter counts, in one aggregate query that shares the search's clauses.**
Fragments chosen by which filters were present blamed filters that matched on their own: across 400 seeded filter combinations on the full index, 151 of 210 zero-hit notices blamed a filter that matched alone — 82 of them asserting the corpus lacked a CVE or CWE it carries — and 61 never named the filter that matched nothing. The notice now follows Decision 26. On a zero-hit result only, `filterCounts` scores every applied filter in one statement. Each predicate is evaluated once per row into a flag column of a `MATERIALIZED` CTE, and the sums read the flags. Without `MATERIALIZED`, SQLite flattens the flags into every aggregate and re-runs the text matches once per sum: 118 ms against 26 ms with all sixteen filters. Both `search()` and the count query build from `filterClauses`, so the counts cannot drift from the search they explain. The one difference is `q`: `search()` matches it through the FTS join that bm25 ranking needs, and the count query matches it through a rowid subquery over the same `MATCH` expression. Re-run over the same seeded 400 combinations, the count query agreed with 1,356 brute-force searches across 209 misses, with no mismatch. The sector, `ICSMA`, and `inKev` fragments now fire only on an index where that filter matches nothing, which the full corpus never produces. `sectorCoverage` carries the sector disclosure on every sector call, and the drop-one counts replace the other two hints. On a content-stale index a `cwe` that matches nothing is withheld, as are the count sentences that would lean on it. Rejected: skipping the query for a single-filter miss, which would save 0.6 ms at the cost of a second code path, and 2n `COUNT(*)` queries, which scan once per filter.

**34. Agent-facing text states no advisory-corpus count, and the coverage figures follow the index after every sync.**
The ICS tool description, the `cve`, `series`, and `publisher` inputs, the `maxCvss` output, and topics `sectors`, `advisory_id_formats`, and `severity_bands` stated figures ("3,926 CSAF 2.0 documents", "(2,863)", "the two advisories") that went wrong with every refresh. Tool and field schemas are built at registration, before the index can seed, and the static topics stay free of service reads (Decision 16), so those figures are dropped rather than read, as Decision 27 did for KEV. Topic `sources` already reports the live `documentCount`. Runtime text reads the index: the zero-hit figures come from `filterCounts`, and the coverage notices come from `coverageCounts()`. That memo was kept for the life of the process, so a refresh left it stale. The coverage scan costs 3 ms, so it is still memoized, now keyed on `completedAt` from the index's own sync state (a 0.01 ms read). A sync by this process, by another server process sharing the index, or by `mirror:refresh` replaces the memo without a restart. Its figures are thousands-grouped like the KEV notices. A row edit made outside a sync is not picked up until the next one. The CSAF counts in this document are labeled with the index checkpoint they were measured on.

**35. `nameContains` spells the fifteen Latin letters NFKD cannot decompose the CLDR Latin-ASCII way, on both sides.**
NFKD leaves `ß æ ð ø þ đ ħ ı ĸ ł ŀ ŉ ŋ œ ŧ` (U+00C0–U+017F) outside a-z, so the `[^a-z0-9]` sweep turned each one into a separator. The fragments on either side then matched as substrings: `Straße` searched `stra e` and returned 88 entries through "administrator", and `Ærø` searched `r` and returned the whole catalog. `normalizeText` now replaces them after lowercasing and before NFKD, which would otherwise split `ŀ` and `ŉ`. The spellings are CLDR's `ß`→`ss`, `æ`→`ae`, `þ`→`th`, `œ`→`oe`, and so on, with one exception: `ŉ` becomes `n` rather than `'n`, because the apostrophe would split the word. Capitals, `ẞ` included, reach the table lowercased. Record text passes through the same function, so matching stays symmetric. `queryTokens` checks for dropped letters after the same fold, so `Straße` and `Øre` are no longer reported as dropped, while `漏洞` and a Latin letter outside the table such as `ƒ` still are. Plain ASCII and NFKD-decomposable queries return byte-identical results on catalog `2026.09.24`, and no KEV record at that version contains one of the fifteen letters. The table stops at Latin Extended-A: 791 of 1,453 Latin-script letters have no a-z fold, mostly IPA and later extensions, and the dropped-word notice covers those. Rejected: dropping one-character tokens. The widening came from multi-letter fragments, and a caller's `7` or `x` is a real token. ICS `q` needs no fold: FTS5 `unicode61` keeps these letters inside a token on both drivers.

**36. `vendor` and `product` fold case the same way on both sides, through `GLOB`, under the 512-character ceiling.**
The filters compared SQLite's `LOWER(column)`, which folds A-Z only, against a needle lowercased in JavaScript, so a stored non-ASCII capital never matched. At the 2026-09-24 checkpoint that hit five labels, all double-encoded upstream (`GeutebrÃ¼ck` 6 advisories, `LeÃ£o` 10, `WeidmÃ¼ller`, `YhtymÃ¤`, `nÂ°`), and a label copied from a result matched nothing. `toSubstringGlob` builds a `GLOB` pattern against `LOWER(column)`:
- A-Z is lowered to meet `LOWER()`.
- Every other letter with a single-character case pair becomes a class of both forms (`Ã` → `[Ãã]`).
- `*`, `?`, and `[` become one-character classes.
- `%`, `_`, and `\` need no escaping, because GLOB has no wildcard or escape character for them.

`GeutebrÃ¼ck`, `geutebrÃ¼ck`, and `geutebrã¼ck` all return the 6. `WEIDMÜLLER` still matches a stored `ü`, and `Siem_ns` and `S%s` still return 0. The scan costs the same as the `LIKE` it replaces. SQLite refuses a `LIKE` or `GLOB` pattern over 50,000 bytes with a raw `SqliteError`. The old `LIKE` reached that limit at 50,000 ASCII characters, and a class per letter reaches it at about 8,300, so both filters now take the shared `assertSearchTextLength` ceiling and fail as `search_text_too_long`. Rejected:
- A stored case-folded column: it needs a migration and a content-version bump, which means a full re-ingest on every install for five labels.
- Folding only the needle to ASCII: it regresses an uppercase-typed `Ü` against a stored `ü`.
- A custom SQLite function: the framework's `SqliteHandle` has no registration hook.

Repairing the upstream mojibake, so that `Geutebrück` matches, is not attempted.
