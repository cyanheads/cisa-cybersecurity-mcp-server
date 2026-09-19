# cisa-cybersecurity-mcp-server — Design

Package `@cyanheads/cisa-cybersecurity-mcp-server` · registry `io.github.cyanheads/cisa-cybersecurity-mcp-server` · display and machine identity `cisa-cybersecurity-mcp-server` · tool prefix `cisa_`.

Upstream shapes in this document were verified against the live sources on 2026-09-19. Every count, field name, header behavior, and size is an observation, not a restatement of upstream documentation.

---

## MCP Surface

### Tools

| Name | Description | Key Inputs | Annotations |
|:-----|:------------|:-----------|:------------|
| `cisa_list_reference` | Decode the vocabulary the rest of the surface takes as input: BOD 26-04 remediation timelines, KEV field meanings, SSVC decision-point values, critical-infrastructure sector names, advisory ID formats, CVSS severity bands, and live data provenance. | `topic` | `readOnlyHint`, `openWorldHint: false` |
| `cisa_check_cve_status` | Check up to 200 CVE IDs against the CISA Known Exploited Vulnerabilities catalog in one call, returning federal remediation deadlines, overdue status, ransomware and forensic-triage flags, and the directive each entry cites. | `cveIds[]` | `readOnlyHint` |
| `cisa_search_kev` | Search the KEV catalog by vendor, product, CWE, date added, due date, overdue status, ransomware use, forensic-triage tier, or directive. | filters, `sortBy`, `limit`, `cursor` | `readOnlyHint` |
| `cisa_get_ssvc` | Fetch the SSVC decision points CISA publishes per CVE — Exploitation, Automatable, Technical Impact — and compute the BOD 26-04 remediation timeline they imply for a stated asset exposure. | `cveIds[]`, `assetExposure` | `readOnlyHint` |
| `cisa_search_ics_advisories` | Search the CISA industrial control system advisory corpus by vendor, product, CVE, CVSS range, severity, sector, series, or free text over advisory titles and product names. | `q`, filters, `sortBy`, `limit`, `cursor` | `readOnlyHint` |
| `cisa_get_advisory` | Read one ICS advisory in full: affected products with version ranges, per-CVE CVSS and CWE, remediations, sectors, and revision history. | `advisoryId`, `sections[]` | `readOnlyHint` |
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
- **ICS advisories in CSAF 2.0** — 3,926 machine-readable advisories covering PLC, HMI, SCADA, building-automation, and medical-device products, spanning 2010 to today.

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

| Property | Observed |
|:---|:---|
| Size | 1,735,385 bytes raw; 191,922 bytes with `Accept-Encoding: gzip` (`content-encoding: gzip`, `vary: Accept-Encoding`) |
| Envelope | `{ title, catalogVersion, dateReleased, count, vulnerabilities[] }` — `catalogVersion "2026.09.18"`, `count 1716` |
| Record fields | `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `forensicTriage`, `notes`, `cwes` — all 12 present on 100% of 1,716 records |
| Published schema | `…/known_exploited_vulnerabilities_schema.json`, 3,623 bytes, draft-07. Marks only 8 fields `required`; the other 4 are schema-optional but universal in practice. **It now documents `forensicTriage`.** No `additionalProperties: false` |
| `knownRansomwareCampaignUse` | `Known` 360 / `Unknown` 1,356 |
| `forensicTriage` | `Yes` 58 / `No` 1,658 |
| `cwes` | Empty array on 175 records; up to 4 entries; pattern `^CWE-([0-9])+$` |
| `notes` | Never empty. `;`-delimited. 100% carry an `https://nvd.nist.gov/vuln/detail/<CVE>` URL. Median 2 URLs, max 11. 116 records open with prose. Labeled segments observed: `BOD 26-04:` (99), `Forensics Triage Requirements:` (99), `CISA Mitigation Instructions:` (13), `Additional References:` (3) |
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
| Advisory IDs | `tracking.id` is uppercase (`ICSA-10-316-01A`); the filename is lowercase. Suffix forms: none (3,805), a letter `a`–`f` (120), and **one numeric form, `ICSA-16-231-01-0`** |
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
- `sources` → `kev` (`catalogVersion`, `dateReleased`, `count`, `lastCheckedAt`, `lastModified`, `refreshCron`), `csafMirror` (`ready`, `documentCount`, `checkpoint`, `syncStatus`, `lastCompletedAt`, `path`), `vulnrichment` (`mode: 'on_demand'`, `cacheTtlSeconds`), `feeds` (`windowItems: 30`, per-feed `oldest`/`newest` when cached).

`sources` reads in-process state only — the KEV snapshot, the mirror's `status()`, and cached feed windows. It makes no network call, which is what keeps it callable while another tool is failing. That is why `openWorldHint` is `false` for the whole tool.

**Errors** — none declared. Every topic is answerable from local state; a cold `sources` reports `ready: false` and `catalogVersion: null` rather than failing.

---

### `cisa_check_cve_status`

**Description**

> Check CVE IDs against the CISA Known Exploited Vulnerabilities catalog — up to 200 per call, served from a cached catalog snapshot at no upstream cost. Returns, per CVE, whether it is in KEV and if so the date added, the federal remediation due date, days remaining or days overdue, which binding operational directive the entry cites, the required action text, whether it is linked to ransomware campaigns, whether it falls in the three-day forensic-triage tier, CISA's own vendor and product labels, associated CWEs, and the reference URLs parsed from the entry's notes. A CVE that is not in KEV is a normal result, not an error. The CWE IDs returned chain directly into CWE-filtered CVE search elsewhere, and the parsed NVD reference gives the canonical record for scoring detail.

| Param | Type | Maps to | Notes |
|:---|:---|:---|:---|
| `cveIds` | `z.array(z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/)).min(1).max(200)` | local index lookup | Pattern is the one the published KEV schema declares. Input normalization: uppercase the `cve` prefix and trim surrounding whitespace — both are one-to-one and meaning-preserving. Nothing else is repaired. |

**Output**

```
results[]:
  cveId, inKev
  # present when inKev
  dateAdded, dueDate, daysUntilDue, overdue
  directive            'BOD 26-04' | 'BOD 22-01' | null
  requiredAction, vulnerabilityName, shortDescription
  vendorProject, product
  knownRansomwareCampaignUse   'Known' | 'Unknown'
  forensicTriage               'Yes' | 'No'
  cwes[]
  references[]: { kind: 'nvd'|'cisa'|'bod_guidance'|'forensic_triage'|'vendor'|'other',
                  label?, url }
  notesCommentary?     free prose from notes, when the entry opens with prose
  kevUrl
foundCount, notFoundCount
```

`directive` is three-state on purpose: 1,277 of 1,716 entries cite no directive at all in their `requiredAction` or `notes`, and `null` is the honest value for those. Never infer 22-01 from an entry's age.

`notes` parsing: split on `;`, trim. A segment matching `^<Label>:\s*<url>` yields `{ label, url }` with `kind` from the label (`BOD 26-04` → `bod_guidance`, `Forensics Triage Requirements` → `forensic_triage`, `CISA Mitigation Instructions` → `cisa`). A bare URL is classified by host (`nvd.nist.gov/vuln/detail/` → `nvd`, `*.cisa.gov` → `cisa`, else `vendor`). Non-URL text becomes `notesCommentary`.

**Enrichment**

| Key | Kind | When |
|:---|:---|:---|
| `catalog` | `echo` | Always — `{ catalogVersion, dateReleased, count, fetchedAt }` |
| `asOf` | `echo` | Always — the UTC date `daysUntilDue` and `overdue` were computed against |
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
| `vendorProject` | `z.string().min(2).optional()` | Case-insensitive substring match on CISA's own vendor label. 283 distinct values. |
| `product` | `z.string().min(2).optional()` | Case-insensitive substring match. 694 distinct values. |
| `nameContains` | `z.string().min(2).optional()` | Strict token match over `vulnerabilityName` + `shortDescription`: normalize both sides (lowercase, strip punctuation), require every query token to appear. No fuzzy fallback — an LLM caller does not need typo tolerance, and a wrong record is worse than a miss. |
| `cwe` | `z.string().regex(/^CWE-[0-9]+$/).optional()` | Exact match against any member of `cwes[]`. |
| `cveIdPrefix` | `z.string().regex(/^CVE-[0-9]{4}$/).optional()` | Year scope, e.g. `CVE-2026`. |
| `dateAddedFrom` / `dateAddedTo` | `z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional()` | Inclusive. |
| `dueBefore` / `dueAfter` | `z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional()` | Inclusive. |
| `overdue` | `z.boolean().optional()` | `dueDate` strictly before the echoed `asOf` date. |
| `ransomware` | `z.boolean().optional()` | `true` selects `knownRansomwareCampaignUse === 'Known'` (360 entries). |
| `forensicTriage` | `z.boolean().optional()` | `true` selects `forensicTriage === 'Yes'` (58 entries), the BOD 26-04 three-day forensic-triage tier. |
| `directive` | `z.enum(['BOD 26-04','BOD 22-01','none']).optional()` | `none` selects entries citing neither (1,277 entries). |
| `sortBy` | `z.enum(['dueDate','dateAdded']).default('dateAdded')` | |
| `order` | `z.enum(['asc','desc']).default('desc')` | |
| `limit` | `z.number().int().min(1).max(100).default(25)` | |
| `cursor` | `z.string().optional()` | Opaque, from `extractCursor`/`paginateArray`. |

All filters AND together. Every one is applied against the complete snapshot, never a page.

**Output** — `results[]` (the same record shape as `cisa_check_cve_status`), `cursor?`, `hasMore`.

**Enrichment**

| Key | Kind | When |
|:---|:---|:---|
| `total` | `total` | Always — matches before paging |
| `truncated` | `truncated` | When the `limit` cap was hit (`{ shown, cap }`) |
| `catalog` | `echo` | Always |
| `asOf` | `echo` | Always — a server-applied default that changes what `overdue` and `daysUntilDue` mean |
| `appliedFilters` | `echo` | Always — the filters as the server parsed them |
| `snapshotCaveat` | `notice` | When `dateAddedFrom` is set — "Additions are queryable by dateAdded. The KEV feed carries no per-record modified timestamp, so an entry whose dueDate or requiredAction changed after it was added is indistinguishable from an unchanged one. This result covers additions in the window, not revisions." |
| `notice` | `notice` | Zero hits. Composed from condition → fragment (below) |

Zero-hit notice fragments, each routing to a concrete next call:

| Condition | Fragment |
|:---|:---|
| `vendorProject` or `product` set | "Vendor and product are CISA's own free-text labels, not CPE names — call cisa_list_reference with topic kev_fields for the value domain, or drop the filter and match on nameContains instead." |
| `cwe` set | "No KEV entry carries that CWE. 175 of 1,716 entries carry an empty cwes array, so a CWE filter excludes them regardless of relevance." |
| `directive: 'BOD 26-04'` with a date window before 2026 | "BOD 26-04 entries begin in 2026; earlier entries cite BOD 22-01 or no directive at all." |
| `overdue: true` with a `dueAfter` in the future | "overdue and dueAfter are contradictory as given — relax one." |
| No filter explains it | "No KEV entry matches. Relax the narrowest filter, or call cisa_check_cve_status if you already have specific CVE IDs." |

**Errors**

| reason | code | when | recovery |
|:---|:---|:---|:---|
| `catalog_unavailable` | `ServiceUnavailable` (`retryable: true`) | No snapshot held and the fetch failed | `The KEV catalog snapshot is not loaded yet; retry in a few seconds, or call cisa_list_reference with topic sources to see the current catalog state.` |
| `invalid_date_range` | `ValidationError` | A `From` bound is later than its `To` bound | `Swap the range bounds so the From date is not later than the To date, then call this tool again.` |

---

### `cisa_get_ssvc`

**Description**

> Fetch the SSVC decision points CISA publishes per CVE as a CVE Authorized Data Publisher — Exploitation, Automatable, and Technical Impact — along with the CVSS score and CWE CISA contributes where present, and compute the BOD 26-04 remediation timeline those values imply for the asset exposure you supply. The computed timeline applies CISA's published decision table to CISA's published decision points and your stated exposure; it is not a compliance determination and it is not CISA's own due-date assignment, which is reported separately when the CVE is in KEV and can differ. Not every CVE is enriched — a miss returns found false with guidance rather than an error. Call cisa_list_reference with topic ssvc_values for the decision-point vocabulary.

| Param | Type | Notes |
|:---|:---|:---|
| `cveIds` | `z.array(z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/)).min(1).max(50)` | Cap 50, not 200: each CVE is a separate upstream file fetch. Fetched with a concurrency limit of 6 and `Promise.allSettled`. |
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

> Search the CISA industrial control system advisory corpus — 3,926 CSAF 2.0 documents covering PLC, HMI, SCADA, building-automation, and medical-device products from 2010 onward. Filter by vendor, product, CVE, CVSS range, severity band, critical-infrastructure sector, advisory series, publication date, or revision date, and run full-text search over advisory titles and product names. Sector filtering reaches only advisories that carry a sector note, which begins in 2017; the response reports how many documents a sector filter can never match. Returns advisory IDs for cisa_get_advisory, the CVEs each advisory covers, and the source URL and attribution every advisory response carries.

| Param | Type | Notes |
|:---|:---|:---|
| `q` | `z.string().min(2).optional()` | Full text over `title`, `vendorsText`, `productsText`. Translated to an FTS5 `MATCH` expression: tokens are quoted and AND-joined, so reserved FTS5 syntax in caller input cannot alter the query. |
| `vendor` | `z.string().min(2).optional()` | Case-insensitive substring over the `vendorsText` column. Vendor names are unnormalized upstream — `GE` and `General Electric (GE)` are distinct labels — so this is substring, not exact. |
| `product` | `z.string().min(2).optional()` | Case-insensitive substring over `productsText`. |
| `cve` | `z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/).optional()` | Exact membership in the advisory's CVE set, via an indexed junction table. |
| `cvssMin` / `cvssMax` | `z.number().min(0).max(10).optional()` | Against the advisory's computed `maxCvss`. |
| `severity` | `z.enum(['NONE','LOW','MEDIUM','HIGH','CRITICAL']).optional()` | Band of `maxCvss`. |
| `sector` | `z.enum([…16 canonical sectors…, 'Multiple']).optional()` | Matches the normalized sector set. |
| `series` | `z.enum(['ICSA','ICSMA']).optional()` | 3,738 ICSA, 188 ICSMA. |
| `publisher` | `z.enum(['coordinator','other']).optional()` | `coordinator` = CISA-authored (2,863), `other` = republished vendor advisory (1,063). |
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
  maxCvss?: { score, severity, version, severityDerived }
  sectors[]                  # normalized canonical names
  sectorsRaw?                # the note text verbatim, when present
  published, revised, revision, publisherCategory
  url                        # cisa.gov web version
  csafUrl                    # raw CSAF JSON
  attribution                # see Licensing
cursor?, hasMore
```

`maxCvss` is computed as the maximum `baseScore` across every `vulnerabilities[].scores[].cvss_v3|cvss_v2` entry — `document.aggregate_severity` exists on only 52 of 3,926 documents and is never relied on. For a `cvss_v2`-only advisory the upstream carries no `baseSeverity`, so the band is derived from the CVSS v2 thresholds and flagged `severityDerived: true`. Two advisories carry no CVSS at all and have no `maxCvss`.

**Enrichment**

| Key | Kind | When |
|:---|:---|:---|
| `total` | `total` | Always |
| `truncated` | `truncated` | Cap hit |
| `appliedFilters` | `echo` | Always |
| `mirror` | `echo` | Always — `{ documentCount, checkpoint, lastRefreshedAt }` |
| `sectorCoverage` | `notice` | Whenever `sector` is set — "729 of 3,926 advisories carry no sector note and cannot match a sector filter. Coverage begins in 2017 and is complete from 2023; every advisory published before 2017 is excluded by this filter regardless of which sectors it affects." |
| `cvssCoverage` | `notice` | Whenever `cvssMin`, `cvssMax`, or `severity` is set — "392 advisories score only in CVSS v2, where the upstream publishes no severity label and the band is derived. Two advisories carry no CVSS score and cannot match a score filter." |
| `notice` | `notice` | Zero hits |

Zero-hit notice fragments:

| Condition | Fragment |
|:---|:---|
| `vendor` set | "Vendor names are the advisory's own labels and are not normalized — the same company appears under several spellings. Try a shorter substring, or search with q instead." |
| `sector` set | "Sector coverage begins in 2017; 729 advisories carry no sector note at all. Drop the sector filter to reach them." |
| `series: 'ICSMA'` | "ICSMA covers medical devices and is 188 of 3,926 advisories. Drop the series filter to include ICSA." |
| `cve` set | "No ICS advisory covers that CVE. The corpus covers 12,321 distinct CVEs; call cisa_check_cve_status to see whether it is in KEV instead." |
| No filter explains it | "No advisory matches. Relax the narrowest filter, or call cisa_list_reference with topic sectors or advisory_id_formats for the value vocabulary." |

**Errors**

| reason | code | when | recovery |
|:---|:---|:---|:---|
| `mirror_not_ready` | `ServiceUnavailable` (`retryable: true`) | The advisory mirror has never completed a full sync | `The ICS advisory index is still building; call cisa_list_reference with topic sources to check its progress, then retry this search.` |
| `invalid_cvss_range` | `ValidationError` | `cvssMin` exceeds `cvssMax` | `Set cvssMin to a value no greater than cvssMax, then call this tool again.` |
| `invalid_date_range` | `ValidationError` | A `From` bound is later than its `To` bound | `Swap the range bounds so the From date is not later than the To date, then call this tool again.` |
| `relevance_sort_without_query` | `ValidationError` | `sortBy` is `relevance` but `q` was not supplied — there is no bm25 rank to sort by | `Add a q value to sort by relevance, or choose a different sortBy such as revised, published, or maxCvss.` |

---

### `cisa_get_advisory`

**Description**

> Read one CISA industrial control system advisory in full: affected products flattened from the CSAF product tree into vendor, product, and version ranges; per-CVE CVSS score, vector, and CWE; remediations with their category and vendor instructions; critical-infrastructure sectors; and the revision history. Large advisories return a section outline instead of the whole document — re-call with the sections you need. Republished vendor advisories carry the originating vendor's text; every response reports the source URL and attribution. Find advisory IDs with cisa_search_ics_advisories.

| Param | Type | Notes |
|:---|:---|:---|
| `advisoryId` | `z.string().regex(/^ICS(A\|MA)-\d{2}-\d{3}-\d{2}(?:[a-z]\|-\d+)?$/i)` | **Case-insensitive, and the suffix arm covers both real forms.** 120 advisories carry a letter suffix (`a`–`f` observed) and one carries a numeric suffix (`ICSA-16-231-01-0`). Input normalization: uppercase, trim, and strip a trailing `.json` — each is one-to-one and meaning-preserving. |
| `sections` | `z.array(z.enum(['advisory','summary','products','vulnerabilities','revisionHistory','references','acknowledgments'])).optional()` | Omit for the whole document, or the outline when it overflows. |

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
                truncated?, shownProducts }
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
sections?        # outline arm: OUTLINE_VARIANT.shape.sections
notice?          # outline arm
guidance?        # present when found is false
```

`format()` renders each arm on field presence with independent `if` blocks — never a branch on `kind` — so parity holds against the linter's all-fields-populated sample.

**Outline behavior.** `outlineOnOverflow(doc, { budget: 24_000 })` on the disclosure path; `selectSections(doc, input.sections, { alwaysKeep: ['advisory'] })` on the selection path. 783 of 3,926 advisories exceed 24 KB and 102 exceed 100 KB, with the largest at 1.38 MB (544 vulnerability entries, 585 products) — truncating those silently is not an option and returning them whole burns the caller's context. The re-call is stateless: the mirror lookup is deterministic, so the handler re-reads the row and projects it.

The `products` arm additionally caps at 200 flattened version rows with `truncated` and `shownProducts` disclosed, because a single advisory can carry 585 products and the outline treats `products` as one indivisible section.

**Product-tree flattening.** Walk `product_tree.branches` recursively, carrying the branch-category path. `vendor` opens a vendor; `product_family` and `product_name` build the product label; `product_version` and `product_version_range` become version entries tagged with their `kind`; `specification`, `service_pack`, and `patch_level` (7 occurrences total) append to the version label. A leaf's `product.product_id` is the `CSAFPID-*` token the vulnerability entries reference, so it is kept — it is how a caller maps a CVE to the exact affected versions.

**Sector extraction.** Read `document.notes[]` for the entry whose title, lowercased with whitespace collapsed, is `critical infrastructure sectors`. Match the raw text against the 16 canonical sector names plus a small alias table, longest-name-first, consuming each match. This is the only correct approach: the note is free-form prose, two canonical names contain the word "and", and `Nuclear Reactors, Materials, and Waste` contains commas — so splitting on separators produces garbage tokens. Validated against the whole corpus: 75.1% of sector notes resolve to at least one canonical name, 24.7% are the `Multiple` sentinel, and 5 documents of 3,201 fail entirely on upstream typos. `sectorsRaw` retains the verbatim text in every case.

**Errors**

| reason | code | when | recovery |
|:---|:---|:---|:---|
| `mirror_not_ready` | `ServiceUnavailable` (`retryable: true`) | The advisory mirror has never completed a full sync | `The ICS advisory index is still building; call cisa_list_reference with topic sources to check its progress, then retry this lookup.` |
| `unknown_section` | `ValidationError` | `sections` names a key this advisory does not carry | `Call this tool without sections to get the outline of the sections this advisory actually has, then request those by name.` |

A miss is a result, not an error: `{ found: false, guidance: "No advisory with that ID is in the index. IDs look like ICSA-26-260-07 or ICSMA-26-253-02, with an optional revision suffix. Call cisa_search_ics_advisories to find the right ID, or cisa_list_reference with topic advisory_id_formats for the format." }`

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
| `echo` | `echo` | When `since` is set — the applied value and how many of the 30 it excluded |
| `truncated` | `truncated` | When `limit` < window size |
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
| `cisa://advisory/{advisoryId}` | `advisoryId` (same regex as `cisa_get_advisory`) | Returns one flattened advisory. Applies the same `outlineOnOverflow(doc, { budget: 24_000 })` treatment as `cisa_get_advisory`'s no-`sections` call — a resource template has no `sections` parameter to request a follow-up with, so a caller who lands on the outline arm for the largest advisories (up to 1.38 MB) uses `cisa_get_advisory` to pull named sections. `list()` → the 30 most recently revised advisories. | `{ ttlMs: 21_600_000, cacheScope: 'public' }` | `cisa_get_advisory` |

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
| Timeouts | `fetchWithTimeout`, default 30 s, `CISA_HTTP_TIMEOUT_MS` overridable. Every fetch forwards `ctx.signal`. |

### API efficiency

There is no upstream search, batch, or field-selection endpoint anywhere. Efficiency comes from the storage tiers, not from query shaping:

- KEV: one file serves every membership check, filter, and sort. A 200-CVE batch costs zero upstream requests.
- CSAF: one archive seeds 3,926 documents; refresh reads one 228 KB manifest and fetches only the documents whose timestamp moved.
- Vulnrichment: one file per CVE is the only access path the source offers; the TTL cache is what keeps a repeated triage loop from re-fetching.
- Feeds: one fetch per feed per TTL window, shared across all callers.

---

## Storage tiers and refresh

### Tier 1 — KEV, in-memory, process-level

1,716 records and 1.74 MB sit far below the mirror tier's floor, and the data is public and byte-identical for every tenant, so one process-level snapshot is shared — no `ctx.state`, no tenant scoping.

Held per refresh: the parsed records, the raw envelope metadata (`catalogVersion`, `dateReleased`, `count`), `fetchedAt`, the upstream `last-modified`, and derived indexes — `Map<cveId, record>`, plus sorted arrays by `dateAdded` and `dueDate`.

**Refresh** uses `If-Modified-Since` with the stored `last-modified`, sent with `Accept-Encoding: gzip`. A no-change poll is a 304 with zero bytes; a change costs 192 KB on the wire. **`If-None-Match` is not used**: the origin serves an ETag but ignores it on conditional requests and returns the full 1.74 MB body every time. Scheduled via `schedulerService` in `setup()`, default `*/30 * * * *`. The catalog updates on business days, so 48 polls a day is ~2 changed fetches and 46 empty ones.

**Cold start** is single-flight: `setup()` kicks the first load off without awaiting it, and a request arriving before it lands awaits the same in-flight promise rather than starting a second fetch. The observed fetch is ~80 ms, so the first request blocks briefly rather than failing. If the load fails and no snapshot is held, the tools throw `catalog_unavailable`; if a snapshot is held, a failed refresh logs a warning and the previous snapshot keeps serving — a stale catalog beats no catalog, and `cisa_list_reference` topic `sources` exposes `lastCheckedAt` so the staleness is visible rather than silent.

### Tier 2 — CSAF advisories, SQLite mirror

3,926 documents and 94.6 MB land squarely in the `MirrorService` tier. One table, FTS5 over the searchable text, one junction table for CVE membership, one for sectors.

```ts
{
  path: config.csafMirrorPath,
  table: 'ics_advisories',
  primaryKey: 'advisoryId',
  version: 1,
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
    document: 'TEXT',        // the normalized advisory, JSON
  },
  fts: ['title', 'vendorsText', 'productsText'],
  indexes: [
    { columns: ['series'] }, { columns: ['maxCvss'] },
    { columns: ['published'] }, { columns: ['revised'] },
    { columns: ['publisherCategory'] },
  ],
}
```

Two auxiliary tables via a `migrations` step (`CREATE TABLE IF NOT EXISTS`, so a fresh database and an upgrade run identically): `advisory_cves(advisoryId, cve)` and `advisory_sectors(advisoryId, sector)`, each indexed on the second column. Exact CVE and sector membership is what they buy — scanning a delimited text column for either is both slow and wrong (`Water` is a substring of `Wastewater`). They are maintained from the ingester's mapping, reached through `mirror.raw()`.

`document` holds the normalized advisory JSON rather than the raw CSAF: the flattening, sector extraction, and CVSS computation run once at ingest, not per read. It also means `cisa_get_advisory`'s section outline measures what it actually returns.

**Ingest (`mode: 'init'`).** One `GET` of the repository tar.gz (11.4 MB, ~1.5 s), streamed and decompressed in memory, entries under `csaf_files/OT/white/*/*.json` parsed and normalized, yielded in pages of 200 with `checkpoint` set to the maximum `current_release_date` seen so far. Filenames are `icsa-*.json` / `icsma-*.json` — never digit-led — so the entry filter is a `.json` suffix match, which also excludes the `.json.asc` and `.json.sha512` sidecars every document ships alongside without any extra exclusion rule. The archive is the seeding path because 3,926 individual `raw.githubusercontent.com` requests is the alternative.

**Refresh (`mode: 'refresh'`).** Conditional `GET` of `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv` with `If-None-Match` — `raw.githubusercontent.com` honors it, so an unchanged poll is a 304 on a 228 KB file. When it changes, parse all 3,926 rows (accepting both the quoted-with-microseconds and unquoted-with-seconds forms the distributions use), diff against the stored `revised` values, fetch only the documents whose timestamp moved, and emit tombstones for paths present in the store but absent from the manifest. `changes.csv` is a full manifest rather than an append-only log, which makes deletions detectable — the reason it is the refresh source instead of the checkpoint alone. Scheduled at `17 */6 * * *` under HTTP transport; stdio operators run `mirror:refresh` out of band.

**Read gating.** Every mirror read is gated on `await mirror.ready()`, which is true once a full sync has *ever* completed — so a mirror mid-refresh, or one whose last refresh failed, keeps serving. There is no live fallback: the corpus only exists as 3,926 individual files, and fanning out per query is not a serving strategy. A never-seeded mirror throws `mirror_not_ready`.

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
| `CISA_KEV_REFRESH_CRON` | No | `*/30 * * * *` | Cron for the KEV conditional-refresh poll. HTTP transport only; empty disables the in-process schedule. |
| `CISA_CSAF_MIRROR_PATH` | No | `.mirror/csaf.sqlite3` | Filesystem path to the ICS advisory index. |
| `CISA_CSAF_MIRROR_AUTO_INIT` | No | `true` | `z.stringbool()`. When true and the mirror has never completed a sync, seed it in the background at startup. Set false where seeding runs out of band. |
| `CISA_CSAF_REFRESH_CRON` | No | `17 */6 * * *` | Cron for the incremental advisory refresh. HTTP transport only; empty disables it. |
| `CISA_VULNRICHMENT_CACHE_TTL_SECONDS` | No | `21600` | TTL for a cached SSVC record. Negative results use one sixth of this. |
| `CISA_FEED_CACHE_TTL_SECONDS` | No | `900` | TTL for a parsed RSS window. |
| `CISA_HTTP_TIMEOUT_MS` | No | `30000` | Per-request timeout for every upstream fetch. |

`z.stringbool()` for the boolean, never `z.coerce.boolean()` — `Boolean("false")` is `true`, so a coerced flag cannot be turned off from the environment.

**Packaging parity.** `lint:packaging` requires the same names in `server.json` `environmentVariables[]` and `manifest.json` `mcp_config.env` + `user_config`. All seven are optional strings, so each `user_config` entry carries `"default": ""` and each is wired as `"CISA_X": "${user_config.cisa_x}"`.

**Dependencies.** `better-sqlite3` is added to `dependencies` (see Decision 2), and `scripts/_mirror-context.ts` plus the three `csaf-mirror-*.ts` lifecycle scripts are added to `package.json` `files[]` so the npm tarball and the bundle carry them.

**Session posture.** `createApp({ sessionMode: 'stateless' })`. No handler returns `ctx.requestInput`, so nothing needs a durable session.

---

## Server Instructions

Draft for `createApp({ instructions })`:

> This server serves four CISA datasets, all keyless and all read-only. Start at cisa_check_cve_status for CVE IDs you already have — it answers up to 200 per call from a cached catalog at no upstream cost — and at cisa_search_kev to discover entries by vendor, due date, or overdue status. cisa_get_ssvc adds the SSVC decision points CISA publishes per CVE and computes the BOD 26-04 remediation timeline they imply for an asset exposure you supply; that computation is CISA's published decision logic applied to CISA's published inputs, not a compliance determination. ICS advisories are served from a local index of the full CSAF corpus back to 2010 — search it with cisa_search_ics_advisories, read one with cisa_get_advisory. The index seeds itself on first run; until it finishes, the two ICS tools report that state and every other tool works normally. cisa_list_reference decodes the vocabulary the rest of the surface takes as input and reports what data this server currently holds. The KEV catalog records additions but no per-record modification timestamp, so "what changed" questions are answerable for additions only.

---

## Test seams

| Seam | What it enables |
|:---|:---|
| `createFetchMock(routes)` from `/testing` | Every upstream boundary. Each service reaches the network only through `fetchWithTimeout`, so one fake covers all four. |
| `initKevCatalog({ now })` | An injected clock. `overdue`, `daysUntilDue`, and the echoed `asOf` are the only time-dependent outputs on the surface; without this they are untestable. |
| `initCsafMirror({ mirrorPath })` | A per-test temporary file. `openSqliteHandle` creates the parent directory, so a `tmpdir()` path is enough; no shared fixture database. |
| Pure functions, no I/O | `parseKevNotes`, `classifyReference`, `resolveBod2604Timeline` (the Table 1 lookup), `extractSectors`, `flattenProductTree`, `computeMaxCvss`, `deriveCvssV2Severity`, `normalizeAdvisoryId`, `parseChangesCsv`, `stripFeedHtml`, `cveToVulnrichmentPath`. Each is unit-testable against a fixture with no network and no database. |
| `runToolContract(definition, input)` | Production-shaped success and error envelopes per tool without transport, auth, or telemetry. |

Required sparse-payload cases, one per external shape:

- KEV record with `cwes: []` and a single-segment `notes` holding only the NVD URL (just over 100 of the 175 empty-`cwes` records look like this).
- KEV record citing no directive at all (1,277 records) — `directive` must be `null`, not inferred.
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
2. **Most KEV entries cite no directive.** 1,277 of 1,716 name neither BOD 22-01 nor BOD 26-04; `directive` is `null` for them rather than inferred from age.
3. **The KEV due date is not reproducible from published SSVC.** In a 24-CVE sample, 9 disagreed with Table 1 under a publicly-exposed assumption and 1 CVE had no enrichment record at all. The two facts are reported side by side and never reconciled.
4. **Vulnrichment coverage is incomplete and can lag.** Not every CVE — including some in KEV — has a record, and a published `Exploitation` value can predate the KEV addition that contradicts it.
5. **Advisory sector coverage begins in 2017.** 729 of 3,926 documents carry no sector note; a sector filter cannot reach them. The gap is disclosed on every filtered call.
6. **No structured CVSS v4 in the advisory corpus.** 392 advisories score only in CVSS v2, where the upstream publishes no severity label and the band must be derived.
7. **The RSS feeds have no history and no conditional GET.** Thirty items, no pagination, no date query, no ETag or Last-Modified — a timer-cached unconditional poll is the only available strategy.
8. **Advisory vendor names are unnormalized.** 895 distinct vendor labels across 3,926 documents, with the same company under several spellings. Vendor filtering is substring matching, not an enum.
9. **The KEV feed ignores `If-None-Match`.** Only `If-Modified-Since` yields a 304; a client that trusts the served ETag re-downloads 1.74 MB on every poll.
10. **No Cloudflare Workers deployment.** The mirror needs embedded SQLite and a persistent filesystem; neither exists in an isolate. stdio, HTTP, Docker, and `.mcpb` are the supported surfaces.

---

## Decisions Log

**1. The CSAF mirror seeds itself in the background at startup; out-of-band scripts are the escape hatch; nothing is baked at container build.**
The corpus is one 11.4 MB archive fetched in ~1.5 s, not an API pagination run — so the usual "init out of band, never on startup" posture is calibrated for a cost this source does not have. Requiring a CLI step before a headline capability works is bad DX for `npx` and impossible for an `.mcpb` user, who has no shell into the bundle. `setup()` therefore kicks `runSync({ mode: 'init' })` off without awaiting it when `CISA_CSAF_MIRROR_AUTO_INIT` is true and the mirror has never completed; KEV, SSVC, and alert tools serve from the first request regardless. `mirror:init` / `mirror:refresh` / `mirror:verify` ship for Docker `exec`, CI, and operators who want explicit control. Build-time baking is rejected on two counts: it adds ~60 MB to the image and ships a snapshot that is stale the day it is built. In Docker the index lives on a named volume at `CISA_CSAF_MIRROR_PATH`, so a container recreation does not re-seed. Default path `.mirror/csaf.sqlite3`.

**2. `better-sqlite3` is a regular dependency, and the `.mcpb` bundle carries it.**
The open question was whether shipping the SQLite driver locks the bundle to the packing platform. It does not. `better-sqlite3@13.0.3` ships all eight platform prebuilds inside the npm tarball — `darwin-{arm64,x64}`, `linux-{arm64,x64}`, `linuxmusl-{arm64,x64}`, `win32-{arm64,x64}`, 16.1 MB total — and `lib/binding.js` selects one at runtime from `process.platform`, `process.arch`, and a musl check. There is no install script, no `prebuild-install` download, and no node-gyp step, so a clean `npx` install on Node needs no build toolchain. Because the prebuilds are all present, the bundle stays cross-platform, and the `NATIVE_BINDING_ENTRY` regex in `clean-mcpb.ts` only targets `@duckdb/node-bindings-*`, so nothing strips it today. Size is the only real constraint: unpacked the package is 26.0 MB, of which `deps/` is 9.8 MB of SQLite C source used solely for a source build. Add a third entry class — `BUILD_ONLY_ENTRY = /^node_modules\/better-sqlite3\/(?:deps|src)\//` — to `clean-mcpb.ts` and the matching literal in `lint-packaging.ts`, which the files' own comments require to be edited together. A separate literal rather than widening `NATIVE_BINDING_ENTRY`: `prebuilds/` is a native binding that must *survive*, and overloading the regex that exists to remove platform-locked natives would invite exactly the deletion that breaks the bundle. Stripped, the zipped contribution is 8.2 MB against 10.7 MB unstripped — comfortably inside the 25 MB registry cap. Under Bun and in the `oven/bun` Docker image the driver is never loaded at all: `openSqliteHandle` uses the built-in `bun:sqlite`.
*Residual risk, deliberately carried:* Node 24+ ships `node:sqlite`, and on Node 26.5.0 it exposes SQLite 3.53.4 with FTS5 and `bm25()` working — a zero-byte driver already inside the Node binary this server pins. The framework's `openSqliteHandle` has no arm for it, so adopting it is a framework change, not a server one. Worth filing upstream; not a blocker, since the prebuild finding removes the portability problem it would have solved.

**3. KEV is an in-memory process-level index refreshed with `If-Modified-Since`, and an HTML body is a transient upstream failure.**
1,716 records and 1.74 MB sit below the mirror tier's floor, and the data is public and byte-identical per tenant, so one shared snapshot with no tenant scoping is correct. Refresh every 30 min conditionally: a no-change poll is a 304 with zero bytes, a change costs 192 KB gzipped. **`If-None-Match` is deliberately unused** — the origin serves an ETag but ignores it on conditional requests and returns the full body, verified against the live ETag in strong, weak, and wildcard forms. Cold start is single-flight and blocking: `setup()` starts the load without awaiting it, and an early request awaits the same promise rather than racing a second fetch; the observed fetch is ~80 ms. A failed refresh with a snapshot in hand logs and keeps serving the old snapshot, with the staleness visible through `cisa_list_reference` topic `sources`; a failed first load throws `catalog_unavailable`, retryable. An HTML body on the JSON route — 46 KB from a Drupal error page — is classified `ServiceUnavailable`, never `SerializationError`: it signals a routing or availability problem the caller can retry past, and labelling it a parse error would make a recoverable outage read as a data-shape defect.

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
Three chaining points are load-bearing and each is stated where the agent reads it. `cisa_check_cve_status` says its returned CWE IDs chain into CWE-filtered CVE search and that the parsed NVD reference gives the canonical scoring record. `cisa_search_kev` says vendor and product are CISA's free-text labels rather than CPE names, so a CPE-shaped query belongs elsewhere. `cisa_check_cve_status` accepts a 200-CVE batch precisely so a CVE alias list from a dependency audit can be checked in one call, and says the call costs nothing upstream. No other server is named — the description tells the caller what the value is and what shape it takes, which is what a caller who installed only this server can act on.

**11. The advisory ID pattern accepts `ICSMA` and both suffix forms.**
The pattern carried in the brief, `^ICS[AM]-\d{2}-\d{3}-\d{2}[a-z]?$`, rejects every one of the 188 `ICSMA-` advisories — `ICS[AM]` matches a single character, so it spells `ICSA` or `ICSM`, never `ICSMA` — and rejects `ICSA-16-231-01-0`, a real document with a numeric rather than alphabetic revision suffix. The design uses `^ICS(A|MA)-\d{2}-\d{3}-\d{2}(?:[a-z]|-\d+)?$`, case-insensitive. Letter suffixes `a` through `f` are observed across 120 documents. Normalization uppercases and strips a trailing `.json`; both are one-to-one and meaning-preserving.

**12. The mirror covers the OT distribution only.**
`csaf_files/` holds three distributions: OT (3,926 `icsa-`/`icsma-` documents, the ICS corpus this server is for), IT (89 `va-` documents), and VA (3 `va-` documents, overlapping IT's paths). Mirroring IT and VA would broaden the server past the ICS scope its name and tool surface promise, for 92 documents whose recent members are already reachable through `cisa_get_alerts`. Adding them later is a `series` enum extension plus a second ingest source, not a redesign. The two `va-` distributions also overlap on path, which would need a distribution-qualified primary key — another reason not to take it on for 92 documents.

**13. Sectors are extracted by longest-match against canonical names, with the raw text always retained.**
The sector note is free-form prose, not an enum. Splitting on commas or "and" is definitively wrong: `Healthcare and Public Health` and `Water and Wastewater Systems` contain "and", and `Nuclear Reactors, Materials, and Waste` contains commas — separator splitting produces tokens like `and Water` and `Facilities`. The design matches the 16 canonical sector names plus a small alias table, longest-first, consuming each hit. Validated across every sector note in the corpus — 3,201 notes on 3,197 documents: 75.1% resolve to at least one canonical name, 24.7% are the `Multiple` sentinel, and 5 documents fail on upstream typos (`Critical Manuacturing`, `Critical Manufacturer`). `sectorsRaw` carries the verbatim text in every case, so nothing the caller might need is lost to normalization.

**14. Maximum CVSS is computed from per-vulnerability scores, and a v2-only band is flagged as derived.**
`document.aggregate_severity` exists on only 52 of 3,926 documents, so it cannot back a severity filter. `maxCvss` is the maximum `baseScore` across every `vulnerabilities[].scores[].cvss_v3|cvss_v2`. `cvss_v3` always carries `baseSeverity`; `cvss_v2` never does across all 697 occurrences, so the band is derived from the CVSS v2 thresholds and marked `severityDerived: true` rather than presented as upstream's. No `cvss_v4` exists anywhere in the corpus as a structured score — where CVSS v4 appears it is prose inside a `details` note, and it is surfaced as a note, never parsed into a score field.

**15. `cisa_get_advisory` uses outline-on-overflow, not truncation.**
783 of 3,926 advisories exceed the 24 KB default budget, 102 exceed 100 KB, and the largest is 1.38 MB with 544 vulnerability entries and 585 products. Returning those whole burns the caller's context; truncating them either hides data or desyncs `content[]` from `structuredContent`. `outlineOnOverflow` returns a complete, honest section outline with per-section byte sizes and a re-call contract, and `selectSections` serves the selection. The re-call is stateless — the mirror lookup is deterministic, so the handler re-reads the row. The `products` arm additionally caps at 200 version rows with the cap disclosed, since the outline treats `products` as one indivisible section and a 585-product advisory would blow the budget inside it.

**16. A not-yet-seeded mirror is a typed retryable error, not an empty result.**
An empty search result would be a lie — it asserts that nothing matches when the index simply does not exist yet. `mirror_not_ready` carries `ServiceUnavailable`, `retryable: true`, and a recovery naming `cisa_list_reference` topic `sources`, which reports the sync status and document count. That routing target is deliberately ungated and network-free: it is callable precisely in the situation the agent is recovering from.

**17. No prompts.**
Every workflow this server serves is a direct lookup or a filtered search whose parameters the tool schema already describes. A prompt template would restate tool descriptions in a surface fewer clients expose.

**18. The `cisa://advisory/{advisoryId}` resource carries the same outline-on-overflow treatment as the tool, not a bare full read.**
An earlier draft of this design had the resource always return `cisa_get_advisory`'s full arm on the reasoning that a resource read is a single fixed shape. That contradicts Decision 15's own reasoning: nothing about reading an advisory through a resource template makes a 1.38 MB, 585-product document any cheaper to hand back whole, and a resource client has no `sections` parameter to opt out with the way a tool caller does. The resource now runs the identical `outlineOnOverflow(doc, { budget: 24_000 })` the tool's no-`sections` call uses; a caller who lands on the outline arm follows up with `cisa_get_advisory` to name the sections it needs.
