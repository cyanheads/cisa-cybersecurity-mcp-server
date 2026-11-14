---
name: cisa-cybersecurity-guide
description: Use cisa_* tools to triage vulnerability lists and trace ICS advisory applicability from CVEs through product definitions, relationships, and scoped remediations. Use for CISA evidence, KEV deadlines, SSVC timelines, affected versions, and recent advisory monitoring when incomplete coverage could change the conclusion.
license: Apache-2.0
metadata:
  author: "cyanheads"
  version: "1.1"
---

## Scope

Use CISA evidence to prioritize an existing vulnerability inventory or investigate an ICS or medical-device advisory. Establish asset identity, installed version, and network exposure from the caller's inventory; these tools do not discover assets or scan them. CISA's published evidence does not establish that an arbitrary asset is affected, exploitable, or compliant.

## Identifiers

- Carry CVE IDs from the inventory into KEV and SSVC lookups, or from advisory results into per-CVE investigation. A CWE describes a weakness class; it is not a substitute for a CVE or an affected-product match.
- Take advisory IDs from cisa_search_ics_advisories or an ICS feed result. An advisory ID identifies the document; its listed CVEs identify the vulnerabilities within it.
- Take product IDs from the selected advisory's vulnerability status, score, remediation, flag, or threat references. Preserve their spelling and case, and resolve them against that same advisory's product definitions. They are opaque identifiers, not version strings or identifiers shared across advisories.
- A relationship product definition references component product IDs. Retrieve those definitions separately; selecting the relationship does not expand them.

## Gates

1. Before reporting an absence, identify which dataset answered and whether its coverage supports the claim. Check cisa_list_reference for source state when freshness or index readiness matters. A KEV miss means absence from that snapshot, not absence of exploitation; an SSVC miss does not establish low risk. Treat an SSVC `fetch_failed` outcome as unavailable evidence, separately from confirmed absence.
2. Before excluding a vendor or product, inspect the applied filters and coverage notices. Sector filters omit documents with no sector note; score filters omit documents with no score. Broaden restrictive discovery filters before claiming that no relevant advisory exists.
3. Before calling an asset affected or recommending a version-specific fix, read the selected vulnerability's product status, resolve the referenced product definitions, and compare their version expressions with the asset inventory. An advisory-level vendor match or maximum CVSS score does not establish applicability to every product or CVE in it. Read product-scoped flags and impact statements before explaining a not-affected status.
4. Keep unresolved product and group references unresolved. A missing definition or an empty applicability list does not establish that a remediation applies to every product, or that an asset is unaffected. Follow the advisory's source references when its normalized evidence cannot settle the match.
5. State asset exposure only from evidence about the caller's estate. When exposure is unknown and the decision points support computation, retain both BOD 26-04 timeline branches. Report the computed timeline separately from CISA's assigned KEV due date and preserve the assigned date when enrichment is missing or the timelines disagree. If the KEV entry cites no directive, treat the basis for its assignment as unknown.
6. Before calling a result set complete, follow its search continuation, process any returned `unprocessedIds`, and inspect selection or outline notices. Search previews and advisory outlines do not contain full vulnerability entries or product definitions. Preserve source links and attribution with the evidence used in the answer.

## Core chain

For scan triage, check the inventory's CVEs with cisa_check_cve_status, then use cisa_get_ssvc for the CVEs requiring a decision based on asset exposure. Keep inventory applicability, KEV membership, assigned due dates, and computed timelines as separate facts in the resulting priorities.

For ICS applicability, discover advisory IDs with cisa_search_ics_advisories, read the relevant CVEs with cisa_get_advisory, then retrieve the product definitions named by their status and remediation entries. Follow relationship components before comparing an installed version. Report the matching status and scoped remediation together, or state the unresolved evidence that prevents a match.

## Workflows

**Discover without narrowing away the evidence.** Use ordinary terms in ICS text search; Boolean and FTS operators are not a query language exposed by this server. Search alternate vendor spellings in separate calls and combine the findings by advisory ID. Use CVE membership to find an advisory covering a known vulnerability rather than treating a CVE string as product text. Use cisa_list_reference for sector and field vocabulary instead of guessing labels.

**Read large advisories in hops.** Use the outline's section names and complete CVE list to request the evidence needed for the current question. Read selected vulnerability entries before requesting their referenced products; for relationship definitions, make the additional component lookup. Explicit selections return the selected content even when large, so request only the sections and identifiers needed for the question.

**Find the originating vendor bulletin.** Search ICS advisories with the bulletin identifier in `q`, then use the returned vendor advisory link to trace the source. Check the index coverage notice before drawing conclusions from a miss.

**Distinguish additions, revisions, and recent publications.** Use KEV additions for newly listed CVEs; they cannot reveal edits to existing KEV entries. Use advisory revision history and revision-date searches for changes to ICS documents. Use cisa_get_alerts for the available recent feed window, following its cursors within that window. If a continuation anchor is unavailable, report the gap and restart without a cursor; do not assume that every intervening publication was retrieved. Inspect freshness and coverage before describing a requested period as complete. The feed cannot establish historical absence; use the ICS advisory index for older ICS documents.

**Read beyond a feed excerpt.** When a capped feed item lacks an advisory ID, reissue the feed page with `detail: "full"`. When the item has an advisory ID, use cisa_get_advisory.
