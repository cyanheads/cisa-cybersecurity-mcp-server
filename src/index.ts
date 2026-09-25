#!/usr/bin/env node
/**
 * @fileoverview cisa-cybersecurity-mcp-server MCP server entry point. Wires the
 * four services, schedules the two refresh loops, and registers the tool and
 * resource surface.
 *
 * Boot never depends on the ICS advisory corpus: the KEV, SSVC, and alert tools
 * serve from the first request, and the advisory index seeds itself in the
 * background when it has never completed a sync — or re-ingests in place, still
 * serving its existing rows, when an older ingest-content version built it.
 * @module index
 */

import { createApp } from '@cyanheads/mcp-ts-core';
import { getServerConfig } from './config/server-config.js';
import { allResourceDefinitions } from './mcp-server/resources/definitions/index.js';
import { allToolDefinitions } from './mcp-server/tools/definitions/index.js';
import { initCisaFeeds } from './services/cisa-feeds/cisa-feeds-service.js';
import { closeCsafMirror, initCsafMirror } from './services/csaf-mirror/csaf-mirror-service.js';
import { initKevCatalog } from './services/kev-catalog/kev-catalog-service.js';
import { startBackgroundRefresh } from './services/refresh-schedule.js';
import { initVulnrichment } from './services/vulnrichment/vulnrichment-service.js';

await createApp({
  name: 'cisa-cybersecurity-mcp-server',
  title: 'cisa-cybersecurity-mcp-server',
  websiteUrl: 'https://github.com/cyanheads/cisa-cybersecurity-mcp-server',
  instructions:
    'This server serves four CISA datasets, all keyless and all read-only. Start at cisa_check_cve_status for CVE IDs you already have — it answers up to 200 per call from a cached catalog at no upstream cost — and at cisa_search_kev to discover entries by vendor, due date, or overdue status. cisa_get_ssvc adds the SSVC decision points CISA publishes per CVE and computes the BOD 26-04 remediation timeline they imply for an asset exposure you supply; that computation is CISA\'s published decision logic applied to CISA\'s published inputs, not a compliance determination. ICS advisories are served from a local index of the full CSAF corpus back to 2010 — search it with cisa_search_ics_advisories, which can also narrow to the advisories covering a KEV-listed CVE, and read one with cisa_get_advisory. The index seeds itself on first run; until it finishes, the two ICS tools report that state and every other tool works normally. For what CISA published most recently, cisa_get_alerts reads a 30-item rolling window of its advisory, alert, or ICS advisory feed with no history beyond that window — reach for cisa_search_ics_advisories instead for ICS advisory history. cisa_list_reference decodes the vocabulary the rest of the surface takes as input and reports what data this server currently holds. The KEV catalog records additions but no per-record modification timestamp, so "what changed" questions are answerable for additions only.',

  /* No handler returns ctx.requestInput, so nothing needs a durable session. */
  sessionMode: 'stateless',

  tools: allToolDefinitions,
  resources: allResourceDefinitions,

  setup() {
    const config = getServerConfig();

    const kev = initKevCatalog({
      refreshCron: config.kevRefreshCron,
      timeoutMs: config.httpTimeoutMs,
    });
    initVulnrichment({
      cacheTtlSeconds: config.vulnrichmentCacheTtlSeconds,
      timeoutMs: config.httpTimeoutMs,
    });
    const mirror = initCsafMirror({
      mirrorPath: config.csafMirrorPath,
      timeoutMs: config.httpTimeoutMs,
    });
    initCisaFeeds({
      cacheTtlSeconds: config.feedCacheTtlSeconds,
      timeoutMs: config.httpTimeoutMs,
    });

    /* Start the KEV load without awaiting it — a request arriving first awaits the same promise. */
    kev.primeInBackground();

    /* The boot pass over the advisory index and both refresh schedules, on every transport. */
    void startBackgroundRefresh({
      csafMirrorAutoInit: config.csafMirrorAutoInit,
      csafRefreshCron: config.csafRefreshCron,
      kevRefreshCron: config.kevRefreshCron,
      kev,
      mirror,
    });
  },

  /* The framework already tears the scheduler down; an in-flight index sync and the SQLite handle are ours. */
  teardown: closeCsafMirror,
});
