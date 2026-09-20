/**
 * @fileoverview The single upstream HTTP boundary for every CISA service in this
 * server. Every outbound request — KEV, Vulnrichment, the CSAF archive and its
 * manifest, the RSS feeds — goes through `fetchUpstream`, so one fetch fake
 * covers the whole surface in tests.
 *
 * It is a plain `fetch` rather than the framework's `fetchWithTimeout` because
 * three of the four sources need a non-2xx status as a *result* rather than a
 * throw: a `304` answers the KEV and `changes.csv` conditional polls, and a `404`
 * from Vulnrichment is an ordinary "CISA has not enriched this CVE" outcome. The
 * timeout, the caller's `AbortSignal`, and the status-mapped error classification
 * are reproduced here; unexpected non-2xx responses still raise the framework's
 * `httpErrorFromResponse` error so `withRetry` classifies them identically.
 *
 * Every URL is composed from a module constant and a schema-validated identifier;
 * nothing on this surface takes a caller-supplied URL.
 * @module services/upstream-http
 */

import { serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { httpErrorFromResponse } from '@cyanheads/mcp-ts-core/utils';

/** Body shape the caller intends to parse, which decides how an HTML body is detected. */
export type UpstreamBodyKind = 'json' | 'xml' | 'text';

/** Options for {@link fetchUpstream}. */
export interface FetchUpstreamOptions {
  /** Statuses the caller handles itself; the response is returned instead of thrown. */
  acceptStatuses?: number[];
  /** Request headers (conditional-GET validators, `Accept-Encoding`, user agent). */
  headers?: Record<string, string>;
  /** Label used in the thrown error's message. */
  service: string;
  /** Caller cancellation, composed with the timeout. */
  signal?: AbortSignal;
  /** Per-request timeout in milliseconds. */
  timeoutMs: number;
}

/**
 * Fetch an upstream URL with a timeout and caller-cancellation composed into one
 * signal. Returns the `Response` for a 2xx or any status listed in
 * `acceptStatuses`; anything else throws a status-mapped `McpError`.
 */
export async function fetchUpstream(url: string, options: FetchUpstreamOptions): Promise<Response> {
  const timeout = AbortSignal.timeout(options.timeoutMs);
  const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;

  const response = await fetch(url, {
    signal,
    redirect: 'follow',
    headers: { 'accept-encoding': 'gzip', ...options.headers },
  });

  if (response.ok || options.acceptStatuses?.includes(response.status)) return response;

  throw await httpErrorFromResponse(response, { service: options.service });
}

/**
 * Reject an HTML error page served on a JSON or XML route. cisa.gov answers a
 * wrong path — and, transiently, a healthy one under load — with a ~46 KB Drupal
 * error page carrying `content-type: text/html`. That is an availability problem
 * the caller can retry past, so it is classified `ServiceUnavailable`, never
 * `SerializationError`: labelling it a parse failure would make a recoverable
 * outage read as a data-shape defect.
 */
export function assertNotHtml(
  body: string,
  contentType: string | null,
  kind: UpstreamBodyKind,
  url: string,
): void {
  const htmlContentType = (contentType ?? '').toLowerCase().includes('text/html');
  const leading = body.trimStart();
  const looksHtml =
    /^<(?:!doctype\s+html|html[\s>])/i.test(leading) ||
    (kind === 'json' && leading.startsWith('<'));

  if (htmlContentType || looksHtml) {
    throw serviceUnavailable(
      `Upstream returned an HTML page instead of ${kind.toUpperCase()} for ${url}. The source is routing or failing, not returning malformed data.`,
      { reason: 'upstream_html_response', url, contentType },
    );
  }
}
