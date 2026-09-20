/**
 * @fileoverview Tests for the shared upstream HTTP boundary — the bounded body
 * reader every service buffers a response through.
 * @module tests/services/upstream-http.test
 */

import { describe, expect, it } from 'vitest';
import { readUpstreamText } from '@/services/upstream-http.js';

/** A response whose body arrives as several chunks, as a real one does. */
function chunkedResponse(chunks: Uint8Array[]): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
  return new Response(stream);
}

const encoder = new TextEncoder();

describe('readUpstreamText', () => {
  it('returns the whole body when it fits the ceiling', async () => {
    const response = chunkedResponse([encoder.encode('{"a":'), encoder.encode('1}')]);
    const text = await readUpstreamText(response, {
      maxBytes: 1024,
      service: 'test',
      url: 'https://example.invalid/a.json',
    });
    expect(text).toBe('{"a":1}');
  });

  it('decodes a multi-byte character split across two chunks', async () => {
    const bytes = encoder.encode('café');
    const response = chunkedResponse([bytes.subarray(0, 4), bytes.subarray(4)]);
    const text = await readUpstreamText(response, {
      maxBytes: 1024,
      service: 'test',
      url: 'https://example.invalid/a.json',
    });
    expect(text).toBe('café');
  });

  it('throws once the body passes the ceiling instead of buffering the rest', async () => {
    const chunk = encoder.encode('x'.repeat(64));
    const response = chunkedResponse(Array.from({ length: 16 }, () => chunk));

    await expect(
      readUpstreamText(response, {
        maxBytes: 128,
        service: 'CISA KEV',
        url: 'https://example.invalid/big.json',
      }),
    ).rejects.toThrow(/128 bytes/);
  });

  it('returns an empty string for a response with no body', async () => {
    const text = await readUpstreamText(new Response(null, { status: 204 }), {
      maxBytes: 128,
      service: 'test',
      url: 'https://example.invalid/empty',
    });
    expect(text).toBe('');
  });
});
