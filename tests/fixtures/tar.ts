/**
 * @fileoverview Minimal ustar + gzip builder for CSAF archive fixtures in tests.
 * Builds just enough of the tar format for `iterateTarGz` to parse: a 512-byte
 * ustar header per entry (no GNU long names, no pax headers — every fixture
 * path stays under 100 bytes) followed by the file content padded to a 512-byte
 * boundary, terminated by two zero blocks.
 * @module tests/fixtures/tar
 */

import { gzipSync } from 'node:zlib';

const BLOCK = 512;
const encoder = new TextEncoder();

function writeString(block: Uint8Array, offset: number, length: number, value: string): void {
  const bytes = encoder.encode(value);
  block.set(bytes.subarray(0, length), offset);
}

/** Octal field: `length - 1` digits followed by a NUL terminator. */
function writeOctal(block: Uint8Array, offset: number, length: number, value: number): void {
  const digits = value.toString(8).padStart(length - 1, '0');
  writeString(block, offset, length - 1, digits);
  block[offset + length - 1] = 0;
}

function buildHeader(name: string, size: number): Uint8Array {
  if (encoder.encode(name).length > 100) {
    throw new Error(`Fixture tar entry name exceeds 100 bytes: ${name}`);
  }
  const header = new Uint8Array(BLOCK);
  writeString(header, 0, 100, name);
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  /* Checksum field starts as eight spaces while the sum is computed. */
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0); /* typeflag: regular file */
  writeString(header, 257, 5, 'ustar');
  header[262] = 0;
  writeString(header, 263, 2, '00');

  let sum = 0;
  for (const byte of header) sum += byte;
  const checksum = sum.toString(8).padStart(6, '0');
  writeString(header, 148, 6, checksum);
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

/** One file to place in the built archive. */
export interface TarFixtureEntry {
  data: string;
  /**
   * Size written into the header in place of the content length — the seam for a
   * malformed-header case, where what the header declares and what follows it
   * disagree.
   */
  declaredSize?: number;
  name: string;
}

/** Build a gzip-compressed ustar archive from a list of entries, as a `Response`. */
export function buildTarGzResponse(entries: TarFixtureEntry[], init?: ResponseInit): Response {
  const parts: Uint8Array[] = [];
  for (const entry of entries) {
    const content = encoder.encode(entry.data);
    parts.push(buildHeader(entry.name, entry.declaredSize ?? content.length));
    parts.push(content);
    const remainder = content.length % BLOCK;
    if (remainder !== 0) parts.push(new Uint8Array(BLOCK - remainder));
  }
  parts.push(new Uint8Array(BLOCK * 2)); /* end-of-archive marker: two zero blocks */

  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const tar = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    tar.set(part, offset);
    offset += part.length;
  }

  const gz = gzipSync(tar);
  return new Response(gz, init);
}
