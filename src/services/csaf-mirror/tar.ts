/**
 * @fileoverview A streaming tar reader over a gzip-compressed response body. The
 * CSAF repository archive is 11.4 MB compressed and ~95 MB expanded, so entries
 * are parsed as the bytes arrive and non-matching ones are skipped without ever
 * being materialized — peak memory is one advisory (max 1.38 MB) plus the read
 * buffer rather than the whole archive.
 *
 * Only the pieces a GitHub codeload archive actually emits are implemented:
 * ustar regular files, the `prefix` field, GNU long names (`L`), and pax
 * extended headers (`x`, read for a `path=` record). Everything else is skipped
 * by its declared size.
 * @module services/csaf-mirror/tar
 */

/** One regular file entry read out of the archive. */
export interface TarEntry {
  data: Uint8Array;
  name: string;
}

const BLOCK = 512;

/** Pull-based byte reader over a `ReadableStream`, with exact-length reads. */
class ByteReader {
  private chunks: Uint8Array[] = [];
  private done = false;
  private size = 0;

  constructor(private readonly reader: ReadableStreamDefaultReader<Uint8Array>) {}

  /** Read exactly `length` bytes, or `null` at a clean end of stream. */
  async readExactly(length: number): Promise<Uint8Array | null> {
    while (this.size < length && !this.done) {
      const { value, done } = await this.reader.read();
      if (done) {
        this.done = true;
        break;
      }
      if (value && value.byteLength > 0) {
        this.chunks.push(value);
        this.size += value.byteLength;
      }
    }
    if (this.size < length) return null;

    const out = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      const chunk = this.chunks[0] as Uint8Array;
      const take = Math.min(chunk.byteLength, length - offset);
      out.set(chunk.subarray(0, take), offset);
      offset += take;
      if (take === chunk.byteLength) this.chunks.shift();
      else this.chunks[0] = chunk.subarray(take);
      this.size -= take;
    }
    return out;
  }

  /** Release the underlying reader. */
  async cancel(): Promise<void> {
    await this.reader.cancel().catch(() => {
      /* The stream may already be closed; nothing to recover. */
    });
  }
}

const decoder = new TextDecoder();

function readString(block: Uint8Array, offset: number, length: number): string {
  const slice = block.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  return decoder.decode(end === -1 ? slice : slice.subarray(0, end)).trim();
}

function readOctal(block: Uint8Array, offset: number, length: number): number {
  const text = readString(block, offset, length).replace(/[^0-7]/g, '');
  return text === '' ? 0 : Number.parseInt(text, 8);
}

function isZeroBlock(block: Uint8Array): boolean {
  return block.every((byte) => byte === 0);
}

/** Pull a `path=` record out of a pax extended header payload. */
function paxPath(payload: Uint8Array): string | undefined {
  for (const record of decoder.decode(payload).split('\n')) {
    const match = /^\d+ path=(.*)$/.exec(record.trim());
    if (match?.[1]) return match[1];
  }
  return undefined;
}

/**
 * Iterate the regular-file entries of a gzip-compressed tar stream whose name
 * satisfies `include`. Entries that do not match are skipped by their declared
 * size without being copied.
 */
export async function* iterateTarGz(
  body: ReadableStream<Uint8Array>,
  include: (name: string) => boolean,
): AsyncGenerator<TarEntry> {
  /*
   * `DecompressionStream` is typed with a `BufferSource` writable side, which is
   * wider than the `Uint8Array` chunks a response body emits; the cast narrows
   * the pair to what actually flows through it.
   */
  const gunzip = new DecompressionStream('gzip') as unknown as ReadableWritablePair<
    Uint8Array,
    Uint8Array
  >;
  const stream = body.pipeThrough(gunzip);
  const reader = new ByteReader(stream.getReader() as ReadableStreamDefaultReader<Uint8Array>);
  let overrideName: string | undefined;

  try {
    while (true) {
      const header = await reader.readExactly(BLOCK);
      if (!header) return;
      if (isZeroBlock(header)) return;

      const name = readString(header, 0, 100);
      const size = readOctal(header, 124, 12);
      const typeFlag = String.fromCharCode(header[156] ?? 0).trim();
      const prefix = readString(header, 345, 155);
      const padded = Math.ceil(size / BLOCK) * BLOCK;

      if (typeFlag === 'L' || typeFlag === 'x' || typeFlag === 'g') {
        const payload = await reader.readExactly(padded);
        if (!payload) return;
        const meaningful = payload.subarray(0, size);
        overrideName =
          typeFlag === 'L' ? decoder.decode(meaningful).replace(/\0+$/, '') : paxPath(meaningful);
        continue;
      }

      const fullName = overrideName ?? (prefix === '' ? name : `${prefix}/${name}`);
      overrideName = undefined;

      const isRegular = typeFlag === '' || typeFlag === '0';
      if (!isRegular || !include(fullName)) {
        if (padded > 0) {
          const skipped = await reader.readExactly(padded);
          if (!skipped) return;
        }
        continue;
      }

      const payload = await reader.readExactly(padded);
      if (!payload) return;
      yield { name: fullName, data: payload.subarray(0, size) };
    }
  } finally {
    await reader.cancel();
  }
}
