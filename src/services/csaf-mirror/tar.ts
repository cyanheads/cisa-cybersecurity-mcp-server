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

/**
 * Ceiling on a single entry this reader will buffer. The header's size field is
 * twelve octal digits, so a corrupt or hostile one can declare gigabytes and the
 * reader would allocate for it before discovering the stream is shorter. The
 * largest advisory in the corpus is 1.38 MB, so 64 MiB is far above anything the
 * source publishes and far below a size that could exhaust the process.
 *
 * It bounds every entry this reader buffers — a document it is about to yield,
 * and a long-name or pax header it has to read to name the next one. An entry
 * the caller filtered out is never buffered at all: it is discarded in bounded
 * chunks, whatever its header claims.
 */
export const MAX_TAR_ENTRY_BYTES = 64 * 1024 * 1024;

/** Bytes discarded per read while skipping past an entry. */
const DISCARD_CHUNK = 64 * 1024;

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

  /**
   * Drop exactly `length` bytes, reading in bounded chunks so a header that
   * declares gigabytes costs a loop rather than an allocation. Returns `false`
   * at a short stream, which ends iteration the same way a short read does.
   */
  async discard(length: number): Promise<boolean> {
    let remaining = length;
    while (remaining > 0) {
      const take = Math.min(remaining, DISCARD_CHUNK);
      if ((await this.readExactly(take)) === null) return false;
      remaining -= take;
    }
    return true;
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
        if (size > MAX_TAR_ENTRY_BYTES) {
          throw new Error(
            `CSAF archive metadata entry declares ${size} bytes, past the ${MAX_TAR_ENTRY_BYTES}-byte ceiling.`,
          );
        }
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
        if (padded > 0 && !(await reader.discard(padded))) return;
        continue;
      }

      if (size > MAX_TAR_ENTRY_BYTES) {
        throw new Error(
          `CSAF archive entry ${fullName} declares ${size} bytes, past the ${MAX_TAR_ENTRY_BYTES}-byte ceiling.`,
        );
      }

      const payload = await reader.readExactly(padded);
      if (!payload) return;
      yield { name: fullName, data: payload.subarray(0, size) };
    }
  } finally {
    await reader.cancel();
  }
}
