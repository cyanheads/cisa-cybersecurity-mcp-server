/**
 * @fileoverview Wall-time measurement for linear-time checks on functions that
 * scan caller- or upstream-sized text: best per-call time at 5k, 20k, and 80k
 * characters, over interleaved rounds.
 * @module tests/helpers/linear-time
 */

/** The input lengths a linear-time check measures. */
export const SIZES = [5_000, 20_000, 80_000] as const;

/** Mean per-call wall time over `runs` calls. */
function meanMs(run: () => void, runs: number): number {
  const start = performance.now();
  for (let i = 0; i < runs; i++) run();
  return (performance.now() - start) / runs;
}

/**
 * Best per-call time for `fn` on `build(n)` at each of {@link SIZES}. Parallel
 * test workers contend for the CPU in bursts; interleaving the sizes round by
 * round spreads all three across the same conditions, and one clean round of
 * each is enough. The 5k time is floored at 0.02 ms so a timer-resolution zero
 * cannot inflate the ratio.
 */
export function bestMsBySize(
  fn: (input: string) => unknown,
  build: (length: number) => string,
): Record<(typeof SIZES)[number], number> {
  const inputs = SIZES.map((size) => build(size));
  for (const input of inputs) fn(input);
  const best = SIZES.map(() => Number.POSITIVE_INFINITY);
  for (let round = 0; round < 10; round++) {
    inputs.forEach((input, i) => {
      const runs = Math.max(2, Math.round(40 / 4 ** i));
      best[i] = Math.min(
        best[i] ?? Number.POSITIVE_INFINITY,
        meanMs(() => fn(input), runs),
      );
    });
  }
  const [ms5k = 0, ms20k = 0, ms80k = 0] = best;
  return { 5000: Math.max(ms5k, 0.02), 20000: ms20k, 80000: ms80k };
}
