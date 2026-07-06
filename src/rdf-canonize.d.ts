// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * Minimal ambient declaration for the subset of `rdf-canonize` (v5) this package uses.
 * There is no `@types/rdf-canonize`; declaring only the used surface keeps the security-critical
 * canonicalisation call reviewable. Mirrors the documented options in the package's index.js.
 */
declare module "rdf-canonize" {
  interface CanonizeOptions {
    /** The canonicalisation algorithm. This package always passes `"RDFC-1.0"`. */
    algorithm: "RDFC-1.0";
    /**
     * Poison-graph complexity control: max deep-comparison iterations as a factor of the number
     * of non-unique blank nodes. `1` = O(n) (default), `2` = O(n^2), `0` = disable, `Infinity` =
     * no limit. Exceeding it THROWS. This package passes a bounded value.
     */
    maxWorkFactor?: number;
    /** Exact max deep iterations; overrides `maxWorkFactor` when set. */
    maxDeepIterations?: number;
    /** Abort signal (e.g. `AbortSignal.timeout(ms)`) — checked periodically during canonicalisation. */
    signal?: AbortSignal;
    /** Message digest algorithm for the algorithm's internal hashing (default `sha256`). */
    messageDigestAlgorithm?: string;
    /** Output format; `application/n-quads` (the default) yields a canonical N-Quads string. */
    format?: "application/n-quads";
    /** Input format; omit for an RDF/JS dataset (array of quads). */
    inputFormat?: "application/n-quads";
  }

  /** Asynchronously canonicalise an RDF/JS dataset (array of quads) to canonical N-Quads. */
  export function canonize(input: unknown, options: CanonizeOptions): Promise<string>;

  const _default: { canonize: typeof canonize };
  export default _default;
}
