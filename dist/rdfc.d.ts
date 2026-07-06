/**
 * `@jeswr/integrity/rdfc` — the ONE built-in integrity provider: a trusted-reference RDFC-1.0
 * content-hash verifier.
 *
 * This is the exact mechanism the suite's hash-pinned protocol documents (`solid-a2a` /
 * `a2a-rdf-extension`) already use: canonicalise an RDF graph with [RDFC-1.0], hash the canonical
 * N-Quads, and compare to a TRUSTED reference digest supplied out-of-band. A match attests
 * `ContentBinding` + `TamperEvidence` + `OfflineVerifiability` (IL2) — plus `PostQuantumForgery`,
 * since a hash has no signature to forge. It does NOT attest authorship: the reference's
 * provenance (who told you the trusted digest) is the caller's trust anchor, not this provider's.
 *
 * This entry is Node-oriented (uses `node:crypto`); it is kept OFF the browser-safe root so a
 * root-only consumer pulls neither `rdf-canonize`, `n3`, nor `node:crypto`.
 *
 * SECURITY — untrusted RDF input surface. The whole point is verifying data you do NOT trust yet,
 * so the input is hostile by assumption. RDFC-1.0 has known super-polynomial "poison graph"
 * blow-up on adversarial blank-node topologies. Defences, all bounded and fail-closed:
 *   1. a byte-size cap BEFORE parsing (`maxInputBytes`);
 *   2. a quad-count cap and a distinct-blank-node cap AFTER parsing (`maxQuads`, `maxBlankNodes`);
 *   3. `rdf-canonize`'s own `maxWorkFactor` complexity limit (default O(n)) — it THROWS on a
 *      poison graph rather than burning CPU;
 *   4. a wall-clock `AbortSignal.timeout` on canonicalisation;
 *   5. any parse / complexity / timeout / mismatch yields an {@link IntegrityFailure}, never a
 *      thrown error into the caller and never a partial/accepting result (deny-by-default).
 */
import type { IntegrityInput, IntegrityVerifier } from "./types.js";
export type { IntegrityAttestation, IntegrityFailure, IntegrityFailureCode, IntegrityInput, IntegrityRequirement, IntegrityResult, IntegrityVerifier, RdfQuadLike, RdfTermLike, } from "./types.js";
/** Digest algorithms this provider accepts. Restricted so no arbitrary string reaches `createHash`. */
export type HashAlgorithm = "sha256" | "sha384" | "sha512";
/** A trusted reference digest to check the canonical content against (supplied out-of-band). */
export interface TrustedReference {
    /**
     * The expected digest as lowercase hex. An optional `"<algorithm>:"` prefix (e.g. `sha256:…`)
     * is accepted and stripped. This is the TRUSTED anchor — it must come from a source the caller
     * already trusts (a pinned constant, a signed manifest, a controlled channel), never from the
     * same untrusted input being verified.
     */
    readonly digest: string;
    /** The hash algorithm `digest` was computed with. */
    readonly algorithm: HashAlgorithm;
}
/** Guard and reference configuration for {@link rdfcContentHashVerifier}. */
export interface RdfcContentHashOptions {
    /** The trusted reference digest to compare the canonical content against. */
    readonly trustedReference: TrustedReference;
    /** Max input bytes before parsing (poison-graph size guard). Default 5_000_000 (5 MB). */
    readonly maxInputBytes?: number;
    /** Max quads after parsing (poison-graph count guard). Default 100_000. */
    readonly maxQuads?: number;
    /** Max DISTINCT blank nodes after parsing (poison-graph topology guard). Default 10_000. */
    readonly maxBlankNodes?: number;
    /** `rdf-canonize` `maxWorkFactor` (O(n^k) deep-iteration cap). Default 1 (O(n)). */
    readonly maxWorkFactor?: number;
    /** Wall-clock cap on canonicalisation, ms. Default 10_000. */
    readonly canonicalizeTimeoutMs?: number;
}
/**
 * Compute the RDFC-1.0 content digest of an input (canonical N-Quads → hash), as lowercase hex.
 *
 * The mirror of verification: a PUBLISHER calls this to mint the trusted reference digest it will
 * pin; a VERIFIER checks against it. Applies the same poison-graph guards. Rejects (throws) on
 * a parse / size / complexity failure so a publisher never silently pins a truncated graph.
 */
export declare function computeRdfcDigest(input: IntegrityInput, options?: {
    algorithm?: HashAlgorithm;
} & Partial<Pick<RdfcContentHashOptions, "maxInputBytes" | "maxQuads" | "maxBlankNodes" | "maxWorkFactor" | "canonicalizeTimeoutMs">>): Promise<string>;
/**
 * Build the trusted-reference RDFC-1.0 content-hash provider (an {@link IntegrityVerifier}).
 *
 * On a digest MATCH it returns an attestation with `achieved` = the `content-hash/rdfc-1.0`
 * ceiling (ContentBinding/TamperEvidence/OfflineVerifiability + PostQuantumForgery) and
 * `contentDigest` = the canonical `"<algorithm>:<hex>"`. On any parse/guard/complexity/mismatch it
 * returns an {@link IntegrityFailure}. It NEVER attests authorship (no signature is checked).
 *
 * @throws {TypeError} at construction if `trustedReference.algorithm` is not an accepted algorithm.
 */
export declare function rdfcContentHashVerifier(options: RdfcContentHashOptions): IntegrityVerifier;
