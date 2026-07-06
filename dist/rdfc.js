// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
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
import { createHash, timingSafeEqual } from "node:crypto";
import { Parser } from "n3";
import rdfCanonize from "rdf-canonize";
import { MECH_CONTENT_HASH_RDFC, MECHANISM_ASSERTIONS } from "./mechanisms.js";
const HASH_ALGORITHMS = new Set(["sha256", "sha384", "sha512"]);
/** RDF media types the provider can parse via N3.js. */
const SUPPORTED_MEDIA_TYPES = new Set([
    "text/turtle",
    "application/n-triples",
    "application/n-quads",
    "application/trig",
]);
const DEFAULTS = {
    maxInputBytes: 5_000_000,
    maxQuads: 100_000,
    maxBlankNodes: 10_000,
    maxWorkFactor: 1,
    canonicalizeTimeoutMs: 10_000,
};
function resolveGuards(o) {
    const pick = (v, d) => typeof v === "number" && Number.isFinite(v) && v > 0 ? v : d;
    return {
        maxInputBytes: pick(o.maxInputBytes, DEFAULTS.maxInputBytes),
        maxQuads: pick(o.maxQuads, DEFAULTS.maxQuads),
        maxBlankNodes: pick(o.maxBlankNodes, DEFAULTS.maxBlankNodes),
        // maxWorkFactor may legitimately be 0 (disable) — only reject negatives / non-finite.
        maxWorkFactor: typeof o.maxWorkFactor === "number" &&
            Number.isFinite(o.maxWorkFactor) &&
            o.maxWorkFactor >= 0
            ? o.maxWorkFactor
            : DEFAULTS.maxWorkFactor,
        canonicalizeTimeoutMs: pick(o.canonicalizeTimeoutMs, DEFAULTS.canonicalizeTimeoutMs),
    };
}
/** Strip an optional `"<algorithm>:"` prefix and whitespace, lowercase. */
function normalizeHex(digest) {
    const colon = digest.indexOf(":");
    const body = colon >= 0 ? digest.slice(colon + 1) : digest;
    return body.trim().toLowerCase();
}
/** Constant-time equality of two hex strings (public digests, but hygiene). */
function hexEqual(a, b) {
    const ab = Buffer.from(a, "utf8");
    const bb = Buffer.from(b, "utf8");
    if (ab.length !== bb.length) {
        return false;
    }
    return timingSafeEqual(ab, bb);
}
function failure(code, reason) {
    return { mechanism: MECH_CONTENT_HASH_RDFC, code, reason };
}
function byteLength(content) {
    return typeof content === "string" ? Buffer.byteLength(content, "utf8") : content.byteLength;
}
/** Count DISTINCT blank-node labels across a quad set (the driver of RDFC-1.0 complexity). */
function distinctBlankNodes(quads) {
    const seen = new Set();
    for (const q of quads) {
        for (const term of [q.subject, q.predicate, q.object, q.graph]) {
            if (term.termType === "BlankNode") {
                seen.add(term.value);
            }
        }
    }
    return seen.size;
}
/**
 * Parse (if needed) and guard the input into a bounded quad array, or return a failure.
 * Never throws; all parse/guard failures become an {@link IntegrityFailure}.
 */
function toGuardedQuads(input, g) {
    let quads;
    if (input.quads !== undefined) {
        quads = input.quads;
    }
    else if (input.content !== undefined) {
        const mediaType = (input.mediaType ?? "").split(";", 1)[0]?.trim().toLowerCase() ?? "";
        if (!SUPPORTED_MEDIA_TYPES.has(mediaType)) {
            return failure("unsupported-input", `unsupported RDF media type: ${JSON.stringify(mediaType)}`);
        }
        if (byteLength(input.content) > g.maxInputBytes) {
            return failure("input-too-large", `input exceeds maxInputBytes (${g.maxInputBytes})`);
        }
        const text = typeof input.content === "string"
            ? input.content
            : new TextDecoder("utf-8", { fatal: false }).decode(input.content);
        try {
            // N3.Parser.parse(string) with no callback returns the full quad array synchronously.
            quads = new Parser({ format: mediaType }).parse(text);
        }
        catch (err) {
            return failure("parse-error", `RDF parse failed: ${err?.message ?? "unknown"}`);
        }
    }
    else {
        return failure("unsupported-input", "no quads and no content to hash");
    }
    if (quads.length > g.maxQuads) {
        return failure("too-complex", `quad count ${quads.length} exceeds maxQuads (${g.maxQuads})`);
    }
    const blanks = distinctBlankNodes(quads);
    if (blanks > g.maxBlankNodes) {
        return failure("too-complex", `distinct blank nodes ${blanks} exceeds maxBlankNodes (${g.maxBlankNodes})`);
    }
    return quads;
}
/** Canonicalise + digest the guarded quads, or return a failure. Never throws. */
async function canonicalDigest(quads, algorithm, g) {
    let canonical;
    try {
        canonical = await rdfCanonize.canonize(quads, {
            algorithm: "RDFC-1.0",
            maxWorkFactor: g.maxWorkFactor,
            signal: AbortSignal.timeout(g.canonicalizeTimeoutMs),
            format: "application/n-quads",
        });
    }
    catch (err) {
        // maxWorkFactor exceeded (poison graph) or timeout abort — fail-closed.
        return failure("too-complex", `canonicalisation aborted: ${err?.message ?? "unknown"}`);
    }
    return createHash(algorithm).update(canonical, "utf8").digest("hex");
}
/**
 * Compute the RDFC-1.0 content digest of an input (canonical N-Quads → hash), as lowercase hex.
 *
 * The mirror of verification: a PUBLISHER calls this to mint the trusted reference digest it will
 * pin; a VERIFIER checks against it. Applies the same poison-graph guards. Rejects (throws) on
 * a parse / size / complexity failure so a publisher never silently pins a truncated graph.
 */
export async function computeRdfcDigest(input, options) {
    const algorithm = options?.algorithm ?? "sha256";
    if (!HASH_ALGORITHMS.has(algorithm)) {
        throw new TypeError(`unsupported hash algorithm: ${JSON.stringify(algorithm)}`);
    }
    const g = resolveGuards({ trustedReference: { digest: "", algorithm }, ...options });
    const guarded = toGuardedQuads(input, g);
    if (!Array.isArray(guarded)) {
        throw new Error(`${guarded.code}: ${guarded.reason}`);
    }
    const digest = await canonicalDigest(guarded, algorithm, g);
    if (typeof digest !== "string") {
        throw new Error(`${digest.code}: ${digest.reason}`);
    }
    return `${algorithm}:${digest}`;
}
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
export function rdfcContentHashVerifier(options) {
    const { trustedReference } = options;
    if (!HASH_ALGORITHMS.has(trustedReference.algorithm)) {
        throw new TypeError(`unsupported hash algorithm: ${JSON.stringify(trustedReference.algorithm)}`);
    }
    const g = resolveGuards(options);
    const expected = normalizeHex(trustedReference.digest);
    const algorithm = trustedReference.algorithm;
    return {
        mechanism: MECH_CONTENT_HASH_RDFC,
        canAttempt(input) {
            if (input.quads !== undefined) {
                return true;
            }
            if (input.content === undefined) {
                return false;
            }
            const mediaType = (input.mediaType ?? "").split(";", 1)[0]?.trim().toLowerCase() ?? "";
            return SUPPORTED_MEDIA_TYPES.has(mediaType);
        },
        async verify(input) {
            const guarded = toGuardedQuads(input, g);
            if (!Array.isArray(guarded)) {
                return guarded;
            }
            const computed = await canonicalDigest(guarded, algorithm, g);
            if (typeof computed !== "string") {
                return computed;
            }
            if (expected.length === 0 || !hexEqual(computed, expected)) {
                return failure("digest-mismatch", "canonical content digest does not match the trusted reference");
            }
            const attestation = {
                mechanism: MECH_CONTENT_HASH_RDFC,
                // A matched content hash confers EXACTLY the content-hash ceiling — this is the one case
                // where the ceiling equals the proven set. Copy it into an independent map for the result.
                achieved: new Map(MECHANISM_ASSERTIONS[MECH_CONTENT_HASH_RDFC]),
                contentDigest: `${algorithm}:${computed}`,
            };
            return attestation;
        },
    };
}
