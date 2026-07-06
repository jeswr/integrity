/**
 * The integrity abstraction interfaces (§C.1).
 *
 * These mirror the shape of the issuer-agnostic auth verifier
 * (`prod-solid-server/src/auth/verifier.ts`): auth code depends on "a verified WebID from a
 * trusted issuer", never on a concrete IdP; integrity code depends on "an attestation
 * satisfying a stated requirement", never on Verifiable Credentials (or any other single
 * mechanism). The dependency direction is one-way: `@jeswr/integrity` NEVER imports
 * `@jeswr/solid-vc` — the solid-vc `./integrity` provider depends on THIS package.
 */
import type { IntegrityPropertyIri, Verdict } from "./vocab.js";
/**
 * A minimal, structural RDF term — zero runtime dependency. Structurally satisfied by
 * `@rdfjs/types` / N3.js terms, so a caller can pass pre-parsed quads without this core
 * pulling an RDF library into the (browser-safe) root entry.
 */
export interface RdfTermLike {
    readonly termType: string;
    readonly value: string;
}
/** A minimal, structural RDF quad — see {@link RdfTermLike}. */
export interface RdfQuadLike {
    readonly subject: RdfTermLike;
    readonly predicate: RdfTermLike;
    readonly object: RdfTermLike;
    readonly graph: RdfTermLike;
}
/**
 * The data whose integrity is being established. A provider consumes whatever fields it
 * understands (see {@link IntegrityVerifier.canAttempt}); the core never inspects it.
 *
 * NOTE (SSRF): `source` is provenance metadata only. The core NEVER dereferences it, and no
 * shipped provider fetches a URL on the caller's behalf — a provider that needs remote key /
 * status resolution takes an injected, caller-controlled resolver (mirroring the auth
 * verifier's `trustedIssuers` seam), so the network egress surface stays with the caller.
 */
export interface IntegrityInput {
    /** Raw serialized RDF / credential bytes to be parsed by a provider that understands it. */
    readonly content?: string | Uint8Array;
    /** IANA media type of `content` (e.g. `text/turtle`, `application/n-quads`, `application/ld+json`). */
    readonly mediaType?: string;
    /** Pre-parsed RDF dataset (an alternative to `content` for callers that already have quads). */
    readonly quads?: readonly RdfQuadLike[];
    /** A structured envelope (e.g. a parsed JSON-LD Verifiable Credential) for envelope providers. */
    readonly document?: unknown;
    /** Provenance URL of the data. Metadata ONLY — never dereferenced by the core. */
    readonly source?: string;
}
/**
 * An integrity REQUIREMENT: a set of properties each demanded at a minimum verdict
 * (sec-req pattern). An "integrity level" is a NAMED requirement profile (see `profiles.ts`);
 * `profile` records which named profile (if any) produced `requires`, for audit/logging.
 */
export interface IntegrityRequirement {
    /** The named profile this requirement was built from, e.g. `INTEGRITY_PROFILES.IL4`. Advisory. */
    readonly profile?: string;
    /** The minimum verdict demanded per property. An ABSENT property is unconstrained. */
    readonly requires: ReadonlyMap<IntegrityPropertyIri, Verdict>;
}
/**
 * Evidence that a mechanism established integrity — never a bare boolean. A successful
 * verification returns exactly what was PROVEN (the `achieved` verdict map), so
 * `satisfies(attestation, requirement)` can decide acceptance, and a PROV audit trail can
 * record which mechanism at which level attested the data.
 */
export interface IntegrityAttestation {
    /** The mechanism id that produced this attestation, e.g. `vc-di/eddsa-rdfc-2022`. */
    readonly mechanism: string;
    /**
     * The verdict PROVEN per property by this run of the mechanism. A property ABSENT from this
     * map is treated as verdict `no` by {@link satisfies} (fail-closed). A provider MUST only
     * assert a property here after actually verifying it — never copy a capability ceiling.
     */
    readonly achieved: ReadonlyMap<IntegrityPropertyIri, Verdict>;
    /** Canonical content identity (e.g. RDFC-1.0 digest) when `ContentBinding` holds. */
    readonly contentDigest?: string;
    /** Bound identity (issuer / WebID) when `AuthorshipBinding` holds. */
    readonly author?: string;
}
/** Machine-readable reason a provider (or `verifyIntegrity`) produced no satisfying attestation. */
export type IntegrityFailureCode = "no-provider" | "unsupported-input" | "parse-error" | "input-too-large" | "too-complex" | "digest-mismatch" | "below-requirement" | "verification-error";
/**
 * A non-satisfying verification outcome — carries WHY, so a provider can be diagnosed without
 * throwing. Distinct from {@link IntegrityAttestation} by the absence of `achieved`
 * (see {@link isAttestation}).
 */
export interface IntegrityFailure {
    /** The mechanism id that produced this failure. */
    readonly mechanism: string;
    /** Machine-readable failure code. */
    readonly code: IntegrityFailureCode;
    /** Human-readable, non-sensitive explanation. */
    readonly reason: string;
}
/** The outcome of a provider's `verify`: either evidence, or a diagnosed non-result. */
export type IntegrityResult = IntegrityAttestation | IntegrityFailure;
/**
 * ONE mechanism = ONE provider (sig-impl pattern). A registry is an ordered list of providers;
 * `verifyIntegrity` tries each whose `canAttempt` returns true, in order, and accepts the first
 * whose attestation satisfies the requirement (deny-by-default).
 */
export interface IntegrityVerifier {
    /** Stable mechanism id, e.g. `content-hash/rdfc-1.0`. */
    readonly mechanism: string;
    /**
     * A cheap, side-effect-free sniff of whether this provider could handle the input (e.g. a
     * JSON-LD VC envelope shape, or the presence of RDF content). MUST NOT perform verification,
     * I/O, or throw. Returning `true` is only a claim of applicability, not of success.
     */
    canAttempt(input: IntegrityInput): boolean;
    /**
     * Perform verification. Returns an {@link IntegrityAttestation} of exactly what was proven, or
     * an {@link IntegrityFailure} explaining why nothing was. SHOULD prefer returning a failure to
     * throwing; `verifyIntegrity` treats a thrown error as fail-closed regardless.
     */
    verify(input: IntegrityInput): Promise<IntegrityResult>;
}
/**
 * Discriminates the {@link IntegrityResult} union. `achieved` is present on an attestation and
 * absent on a failure, so this narrowing is exhaustive and fail-closed for any malformed object.
 */
export declare function isAttestation(result: IntegrityResult): result is IntegrityAttestation;
