// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
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
/**
 * Discriminates the {@link IntegrityResult} union. `achieved` is present on an attestation and
 * absent on a failure, so this narrowing is exhaustive and fail-closed for any malformed object.
 */
export function isAttestation(result) {
    return (typeof result === "object" &&
        result !== null &&
        "achieved" in result &&
        result.achieved instanceof Map);
}
