/**
 * The two decision functions at the heart of the abstraction — both FAIL-CLOSED.
 *
 *   - `satisfies(attestation, requirement)` — pure predicate: does the proven evidence meet
 *     every demanded property at its minimum verdict? An ABSENT property counts as `no`; a
 *     MALFORMED minimum verdict denies (fail-closed).
 *   - `verifyIntegrity(input, requirement, registry, options?)` — DENY-BY-DEFAULT dispatch: try
 *     each applicable provider in order; accept the first attestation that satisfies the
 *     requirement; otherwise return `undefined`. An optional per-provider timeout stops a
 *     never-resolving provider from stalling the dispatch.
 */
import { type IntegrityAttestation, type IntegrityInput, type IntegrityRequirement, type IntegrityVerifier } from "./types.js";
/**
 * Does `attestation` satisfy `requirement`?
 *
 * TRUE iff for every `(property, min)` in `requirement.requires`,
 * `rank(attestation.achieved.get(property) ?? "no") >= rank(min)`.
 *
 * Fail-closed properties:
 *   - a property REQUIRED but ABSENT from `achieved` is treated as verdict `no` (rank 0), so a
 *     missing property can never satisfy a `partial`/`yes` demand;
 *   - a MALFORMED minimum verdict (not one of `yes`/`partial`/`no` — e.g. a typo'd `"yees"`)
 *     DENIES the whole requirement rather than ranking `no` and becoming a vacuous demand. A
 *     malformed requirement is a caller bug; failing closed surfaces it instead of silently
 *     passing (`requireProfile` only ever produces valid minimums — this guards hand-built maps);
 *   - an EMPTY requirement (`requires.size === 0`) is vacuously satisfied — it demands nothing,
 *     which is the intended semantics of the `IL0-none` profile ("data as found").
 */
export declare function satisfies(attestation: IntegrityAttestation, requirement: IntegrityRequirement): boolean;
/** Options for {@link verifyIntegrity}. */
export interface VerifyIntegrityOptions {
    /**
     * Optional wall-clock cap (ms) on EACH provider's `verify`. When set, a provider that does not
     * settle within the cap is SKIPPED (fail-closed → the dispatch proceeds to the next provider),
     * so a buggy/hostile provider that never resolves cannot stall verification or mask a later
     * valid provider. Omit for no timeout (the default). Note: JavaScript cannot cancel the
     * underlying work — the timed-out provider's promise is abandoned (its late settlement is
     * swallowed), only the DISPATCH moves on.
     */
    readonly providerTimeoutMs?: number;
}
/**
 * DENY-BY-DEFAULT integrity verification over a provider registry.
 *
 * Tries each provider in `registry` order for which `canAttempt(input)` is true, awaits its
 * `verify`, and returns the FIRST attestation that `satisfies` the requirement. Returns
 * `undefined` when no provider yields a satisfying attestation — the caller (e.g. a mandate
 * executor) then refuses. Registry ORDER is the caller's trust order, exactly like the auth
 * verifier's `trustedIssuers`.
 *
 * Fail-closed properties (this is the security-critical surface):
 *   - a provider whose `canAttempt` THROWS is skipped (treated as not-applicable);
 *   - a provider whose `verify` THROWS or REJECTS is skipped (never yields acceptance) — a
 *     buggy/hostile provider cannot crash the dispatch and cannot mask a later good provider;
 *   - a provider whose `verify` does not settle within `options.providerTimeoutMs` (when set) is
 *     skipped, so a never-resolving provider cannot stall the dispatch;
 *   - a provider that returns a non-satisfying attestation, or a failure, is skipped;
 *   - if the registry is empty, or nothing satisfies, the result is `undefined` (deny).
 *
 * Note: this returns only the ATTESTATION (or `undefined`). Per-provider failure diagnostics are
 * available by calling a provider's `verify` directly; `verifyIntegrity` deliberately reduces to
 * accept-or-deny so it cannot leak a partial/rejected result into an accept path.
 */
export declare function verifyIntegrity(input: IntegrityInput, requirement: IntegrityRequirement, registry: Iterable<IntegrityVerifier>, options?: VerifyIntegrityOptions): Promise<IntegrityAttestation | undefined>;
