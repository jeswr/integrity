// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * The two decision functions at the heart of the abstraction — both FAIL-CLOSED.
 *
 *   - `satisfies(attestation, requirement)` — pure predicate: does the proven evidence meet
 *     every demanded property at its minimum verdict? An ABSENT property counts as `no`.
 *   - `verifyIntegrity(input, requirement, registry)` — DENY-BY-DEFAULT dispatch: try each
 *     applicable provider in order; accept the first attestation that satisfies the
 *     requirement; otherwise return `undefined`.
 */
import { isAttestation, } from "./types.js";
import { rank } from "./vocab.js";
/**
 * Does `attestation` satisfy `requirement`?
 *
 * TRUE iff for every `(property, min)` in `requirement.requires`,
 * `rank(attestation.achieved.get(property) ?? "no") >= rank(min)`.
 *
 * Fail-closed properties:
 *   - a property REQUIRED but ABSENT from `achieved` is treated as verdict `no` (rank 0), so a
 *     missing property can never satisfy a `partial`/`yes` demand;
 *   - an EMPTY requirement (`requires.size === 0`) is vacuously satisfied — it demands nothing,
 *     which is the intended semantics of the `IL0-none` profile ("data as found").
 */
export function satisfies(attestation, requirement) {
    for (const [property, min] of requirement.requires) {
        const achieved = attestation.achieved.get(property);
        if (rank(achieved) < rank(min)) {
            return false;
        }
    }
    return true;
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
 *   - a provider that returns a non-satisfying attestation, or a failure, is skipped;
 *   - if the registry is empty, or nothing satisfies, the result is `undefined` (deny).
 *
 * Note: this returns only the ATTESTATION (or `undefined`). Per-provider failure diagnostics are
 * available by calling a provider's `verify` directly; `verifyIntegrity` deliberately reduces to
 * accept-or-deny so it cannot leak a partial/rejected result into an accept path.
 */
export async function verifyIntegrity(input, requirement, registry) {
    for (const provider of registry) {
        let applicable = false;
        try {
            applicable = provider.canAttempt(input) === true;
        }
        catch {
            // A throwing `canAttempt` is treated as "cannot attempt" — fail-closed.
            applicable = false;
        }
        if (!applicable) {
            continue;
        }
        let result;
        try {
            result = await provider.verify(input);
        }
        catch {
            // A thrown/rejected `verify` never yields acceptance — fail-closed, try the next provider.
            continue;
        }
        if (isAttestation(result) && satisfies(result, requirement)) {
            return result;
        }
        // Non-satisfying attestation or an IntegrityFailure — deny this provider, try the next.
    }
    return undefined;
}
