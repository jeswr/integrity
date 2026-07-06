// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
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
import { isAttestation, } from "./types.js";
import { isVerdict, rank } from "./vocab.js";
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
export function satisfies(attestation, requirement) {
    for (const [property, min] of requirement.requires) {
        if (!isVerdict(min)) {
            // Malformed requirement — cannot be satisfied. Fail-closed (never treat as "don't care").
            return false;
        }
        const achieved = attestation.achieved.get(property);
        if (rank(achieved) < rank(min)) {
            return false;
        }
    }
    return true;
}
const TIMED_OUT = Symbol("integrity.providerTimeout");
/** Resolve to `TIMED_OUT` if `promise` has not settled within `ms`; never rejects. */
function withTimeout(promise, ms) {
    // Swallow a late rejection so abandoning the race cannot raise an unhandled rejection.
    promise.catch(() => { });
    let timer;
    const timeout = new Promise((resolve) => {
        timer = setTimeout(() => resolve(TIMED_OUT), ms);
    });
    return Promise.race([promise, timeout]).finally(() => {
        if (timer !== undefined) {
            clearTimeout(timer);
        }
    });
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
export async function verifyIntegrity(input, requirement, registry, options) {
    const timeoutMs = typeof options?.providerTimeoutMs === "number" &&
        Number.isFinite(options.providerTimeoutMs) &&
        options.providerTimeoutMs > 0
        ? options.providerTimeoutMs
        : undefined;
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
            result =
                timeoutMs === undefined
                    ? await provider.verify(input)
                    : await withTimeout(provider.verify(input), timeoutMs);
        }
        catch {
            // A thrown/rejected `verify` never yields acceptance — fail-closed, try the next provider.
            continue;
        }
        if (result === TIMED_OUT) {
            // A stalled provider — fail-closed, try the next provider.
            continue;
        }
        if (isAttestation(result) && satisfies(result, requirement)) {
            return result;
        }
        // Non-satisfying attestation or an IntegrityFailure — deny this provider, try the next.
    }
    return undefined;
}
