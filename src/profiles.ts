// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * The profile ladder (§A.3) — named property-set profiles, NOT an ordinal enum.
 *
 * A "profile" (a.k.a. an "integrity level") is a `Map<property, minVerdict>`. The common
 * profiles IL0-IL4 happen to NEST, but that is a fact about these particular profiles, not a
 * total order on the space: the add-on flags (`+SelectiveDisclosure`, `+Unlinkability`,
 * `+PostQuantumForgery`, `+CircuitAudit`) are ORTHOGONAL and compose into any base profile —
 * the real sparq ontology proves e.g. Unlinkability ⊥ PostQuantumForgery.
 *
 * PLACEHOLDER: these profiles must be reconciled with the sparq ontology once the six base
 * properties (§A.2) land in `sec-prop:` and the `zkp-sparql` IRIs go public (see ALIGNMENT.md).
 */

import { frozenVerdictMap } from "./internal.js";
import type { IntegrityRequirement } from "./types.js";
import type { IntegrityPropertyIri, Verdict } from "./vocab.js";
import {
  AUTHORSHIP_BINDING,
  CIRCUIT_AUDIT,
  CONTENT_BINDING,
  OFFLINE_VERIFIABILITY,
  POST_QUANTUM_FORGERY,
  REVOCATION_FRESHNESS,
  rank,
  SOURCE_CREDENTIAL_DISCLOSURE,
  TAMPER_EVIDENCE,
  TRANSPORT_ORIGIN_AUTH,
  UNLINKABILITY,
} from "./vocab.js";

/** The stronger of two verdicts, by `rank`. */
export function maxVerdict(a: Verdict, b: Verdict): Verdict {
  return rank(a) >= rank(b) ? a : b;
}

// --- Profile names (used as the advisory `IntegrityRequirement.profile` label) --------------

export const IL0_NONE = "IL0-none" as const;
export const IL1_TRANSPORT = "IL1-transport" as const;
export const IL2_CONTENT_BOUND = "IL2-content-bound" as const;
export const IL3_AUTHOR_BOUND = "IL3-author-bound" as const;
export const IL4_AUTHOR_BOUND_FRESH = "IL4-author-bound-fresh" as const;

export type IntegrityProfileName =
  | typeof IL0_NONE
  | typeof IL1_TRANSPORT
  | typeof IL2_CONTENT_BOUND
  | typeof IL3_AUTHOR_BOUND
  | typeof IL4_AUTHOR_BOUND_FRESH;

// --- Add-on flag names (orthogonal, composed into any base profile) -------------------------

export const ADDON_SELECTIVE_DISCLOSURE = "+SelectiveDisclosure" as const;
export const ADDON_UNLINKABILITY = "+Unlinkability" as const;
export const ADDON_POST_QUANTUM_FORGERY = "+PostQuantumForgery" as const;
export const ADDON_CIRCUIT_AUDIT = "+CircuitAudit" as const;

export type IntegrityAddonName =
  | typeof ADDON_SELECTIVE_DISCLOSURE
  | typeof ADDON_UNLINKABILITY
  | typeof ADDON_POST_QUANTUM_FORGERY
  | typeof ADDON_CIRCUIT_AUDIT;

// --- The profile maps (§A.3) ----------------------------------------------------------------

// IL2 content-bound: bound to a canonical content + tamper-evident + offline-verifiable
// GIVEN a trusted reference (the reference itself carries the AuthorshipBinding).
const IL2_ENTRIES: readonly (readonly [IntegrityPropertyIri, Verdict])[] = [
  [CONTENT_BINDING, "yes"],
  [TAMPER_EVIDENCE, "yes"],
  [OFFLINE_VERIFIABILITY, "yes"],
];

/**
 * The nesting ladder IL0 ⊂ IL1(≠) ⊂ IL2 ⊂ IL3 ⊂ IL4. (IL1 is off the IL2 chain — transport
 * auth does not survive copying — but is included as a named rung.)
 */
export const INTEGRITY_PROFILES: Readonly<
  Record<IntegrityProfileName, ReadonlyMap<IntegrityPropertyIri, Verdict>>
> = Object.freeze({
  [IL0_NONE]: frozenVerdictMap([]),
  [IL1_TRANSPORT]: frozenVerdictMap([[TRANSPORT_ORIGIN_AUTH, "yes"]]),
  [IL2_CONTENT_BOUND]: frozenVerdictMap(IL2_ENTRIES),
  [IL3_AUTHOR_BOUND]: frozenVerdictMap([...IL2_ENTRIES, [AUTHORSHIP_BINDING, "yes"]]),
  [IL4_AUTHOR_BOUND_FRESH]: frozenVerdictMap([
    ...IL2_ENTRIES,
    [AUTHORSHIP_BINDING, "yes"],
    [REVOCATION_FRESHNESS, "yes"],
  ]),
});

/** The orthogonal add-on flags (§A.3), each a single-property demand composed into a base. */
export const INTEGRITY_ADDONS: Readonly<
  Record<IntegrityAddonName, ReadonlyMap<IntegrityPropertyIri, Verdict>>
> = Object.freeze({
  // "+SelectiveDisclosure" ≈ SourceCredentialDisclosure ≥ partial (§A.3).
  [ADDON_SELECTIVE_DISCLOSURE]: frozenVerdictMap([[SOURCE_CREDENTIAL_DISCLOSURE, "partial"]]),
  [ADDON_UNLINKABILITY]: frozenVerdictMap([[UNLINKABILITY, "yes"]]),
  [ADDON_POST_QUANTUM_FORGERY]: frozenVerdictMap([[POST_QUANTUM_FORGERY, "yes"]]),
  [ADDON_CIRCUIT_AUDIT]: frozenVerdictMap([[CIRCUIT_AUDIT, "yes"]]),
});

/**
 * Merge verdict maps into a FRESH mutable-internally / returned-readonly Map, taking the
 * STRONGER (max `rank`) demand for any property present in more than one input.
 */
export function composeProfileMap(
  ...maps: ReadonlyMap<IntegrityPropertyIri, Verdict>[]
): ReadonlyMap<IntegrityPropertyIri, Verdict> {
  const out = new Map<IntegrityPropertyIri, Verdict>();
  for (const map of maps) {
    for (const [property, verdict] of map) {
      const existing = out.get(property);
      out.set(property, existing === undefined ? verdict : maxVerdict(existing, verdict));
    }
  }
  return out;
}

/**
 * Build an {@link IntegrityRequirement} from a named base profile plus zero or more orthogonal
 * add-on flags. The returned requirement has a FRESH `requires` map (mutating it cannot corrupt
 * the shared profile) and a composed `profile` label for audit/logging, e.g.
 * `IL4-author-bound-fresh+Unlinkability`.
 */
export function requireProfile(
  profile: IntegrityProfileName,
  ...addons: IntegrityAddonName[]
): IntegrityRequirement {
  const base = INTEGRITY_PROFILES[profile];
  const addonMaps = addons.map((a) => INTEGRITY_ADDONS[a]);
  const requires = composeProfileMap(base, ...addonMaps);
  const label = addons.length > 0 ? `${profile}${addons.join("")}` : profile;
  return { profile: label, requires };
}
