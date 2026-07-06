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
import type { IntegrityRequirement } from "./types.js";
import type { IntegrityPropertyIri, Verdict } from "./vocab.js";
/** The stronger of two verdicts, by `rank`. */
export declare function maxVerdict(a: Verdict, b: Verdict): Verdict;
export declare const IL0_NONE: "IL0-none";
export declare const IL1_TRANSPORT: "IL1-transport";
export declare const IL2_CONTENT_BOUND: "IL2-content-bound";
export declare const IL3_AUTHOR_BOUND: "IL3-author-bound";
export declare const IL4_AUTHOR_BOUND_FRESH: "IL4-author-bound-fresh";
export type IntegrityProfileName = typeof IL0_NONE | typeof IL1_TRANSPORT | typeof IL2_CONTENT_BOUND | typeof IL3_AUTHOR_BOUND | typeof IL4_AUTHOR_BOUND_FRESH;
export declare const ADDON_SELECTIVE_DISCLOSURE: "+SelectiveDisclosure";
export declare const ADDON_UNLINKABILITY: "+Unlinkability";
export declare const ADDON_POST_QUANTUM_FORGERY: "+PostQuantumForgery";
export declare const ADDON_CIRCUIT_AUDIT: "+CircuitAudit";
export type IntegrityAddonName = typeof ADDON_SELECTIVE_DISCLOSURE | typeof ADDON_UNLINKABILITY | typeof ADDON_POST_QUANTUM_FORGERY | typeof ADDON_CIRCUIT_AUDIT;
/**
 * The nesting ladder IL0 ⊂ IL1(≠) ⊂ IL2 ⊂ IL3 ⊂ IL4. (IL1 is off the IL2 chain — transport
 * auth does not survive copying — but is included as a named rung.)
 */
export declare const INTEGRITY_PROFILES: Readonly<Record<IntegrityProfileName, ReadonlyMap<IntegrityPropertyIri, Verdict>>>;
/** The orthogonal add-on flags (§A.3), each a single-property demand composed into a base. */
export declare const INTEGRITY_ADDONS: Readonly<Record<IntegrityAddonName, ReadonlyMap<IntegrityPropertyIri, Verdict>>>;
/**
 * Merge verdict maps into a FRESH mutable-internally / returned-readonly Map, taking the
 * STRONGER (max `rank`) demand for any property present in more than one input.
 */
export declare function composeProfileMap(...maps: ReadonlyMap<IntegrityPropertyIri, Verdict>[]): ReadonlyMap<IntegrityPropertyIri, Verdict>;
/**
 * Build an {@link IntegrityRequirement} from a named base profile plus zero or more orthogonal
 * add-on flags. The returned requirement has a FRESH `requires` map (mutating it cannot corrupt
 * the shared profile) and a composed `profile` label for audit/logging, e.g.
 * `IL4-author-bound-fresh+Unlinkability`.
 */
export declare function requireProfile(profile: IntegrityProfileName, ...addons: IntegrityAddonName[]): IntegrityRequirement;
