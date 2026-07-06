// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * Integrity vocabulary — the atoms of the abstraction.
 *
 * The model mirrors the sparq security & integrity type ontologies (see ALIGNMENT.md):
 *   - a PROPERTY is what a mechanism may attain / partially attain / fail  (sec-prop pattern)
 *   - a VERDICT is one of {yes, partial, no}                               (sig-impl pattern)
 *   - a REQUIREMENT pulls on a set of properties, each at a minimum verdict (sec-req pattern)
 *
 * IRIs here are minted under the @jeswr placeholder namespace
 * `https://w3id.org/jeswr/integrity#` (suite house rule: new vocab terms live under
 * `https://w3id.org/jeswr/…`). They are NOT the private `https://w3id.org/zkp-sparql/…`
 * IRIs — that repo is PRIVATE / do-not-publish, so we mirror the STRUCTURE and defer
 * term-level `owl:equivalent*` alignment until its public-flip (sparq-org/sparq#1682).
 * Each advanced-tier constant below cites the sparq `sec-prop:` term it aligns to; the
 * full pending alignment table is ALIGNMENT.md.
 */
/**
 * Total order on verdicts for the fail-closed comparison in `satisfies`.
 * `no` (0) < `partial` (1) < `yes` (2). Any unrecognised value ranks as `no` (fail-closed).
 *
 * NOTE: ranking an unknown value as `no` is the correct fail-closed behaviour for an ACHIEVED
 * verdict (a malformed proof helps satisfy nothing). It is NOT safe for a REQUIRED MINIMUM —
 * a typo'd minimum (e.g. `"yees"`) would then rank `no` and make the demand vacuous. `satisfies`
 * therefore guards the minimum with {@link isVerdict} and denies a malformed requirement.
 */
export function rank(v) {
    switch (v) {
        case "yes":
            return 2;
        case "partial":
            return 1;
        default:
            // `no`, `undefined`, or any unrecognised value — fail-closed.
            return 0;
    }
}
/** True iff `v` is one of the three recognised verdict strings. */
export function isVerdict(v) {
    return v === "yes" || v === "partial" || v === "no";
}
/** The @jeswr placeholder vocabulary namespace for integrity properties. */
export const INTEGRITY_NS = "https://w3id.org/jeswr/integrity#";
// ---------------------------------------------------------------------------
// Base tier (§A.2) — the presupposed integrity properties every suite requirement
// actually gates on. Proposed as a minimal sparq-side extension of `sec-prop:SecurityProperty`
// (six instances, zero new classes). Marked PLACEHOLDER-pending-reconciliation: their eventual
// canonical home is the zkp-sparql sec-prop module once the extension lands + the IRIs go public.
// ---------------------------------------------------------------------------
/**
 * Integrity/origin assured only for the retrieval channel (TLS, DPoP-bound); does NOT survive
 * copying. PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const TRANSPORT_ORIGIN_AUTH = `${INTEGRITY_NS}TransportOriginAuth`;
/**
 * The artifact is bound to a specific canonical content (RDFC-1.0 digest / bytes hash).
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const CONTENT_BINDING = `${INTEGRITY_NS}ContentBinding`;
/**
 * Any post-attestation modification is detectable by a holder.
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const TAMPER_EVIDENCE = `${INTEGRITY_NS}TamperEvidence`;
/**
 * The content is bound to an identified key/identity (issuer / WebID).
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const AUTHORSHIP_BINDING = `${INTEGRITY_NS}AuthorshipBinding`;
/**
 * Verification needs no callback to the origin at check time.
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const OFFLINE_VERIFIABILITY = `${INTEGRITY_NS}OfflineVerifiability`;
/**
 * Validity window + status (revocation / suspension) checked, fail-closed.
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const REVOCATION_FRESHNESS = `${INTEGRITY_NS}RevocationFreshness`;
// ---------------------------------------------------------------------------
// Advanced tier (§A) — mirrored VERBATIM (name-for-name) from the sparq `sec-prop:` module
// (`https://w3id.org/zkp-sparql/sec-prop#`, PRIVATE). These are the advanced privacy / PQ /
// leakage properties above the base tier. Each constant cites the `sec-prop:` term it aligns to;
// the pending `owl:equivalentClass`/`equivalentProperty` mapping is documented in ALIGNMENT.md.
// ---------------------------------------------------------------------------
/** aligns to sparq `sec-prop:Unlinkability` (category: informationDisclosure). */
export const UNLINKABILITY = `${INTEGRITY_NS}Unlinkability`;
/** aligns to sparq `sec-prop:SourceCredentialDisclosure` (category: informationDisclosure). */
export const SOURCE_CREDENTIAL_DISCLOSURE = `${INTEGRITY_NS}SourceCredentialDisclosure`;
/** aligns to sparq `sec-prop:PostQuantumForgery` (category: formalAnalysisPriority). */
export const POST_QUANTUM_FORGERY = `${INTEGRITY_NS}PostQuantumForgery`;
/** aligns to sparq `sec-prop:PostQuantumSnooping` (category: formalAnalysisPriority). */
export const POST_QUANTUM_SNOOPING = `${INTEGRITY_NS}PostQuantumSnooping`;
/** aligns to sparq `sec-prop:SignatureTypeLeakage` (category: informationDisclosure). */
export const SIGNATURE_TYPE_LEAKAGE = `${INTEGRITY_NS}SignatureTypeLeakage`;
/** aligns to sparq `sec-prop:ProofSizeLeakage` (category: informationDisclosure). */
export const PROOF_SIZE_LEAKAGE = `${INTEGRITY_NS}ProofSizeLeakage`;
/** aligns to sparq `sec-prop:ValidityPeriodLeakage` (category: informationDisclosure). */
export const VALIDITY_PERIOD_LEAKAGE = `${INTEGRITY_NS}ValidityPeriodLeakage`;
/** aligns to sparq `sec-prop:CircuitAudit` (category: deploymentSpec). */
export const CIRCUIT_AUDIT = `${INTEGRITY_NS}CircuitAudit`;
/** The six proposed base-tier integrity properties (§A.2), frozen. */
export const BASE_PROPERTIES = Object.freeze([
    TRANSPORT_ORIGIN_AUTH,
    CONTENT_BINDING,
    TAMPER_EVIDENCE,
    AUTHORSHIP_BINDING,
    OFFLINE_VERIFIABILITY,
    REVOCATION_FRESHNESS,
]);
/** The eight advanced-tier integrity properties mirrored from sparq `sec-prop:`, frozen. */
export const ADVANCED_PROPERTIES = Object.freeze([
    UNLINKABILITY,
    SOURCE_CREDENTIAL_DISCLOSURE,
    POST_QUANTUM_FORGERY,
    POST_QUANTUM_SNOOPING,
    SIGNATURE_TYPE_LEAKAGE,
    PROOF_SIZE_LEAKAGE,
    VALIDITY_PERIOD_LEAKAGE,
    CIRCUIT_AUDIT,
]);
/** All fourteen known integrity properties (base ∪ advanced), frozen. */
export const ALL_PROPERTIES = Object.freeze([
    ...BASE_PROPERTIES,
    ...ADVANCED_PROPERTIES,
]);
