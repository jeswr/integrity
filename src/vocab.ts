// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * Integrity vocabulary — the atoms of the abstraction.
 *
 * The model mirrors the sparq security & integrity type ontologies (see ALIGNMENT.md):
 *   - a PROPERTY is what a mechanism may attain / partially attain / fail  (sec-prop pattern)
 *   - a VERDICT is one of {yes, partial, no}                               (sig-impl pattern)
 *   - a REQUIREMENT pulls on a set of properties, each at a minimum verdict (sec-req pattern)
 *
 * IRIs here are minted under the @jeswr namespace `https://jeswr.org/ns/integrity#`
 * (suite house rule: mint jeswr namespaces under `jeswr.org`, served via the portfolio
 * `/ns` redirect layer — NEVER `w3id.org`). They are NOT the private
 * `https://w3id.org/zkp-sparql/…` IRIs — that repo is PRIVATE / do-not-publish, so we
 * mirror the STRUCTURE and defer term-level `owl:equivalent*` alignment until its
 * public-flip (sparq-org/sparq#1682). Each advanced-tier constant below cites the sparq
 * `sec-prop:` term it aligns to; the full pending alignment table is ALIGNMENT.md.
 */

/**
 * A verdict on whether a mechanism attains an integrity property.
 *
 * Mirrors the sparq `sig-impl:Assertion` verdict enum verbatim: `yes` / `partial` / `no`.
 * There is deliberately NO ordinal integrity "level" scalar — the real ontology proves the
 * property space is only partially ordered (e.g. Unlinkability ⊥ PostQuantumForgery), so an
 * "integrity level" is a NAMED property-set profile (see `profiles.ts`), not a number.
 */
export type Verdict = "yes" | "partial" | "no";

/** An integrity-property IRI (one of the exported constants below, or an aligned external IRI). */
export type IntegrityPropertyIri = string;

/**
 * Total order on verdicts for the fail-closed comparison in `satisfies`.
 * `no` (0) < `partial` (1) < `yes` (2). Any unrecognised value ranks as `no` (fail-closed).
 *
 * NOTE: ranking an unknown value as `no` is the correct fail-closed behaviour for an ACHIEVED
 * verdict (a malformed proof helps satisfy nothing). It is NOT safe for a REQUIRED MINIMUM —
 * a typo'd minimum (e.g. `"yees"`) would then rank `no` and make the demand vacuous. `satisfies`
 * therefore guards the minimum with {@link isVerdict} and denies a malformed requirement.
 */
export function rank(v: Verdict | undefined): 0 | 1 | 2 {
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
export function isVerdict(v: unknown): v is Verdict {
  return v === "yes" || v === "partial" || v === "no";
}

/** The @jeswr vocabulary namespace for integrity properties. */
export const INTEGRITY_NS = "https://jeswr.org/ns/integrity#" as const;

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
export const TRANSPORT_ORIGIN_AUTH: IntegrityPropertyIri = `${INTEGRITY_NS}TransportOriginAuth`;

/**
 * The artifact is bound to a specific canonical content (RDFC-1.0 digest / bytes hash).
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const CONTENT_BINDING: IntegrityPropertyIri = `${INTEGRITY_NS}ContentBinding`;

/**
 * Any post-attestation modification is detectable by a holder.
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const TAMPER_EVIDENCE: IntegrityPropertyIri = `${INTEGRITY_NS}TamperEvidence`;

/**
 * The content is bound to an identified key/identity (issuer / WebID).
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const AUTHORSHIP_BINDING: IntegrityPropertyIri = `${INTEGRITY_NS}AuthorshipBinding`;

/**
 * Verification needs no callback to the origin at check time.
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const OFFLINE_VERIFIABILITY: IntegrityPropertyIri = `${INTEGRITY_NS}OfflineVerifiability`;

/**
 * Validity window + status (revocation / suspension) checked, fail-closed.
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export const REVOCATION_FRESHNESS: IntegrityPropertyIri = `${INTEGRITY_NS}RevocationFreshness`;

// ---------------------------------------------------------------------------
// Advanced tier (§A) — mirrored VERBATIM (name-for-name) from the sparq `sec-prop:` module
// (`https://w3id.org/zkp-sparql/sec-prop#`, PRIVATE). These are the advanced privacy / PQ /
// leakage properties above the base tier. Each constant cites the `sec-prop:` term it aligns to;
// the pending `owl:equivalentClass`/`equivalentProperty` mapping is documented in ALIGNMENT.md.
// ---------------------------------------------------------------------------

/** aligns to sparq `sec-prop:Unlinkability` (category: informationDisclosure). */
export const UNLINKABILITY: IntegrityPropertyIri = `${INTEGRITY_NS}Unlinkability`;

/** aligns to sparq `sec-prop:SourceCredentialDisclosure` (category: informationDisclosure). */
export const SOURCE_CREDENTIAL_DISCLOSURE: IntegrityPropertyIri = `${INTEGRITY_NS}SourceCredentialDisclosure`;

/** aligns to sparq `sec-prop:PostQuantumForgery` (category: formalAnalysisPriority). */
export const POST_QUANTUM_FORGERY: IntegrityPropertyIri = `${INTEGRITY_NS}PostQuantumForgery`;

/** aligns to sparq `sec-prop:PostQuantumSnooping` (category: formalAnalysisPriority). */
export const POST_QUANTUM_SNOOPING: IntegrityPropertyIri = `${INTEGRITY_NS}PostQuantumSnooping`;

/** aligns to sparq `sec-prop:SignatureTypeLeakage` (category: informationDisclosure). */
export const SIGNATURE_TYPE_LEAKAGE: IntegrityPropertyIri = `${INTEGRITY_NS}SignatureTypeLeakage`;

/** aligns to sparq `sec-prop:ProofSizeLeakage` (category: informationDisclosure). */
export const PROOF_SIZE_LEAKAGE: IntegrityPropertyIri = `${INTEGRITY_NS}ProofSizeLeakage`;

/** aligns to sparq `sec-prop:ValidityPeriodLeakage` (category: informationDisclosure). */
export const VALIDITY_PERIOD_LEAKAGE: IntegrityPropertyIri = `${INTEGRITY_NS}ValidityPeriodLeakage`;

/** aligns to sparq `sec-prop:CircuitAudit` (category: deploymentSpec). */
export const CIRCUIT_AUDIT: IntegrityPropertyIri = `${INTEGRITY_NS}CircuitAudit`;

/** The six proposed base-tier integrity properties (§A.2), frozen. */
export const BASE_PROPERTIES: readonly IntegrityPropertyIri[] = Object.freeze([
  TRANSPORT_ORIGIN_AUTH,
  CONTENT_BINDING,
  TAMPER_EVIDENCE,
  AUTHORSHIP_BINDING,
  OFFLINE_VERIFIABILITY,
  REVOCATION_FRESHNESS,
]);

/** The eight advanced-tier integrity properties mirrored from sparq `sec-prop:`, frozen. */
export const ADVANCED_PROPERTIES: readonly IntegrityPropertyIri[] = Object.freeze([
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
export const ALL_PROPERTIES: readonly IntegrityPropertyIri[] = Object.freeze([
  ...BASE_PROPERTIES,
  ...ADVANCED_PROPERTIES,
]);
