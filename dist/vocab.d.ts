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
 */
export declare function rank(v: Verdict | undefined): 0 | 1 | 2;
/** The @jeswr placeholder vocabulary namespace for integrity properties. */
export declare const INTEGRITY_NS: "https://w3id.org/jeswr/integrity#";
/**
 * Integrity/origin assured only for the retrieval channel (TLS, DPoP-bound); does NOT survive
 * copying. PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export declare const TRANSPORT_ORIGIN_AUTH: IntegrityPropertyIri;
/**
 * The artifact is bound to a specific canonical content (RDFC-1.0 digest / bytes hash).
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export declare const CONTENT_BINDING: IntegrityPropertyIri;
/**
 * Any post-attestation modification is detectable by a holder.
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export declare const TAMPER_EVIDENCE: IntegrityPropertyIri;
/**
 * The content is bound to an identified key/identity (issuer / WebID).
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export declare const AUTHORSHIP_BINDING: IntegrityPropertyIri;
/**
 * Verification needs no callback to the origin at check time.
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export declare const OFFLINE_VERIFIABILITY: IntegrityPropertyIri;
/**
 * Validity window + status (revocation / suspension) checked, fail-closed.
 * PROPOSED base property — not yet in sparq `sec-prop:`.
 */
export declare const REVOCATION_FRESHNESS: IntegrityPropertyIri;
/** aligns to sparq `sec-prop:Unlinkability` (category: informationDisclosure). */
export declare const UNLINKABILITY: IntegrityPropertyIri;
/** aligns to sparq `sec-prop:SourceCredentialDisclosure` (category: informationDisclosure). */
export declare const SOURCE_CREDENTIAL_DISCLOSURE: IntegrityPropertyIri;
/** aligns to sparq `sec-prop:PostQuantumForgery` (category: formalAnalysisPriority). */
export declare const POST_QUANTUM_FORGERY: IntegrityPropertyIri;
/** aligns to sparq `sec-prop:PostQuantumSnooping` (category: formalAnalysisPriority). */
export declare const POST_QUANTUM_SNOOPING: IntegrityPropertyIri;
/** aligns to sparq `sec-prop:SignatureTypeLeakage` (category: informationDisclosure). */
export declare const SIGNATURE_TYPE_LEAKAGE: IntegrityPropertyIri;
/** aligns to sparq `sec-prop:ProofSizeLeakage` (category: informationDisclosure). */
export declare const PROOF_SIZE_LEAKAGE: IntegrityPropertyIri;
/** aligns to sparq `sec-prop:ValidityPeriodLeakage` (category: informationDisclosure). */
export declare const VALIDITY_PERIOD_LEAKAGE: IntegrityPropertyIri;
/** aligns to sparq `sec-prop:CircuitAudit` (category: deploymentSpec). */
export declare const CIRCUIT_AUDIT: IntegrityPropertyIri;
/** The six proposed base-tier integrity properties (§A.2), frozen. */
export declare const BASE_PROPERTIES: readonly IntegrityPropertyIri[];
/** The eight advanced-tier integrity properties mirrored from sparq `sec-prop:`, frozen. */
export declare const ADVANCED_PROPERTIES: readonly IntegrityPropertyIri[];
/** All fourteen known integrity properties (base ∪ advanced), frozen. */
export declare const ALL_PROPERTIES: readonly IntegrityPropertyIri[];
