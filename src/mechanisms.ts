// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * The default mechanism → property assertion table (§A.4), shipped as DATA.
 *
 * This is exactly the reified-assertion matrix the abstraction ships as its registry defaults.
 * Each advanced-tier cell cites the sparq `sig-impl:` assertion it mirrors (see ALIGNMENT.md);
 * base-tier cells are the proposed §A.2 extension.
 *
 * ────────────────────────────────────────────────────────────────────────────────────────────
 * IMPORTANT — this is a CAPABILITY CEILING, NOT an attestation.
 *
 * A cell verdict is the BEST a mechanism can confer WHEN its verification FULLY succeeds
 * (including conditions noted inline, e.g. RevocationFreshness requires a live status check). It
 * is NOT proof that any particular artifact achieved it. A provider MUST verify each property
 * for real and emit an {@link IntegrityAttestation} of what it ACTUALLY proved — it may use these
 * maps as an upper bound to intersect against, but must never copy a ceiling into an attestation
 * for a property it did not check (that would be an integrity claim the mechanism did not earn).
 * The shipped `./rdfc` provider follows this rule: it only asserts the `content-hash/rdfc-1.0`
 * cells AFTER the trusted-reference digest matches.
 * ────────────────────────────────────────────────────────────────────────────────────────────
 *
 * Verdicts are the sparq enum {yes, partial, no}. A property ABSENT from a mechanism's map means
 * "not conferred" (fail-closed / rank `no`); an explicit `no` additionally records a CITED KNOWN
 * failure (e.g. ed25519 unlinkability). Leakage properties (SignatureType/ProofSize/ValidityPeriod
 * Leakage, PostQuantumSnooping) are intentionally NOT asserted here — the shipped profiles never
 * gate on them and their verdict polarity follows sparq's assertion semantics, which we do not
 * over-commit to pre-flip.
 */

import { frozenVerdictMap } from "./internal.js";
import type { IntegrityPropertyIri, Verdict } from "./vocab.js";
import {
  AUTHORSHIP_BINDING,
  CONTENT_BINDING,
  OFFLINE_VERIFIABILITY,
  POST_QUANTUM_FORGERY,
  REVOCATION_FRESHNESS,
  SOURCE_CREDENTIAL_DISCLOSURE,
  TAMPER_EVIDENCE,
  TRANSPORT_ORIGIN_AUTH,
  UNLINKABILITY,
} from "./vocab.js";

// --- Mechanism ids (sig-impl-style) ---------------------------------------------------------

/** TLS / DPoP-bound retrieval channel — integrity of the channel only, does not survive copying. */
export const MECH_TRANSPORT_TLS_DPOP = "transport/tls-dpop" as const;
/** RDFC-1.0 canonical-graph digest vs a trusted reference — the solid-a2a hash-pinned pattern. */
export const MECH_CONTENT_HASH_RDFC = "content-hash/rdfc-1.0" as const;
/** Detached JWS (ed25519) over the RDFC-1.0 canonical graph. */
export const MECH_JWS_ED25519_RDFC = "jws/ed25519-rdfc-1.0" as const;
/** W3C VC Data Integrity, `eddsa-rdfc-2022` cryptosuite. */
export const MECH_VC_DI_EDDSA = "vc-di/eddsa-rdfc-2022" as const;
/** W3C VC Data Integrity, `ecdsa-rdfc-2019` cryptosuite. */
export const MECH_VC_DI_ECDSA = "vc-di/ecdsa-rdfc-2019" as const;
/** W3C VC Data Integrity, `vc-di-bbs` (BBS) cryptosuite — selective disclosure + unlinkable. */
export const MECH_VC_DI_BBS = "vc-di/bbs" as const;
/** SD-JWT-VC (IETF) selective-disclosure JWT credential. */
export const MECH_SD_JWT_VC = "sd-jwt-vc" as const;
/** ZK-over-SPARQL (the SPARQ future suite). */
export const MECH_ZK_SPARQL = "zk-sparql" as const;
/** ML-DSA / lattice signature suites (FIPS 204) — future; NOT YET a sparq `sig-impl:` instance. */
export const MECH_ML_DSA = "ml-dsa" as const;

// Shared base-tier cell block for the graph-signature mechanisms (JWS + all VC-DI + ZK + ML-DSA):
// content-bound + tamper-evident + offline-verifiable + author-bound. RevocationFreshness is added
// per-mechanism as a CONDITIONAL cell (see note above).
const GRAPH_SIGNATURE_BASE: readonly (readonly [IntegrityPropertyIri, Verdict])[] = [
  [CONTENT_BINDING, "yes"],
  [TAMPER_EVIDENCE, "yes"],
  [OFFLINE_VERIFIABILITY, "yes"],
  [AUTHORSHIP_BINDING, "yes"],
];

/**
 * The §A.4 matrix as data. `MECHANISM_ASSERTIONS[mechanismId]` is the capability ceiling for
 * that mechanism (see the module note — a ceiling, not an attestation).
 */
export const MECHANISM_ASSERTIONS: Readonly<
  Record<string, ReadonlyMap<IntegrityPropertyIri, Verdict>>
> = Object.freeze({
  // Transport: origin/integrity for the channel only.
  [MECH_TRANSPORT_TLS_DPOP]: frozenVerdictMap([[TRANSPORT_ORIGIN_AUTH, "yes"]]),

  // Content hash vs trusted reference (solid-a2a pattern) → IL2.
  [MECH_CONTENT_HASH_RDFC]: frozenVerdictMap([
    [CONTENT_BINDING, "yes"],
    [TAMPER_EVIDENCE, "yes"],
    [OFFLINE_VERIFIABILITY, "yes"],
    // hash-based: there is no signature to forge and SHA-2 collision resistance is only mildly
    // weakened by Grover (~2^128), so tamper-evidence is PQ-forgery-resistant by construction.
    // NOT a sig-impl instance — `sec-prop:` assertions cover signature schemes, not hashes.
    [POST_QUANTUM_FORGERY, "yes"],
  ]),

  // Detached JWS ed25519 over RDFC-1.0 → IL3 (author-bound). RevocationFreshness only "with a
  // status seam", so it is NOT in the ceiling here (a status-checking wrapper adds it).
  [MECH_JWS_ED25519_RDFC]: frozenVerdictMap([
    ...GRAPH_SIGNATURE_BASE,
    // sig-impl `assert-ed25519-unlinkability` = no (ed25519 is deterministic; the signature value
    // is replayed verbatim across presentations).
    [UNLINKABILITY, "no"],
    // sig-impl `sig-impl:Ed25519` postQuantum = false.
    [POST_QUANTUM_FORGERY, "no"],
  ]),

  // VC-DI eddsa-rdfc-2022 → IL4 with a live status check. Unlinkability/PQ as ed25519.
  [MECH_VC_DI_EDDSA]: frozenVerdictMap([
    ...GRAPH_SIGNATURE_BASE,
    // CONDITIONAL: only when the provider runs a live `resolveStatus` check that passes.
    [REVOCATION_FRESHNESS, "yes"],
    // sig-impl `assert-ed25519-unlinkability` = no.
    [UNLINKABILITY, "no"],
    // sig-impl `sig-impl:Ed25519` postQuantum = false.
    [POST_QUANTUM_FORGERY, "no"],
  ]),

  // VC-DI ecdsa-rdfc-2019 → IL4 with a live status check.
  [MECH_VC_DI_ECDSA]: frozenVerdictMap([
    ...GRAPH_SIGNATURE_BASE,
    // CONDITIONAL: live `resolveStatus`.
    [REVOCATION_FRESHNESS, "yes"],
    // sig-impl `assert-ecdsa-unlinkability` = no.
    [UNLINKABILITY, "no"],
    // sig-impl `sig-impl:Ecdsa` postQuantum = false.
    [POST_QUANTUM_FORGERY, "no"],
  ]),

  // VC-DI BBS → IL4 + selective disclosure + unlinkable, but not PQ-forgery-resistant.
  [MECH_VC_DI_BBS]: frozenVerdictMap([
    ...GRAPH_SIGNATURE_BASE,
    // CONDITIONAL: live `resolveStatus`.
    [REVOCATION_FRESHNESS, "yes"],
    // BBS proofs disclose a chosen subset — full source-credential-disclosure control.
    [SOURCE_CREDENTIAL_DISCLOSURE, "yes"],
    // sig-impl `assert-bbs-unlinkability` = yes.
    [UNLINKABILITY, "yes"],
    // sig-impl `assert-bbs-pq-forgery` = no (BbsPlus postQuantum = false).
    [POST_QUANTUM_FORGERY, "no"],
  ]),

  // SD-JWT-VC → IL4 + partial selective disclosure.
  [MECH_SD_JWT_VC]: frozenVerdictMap([
    ...GRAPH_SIGNATURE_BASE,
    // CONDITIONAL: live `resolveStatus`.
    [REVOCATION_FRESHNESS, "yes"],
    // sig-impl `assert-sdjwt-source-disclosure` = partial (per-claim salted disclosure; the issuer
    // signature over the full claim set is still presented, so disclosure control is partial).
    [SOURCE_CREDENTIAL_DISCLOSURE, "partial"],
    // SD-JWT-VC binds to a conventional signature scheme — not unlinkable.
    [UNLINKABILITY, "no"],
  ]),

  // ZK-over-SPARQL (SPARQ, future) → IL4 + selective disclosure + unlinkable (design goal); NOT
  // PQ-forgery-resistant today, and CircuitAudit (a `sec-prop:` deploymentSpec property) applies
  // as an OPEN property — deliberately left ABSENT (not yet attained), not asserted `yes`.
  [MECH_ZK_SPARQL]: frozenVerdictMap([
    ...GRAPH_SIGNATURE_BASE,
    // CONDITIONAL: live `resolveStatus`.
    [REVOCATION_FRESHNESS, "yes"],
    [SOURCE_CREDENTIAL_DISCLOSURE, "yes"],
    // design goal — the ZK presentation is unlinkable.
    [UNLINKABILITY, "yes"],
    // no today — the underlying signature suite is not yet PQ.
    [POST_QUANTUM_FORGERY, "no"],
  ]),

  // ML-DSA / lattice (FIPS 204), future → IL4 + PQ-forgery-resistant. NOT YET a sparq sig-impl
  // instance — the PQ-yes column currently has no instance (§E ask (c)).
  [MECH_ML_DSA]: frozenVerdictMap([
    ...GRAPH_SIGNATURE_BASE,
    // CONDITIONAL: live `resolveStatus`.
    [REVOCATION_FRESHNESS, "yes"],
    // lattice signatures are PQ-secure against forgery.
    [POST_QUANTUM_FORGERY, "yes"],
    // ML-DSA is a conventional (linkable) signature — not unlinkable.
    [UNLINKABILITY, "no"],
  ]),
});
