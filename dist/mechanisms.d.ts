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
import type { IntegrityPropertyIri, Verdict } from "./vocab.js";
/** TLS / DPoP-bound retrieval channel — integrity of the channel only, does not survive copying. */
export declare const MECH_TRANSPORT_TLS_DPOP: "transport/tls-dpop";
/** RDFC-1.0 canonical-graph digest vs a trusted reference — the solid-a2a hash-pinned pattern. */
export declare const MECH_CONTENT_HASH_RDFC: "content-hash/rdfc-1.0";
/** Detached JWS (ed25519) over the RDFC-1.0 canonical graph. */
export declare const MECH_JWS_ED25519_RDFC: "jws/ed25519-rdfc-1.0";
/** W3C VC Data Integrity, `eddsa-rdfc-2022` cryptosuite. */
export declare const MECH_VC_DI_EDDSA: "vc-di/eddsa-rdfc-2022";
/** W3C VC Data Integrity, `ecdsa-rdfc-2019` cryptosuite. */
export declare const MECH_VC_DI_ECDSA: "vc-di/ecdsa-rdfc-2019";
/** W3C VC Data Integrity, `vc-di-bbs` (BBS) cryptosuite — selective disclosure + unlinkable. */
export declare const MECH_VC_DI_BBS: "vc-di/bbs";
/** SD-JWT-VC (IETF) selective-disclosure JWT credential. */
export declare const MECH_SD_JWT_VC: "sd-jwt-vc";
/** ZK-over-SPARQL (the SPARQ future suite). */
export declare const MECH_ZK_SPARQL: "zk-sparql";
/** ML-DSA / lattice signature suites (FIPS 204) — future; NOT YET a sparq `sig-impl:` instance. */
export declare const MECH_ML_DSA: "ml-dsa";
/**
 * The §A.4 matrix as data. `MECHANISM_ASSERTIONS[mechanismId]` is the capability ceiling for
 * that mechanism (see the module note — a ceiling, not an attestation).
 */
export declare const MECHANISM_ASSERTIONS: Readonly<Record<string, ReadonlyMap<IntegrityPropertyIri, Verdict>>>;
