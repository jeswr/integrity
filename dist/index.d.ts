/**
 * `@jeswr/integrity` — the integrity abstraction seam.
 *
 * "Integrity" is the top-level concept: CERTAINTY THAT DATA MEETS A STATED INTEGRITY REQUIREMENT.
 * Verifiable Credentials are ONE mechanism for obtaining high-integrity data among several (as
 * HTTP is one transport; as many signature algorithms serve authentication). Code depends on this
 * abstraction, never on VC directly — mirroring the issuer-agnostic auth verifier.
 *
 * This ROOT entry is ZERO-DEPENDENCY and browser-safe. The one built-in provider (a trusted-
 * reference RDFC-1.0 content-hash verifier) lives behind the `@jeswr/integrity/rdfc` subexport so
 * that a root-only consumer pulls no RDF library.
 *
 * DEPENDENCY DIRECTION (load-bearing): `@jeswr/integrity` NEVER imports `@jeswr/solid-vc`. The
 * solid-vc `./integrity` provider depends on THIS package, not the reverse.
 */
export { MECH_CONTENT_HASH_RDFC, MECH_JWS_ED25519_RDFC, MECH_ML_DSA, MECH_SD_JWT_VC, MECH_TRANSPORT_TLS_DPOP, MECH_VC_DI_BBS, MECH_VC_DI_ECDSA, MECH_VC_DI_EDDSA, MECH_ZK_SPARQL, MECHANISM_ASSERTIONS, } from "./mechanisms.js";
export { ADDON_CIRCUIT_AUDIT, ADDON_POST_QUANTUM_FORGERY, ADDON_SELECTIVE_DISCLOSURE, ADDON_UNLINKABILITY, composeProfileMap, IL0_NONE, IL1_TRANSPORT, IL2_CONTENT_BOUND, IL3_AUTHOR_BOUND, IL4_AUTHOR_BOUND_FRESH, INTEGRITY_ADDONS, INTEGRITY_PROFILES, type IntegrityAddonName, type IntegrityProfileName, maxVerdict, requireProfile, } from "./profiles.js";
export { satisfies, type VerifyIntegrityOptions, verifyIntegrity } from "./satisfies.js";
export { type IntegrityAttestation, type IntegrityFailure, type IntegrityFailureCode, type IntegrityInput, type IntegrityRequirement, type IntegrityResult, type IntegrityVerifier, isAttestation, type RdfQuadLike, type RdfTermLike, } from "./types.js";
export { ADVANCED_PROPERTIES, ALL_PROPERTIES, AUTHORSHIP_BINDING, BASE_PROPERTIES, CIRCUIT_AUDIT, CONTENT_BINDING, INTEGRITY_NS, type IntegrityPropertyIri, isVerdict, OFFLINE_VERIFIABILITY, POST_QUANTUM_FORGERY, POST_QUANTUM_SNOOPING, PROOF_SIZE_LEAKAGE, REVOCATION_FRESHNESS, rank, SIGNATURE_TYPE_LEAKAGE, SOURCE_CREDENTIAL_DISCLOSURE, TAMPER_EVIDENCE, TRANSPORT_ORIGIN_AUTH, UNLINKABILITY, VALIDITY_PERIOD_LEAKAGE, type Verdict, } from "./vocab.js";
