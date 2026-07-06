// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
import { describe, expect, it } from "vitest";
import {
  AUTHORSHIP_BINDING,
  CIRCUIT_AUDIT,
  CONTENT_BINDING,
  MECH_CONTENT_HASH_RDFC,
  MECH_JWS_ED25519_RDFC,
  MECH_ML_DSA,
  MECH_SD_JWT_VC,
  MECH_TRANSPORT_TLS_DPOP,
  MECH_VC_DI_BBS,
  MECH_VC_DI_ECDSA,
  MECH_VC_DI_EDDSA,
  MECH_ZK_SPARQL,
  MECHANISM_ASSERTIONS,
  OFFLINE_VERIFIABILITY,
  POST_QUANTUM_FORGERY,
  REVOCATION_FRESHNESS,
  SOURCE_CREDENTIAL_DISCLOSURE,
  TAMPER_EVIDENCE,
  TRANSPORT_ORIGIN_AUTH,
  UNLINKABILITY,
} from "../src/index.js";

describe("mechanisms: §A.4 assertion table (capability ceilings)", () => {
  it("transport/tls-dpop confers only TransportOriginAuth", () => {
    const m = MECHANISM_ASSERTIONS[MECH_TRANSPORT_TLS_DPOP];
    expect(m.get(TRANSPORT_ORIGIN_AUTH)).toBe("yes");
    expect(m.has(CONTENT_BINDING)).toBe(false);
  });

  it("content-hash/rdfc-1.0 confers IL2 + PostQuantumForgery (hash-based), no authorship", () => {
    const m = MECHANISM_ASSERTIONS[MECH_CONTENT_HASH_RDFC];
    expect(m.get(CONTENT_BINDING)).toBe("yes");
    expect(m.get(TAMPER_EVIDENCE)).toBe("yes");
    expect(m.get(OFFLINE_VERIFIABILITY)).toBe("yes");
    expect(m.get(POST_QUANTUM_FORGERY)).toBe("yes");
    expect(m.has(AUTHORSHIP_BINDING)).toBe(false);
  });

  it("jws/ed25519 confers authorship but is linkable + not PQ (cited sig-impl verdicts)", () => {
    const m = MECHANISM_ASSERTIONS[MECH_JWS_ED25519_RDFC];
    expect(m.get(AUTHORSHIP_BINDING)).toBe("yes");
    expect(m.get(UNLINKABILITY)).toBe("no"); // assert-ed25519-unlinkability = no
    expect(m.get(POST_QUANTUM_FORGERY)).toBe("no");
    // RevocationFreshness only "with a status seam" — NOT in the ceiling.
    expect(m.has(REVOCATION_FRESHNESS)).toBe(false);
  });

  it("vc-di eddsa/ecdsa confer IL4 (conditional freshness) but are linkable", () => {
    for (const id of [MECH_VC_DI_EDDSA, MECH_VC_DI_ECDSA]) {
      const m = MECHANISM_ASSERTIONS[id];
      expect(m.get(AUTHORSHIP_BINDING)).toBe("yes");
      expect(m.get(REVOCATION_FRESHNESS)).toBe("yes");
      expect(m.get(UNLINKABILITY)).toBe("no");
      expect(m.get(POST_QUANTUM_FORGERY)).toBe("no");
    }
  });

  it("vc-di BBS is unlinkable + selectively-disclosable but not PQ (cited sig-impl verdicts)", () => {
    const m = MECHANISM_ASSERTIONS[MECH_VC_DI_BBS];
    expect(m.get(UNLINKABILITY)).toBe("yes"); // assert-bbs-unlinkability = yes
    expect(m.get(SOURCE_CREDENTIAL_DISCLOSURE)).toBe("yes");
    expect(m.get(POST_QUANTUM_FORGERY)).toBe("no"); // assert-bbs-pq-forgery = no
  });

  it("sd-jwt-vc has PARTIAL source-credential disclosure", () => {
    expect(MECHANISM_ASSERTIONS[MECH_SD_JWT_VC].get(SOURCE_CREDENTIAL_DISCLOSURE)).toBe("partial");
  });

  it("zk-sparql is unlinkable, not-PQ-today, and CircuitAudit is an OPEN (absent) property", () => {
    const m = MECHANISM_ASSERTIONS[MECH_ZK_SPARQL];
    expect(m.get(UNLINKABILITY)).toBe("yes");
    expect(m.get(POST_QUANTUM_FORGERY)).toBe("no");
    expect(m.has(CIRCUIT_AUDIT)).toBe(false); // not yet attained — not asserted yes
  });

  it("ml-dsa (future) is the only PostQuantumForgery=yes signature suite", () => {
    expect(MECHANISM_ASSERTIONS[MECH_ML_DSA].get(POST_QUANTUM_FORGERY)).toBe("yes");
    // No other signature-based mechanism claims PQ-forgery yes.
    for (const id of [MECH_JWS_ED25519_RDFC, MECH_VC_DI_EDDSA, MECH_VC_DI_ECDSA, MECH_VC_DI_BBS]) {
      expect(MECHANISM_ASSERTIONS[id].get(POST_QUANTUM_FORGERY)).toBe("no");
    }
  });
});

describe("mechanisms: ceilings are immutable", () => {
  it("throws on mutating a shared ceiling map", () => {
    const m = MECHANISM_ASSERTIONS[MECH_VC_DI_BBS] as unknown as Map<string, string>;
    expect(() => m.set("x", "yes")).toThrow(/immutable/);
    expect(() => m.delete(UNLINKABILITY)).toThrow(/immutable/);
  });

  it("freezes the table object", () => {
    expect(Object.isFrozen(MECHANISM_ASSERTIONS)).toBe(true);
  });
});
