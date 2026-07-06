// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
import { describe, expect, it } from "vitest";
import {
  ADDON_POST_QUANTUM_FORGERY,
  ADDON_SELECTIVE_DISCLOSURE,
  ADDON_UNLINKABILITY,
  AUTHORSHIP_BINDING,
  CONTENT_BINDING,
  composeProfileMap,
  IL0_NONE,
  IL1_TRANSPORT,
  IL2_CONTENT_BOUND,
  IL3_AUTHOR_BOUND,
  IL4_AUTHOR_BOUND_FRESH,
  INTEGRITY_ADDONS,
  INTEGRITY_PROFILES,
  maxVerdict,
  OFFLINE_VERIFIABILITY,
  POST_QUANTUM_FORGERY,
  REVOCATION_FRESHNESS,
  requireProfile,
  SOURCE_CREDENTIAL_DISCLOSURE,
  TAMPER_EVIDENCE,
  TRANSPORT_ORIGIN_AUTH,
  UNLINKABILITY,
} from "../src/index.js";

describe("profiles: the ladder (§A.3)", () => {
  it("IL0 is empty (data as found)", () => {
    expect(INTEGRITY_PROFILES[IL0_NONE].size).toBe(0);
  });

  it("IL1 demands only transport-origin auth", () => {
    const il1 = INTEGRITY_PROFILES[IL1_TRANSPORT];
    expect([...il1.entries()]).toEqual([[TRANSPORT_ORIGIN_AUTH, "yes"]]);
  });

  it("IL2 = content-bound + tamper-evident + offline-verifiable", () => {
    const il2 = INTEGRITY_PROFILES[IL2_CONTENT_BOUND];
    expect(il2.get(CONTENT_BINDING)).toBe("yes");
    expect(il2.get(TAMPER_EVIDENCE)).toBe("yes");
    expect(il2.get(OFFLINE_VERIFIABILITY)).toBe("yes");
    expect(il2.size).toBe(3);
    expect(il2.has(TRANSPORT_ORIGIN_AUTH)).toBe(false);
  });

  it("IL3 = IL2 ∪ authorship-binding", () => {
    const il3 = INTEGRITY_PROFILES[IL3_AUTHOR_BOUND];
    expect(il3.get(AUTHORSHIP_BINDING)).toBe("yes");
    expect(il3.size).toBe(4);
    // nests IL2
    for (const [p, v] of INTEGRITY_PROFILES[IL2_CONTENT_BOUND]) {
      expect(il3.get(p)).toBe(v);
    }
  });

  it("IL4 = IL3 ∪ revocation-freshness (the mandate/credential default)", () => {
    const il4 = INTEGRITY_PROFILES[IL4_AUTHOR_BOUND_FRESH];
    expect(il4.get(REVOCATION_FRESHNESS)).toBe("yes");
    expect(il4.size).toBe(5);
    for (const [p, v] of INTEGRITY_PROFILES[IL3_AUTHOR_BOUND]) {
      expect(il4.get(p)).toBe(v);
    }
  });
});

describe("profiles: immutability (cannot be corrupted for other consumers)", () => {
  it("throws on set/delete/clear of a shared profile map", () => {
    const il4 = INTEGRITY_PROFILES[IL4_AUTHOR_BOUND_FRESH] as unknown as Map<string, string>;
    expect(() => il4.set("x", "yes")).toThrow(/immutable/);
    expect(() => il4.delete(CONTENT_BINDING)).toThrow(/immutable/);
    expect(() => il4.clear()).toThrow(/immutable/);
    // unchanged
    expect(INTEGRITY_PROFILES[IL4_AUTHOR_BOUND_FRESH].size).toBe(5);
  });

  it("throws on mutating a shared add-on map", () => {
    const addon = INTEGRITY_ADDONS[ADDON_UNLINKABILITY] as unknown as Map<string, string>;
    expect(() => addon.set("x", "yes")).toThrow(/immutable/);
  });

  it("freezes the profile + add-on record objects", () => {
    expect(Object.isFrozen(INTEGRITY_PROFILES)).toBe(true);
    expect(Object.isFrozen(INTEGRITY_ADDONS)).toBe(true);
  });
});

describe("profiles: add-on flags (orthogonal)", () => {
  it("+SelectiveDisclosure demands SourceCredentialDisclosure ≥ partial", () => {
    expect(INTEGRITY_ADDONS[ADDON_SELECTIVE_DISCLOSURE].get(SOURCE_CREDENTIAL_DISCLOSURE)).toBe(
      "partial",
    );
  });

  it("+Unlinkability / +PostQuantumForgery demand yes", () => {
    expect(INTEGRITY_ADDONS[ADDON_UNLINKABILITY].get(UNLINKABILITY)).toBe("yes");
    expect(INTEGRITY_ADDONS[ADDON_POST_QUANTUM_FORGERY].get(POST_QUANTUM_FORGERY)).toBe("yes");
  });
});

describe("profiles: requireProfile()", () => {
  it("builds a requirement with a FRESH map (mutating it cannot corrupt the shared profile)", () => {
    const req = requireProfile(IL4_AUTHOR_BOUND_FRESH);
    expect(req.profile).toBe("IL4-author-bound-fresh");
    expect(req.requires.get(REVOCATION_FRESHNESS)).toBe("yes");
    // The requirement's own map is a normal mutable Map, distinct from the frozen source.
    const m = req.requires as Map<string, string>;
    expect(() => m.set("x", "yes")).not.toThrow();
    expect(INTEGRITY_PROFILES[IL4_AUTHOR_BOUND_FRESH].has("x")).toBe(false);
  });

  it("composes add-ons into the requirement + a labelled profile", () => {
    const req = requireProfile(
      IL4_AUTHOR_BOUND_FRESH,
      ADDON_UNLINKABILITY,
      ADDON_SELECTIVE_DISCLOSURE,
    );
    expect(req.profile).toBe("IL4-author-bound-fresh+Unlinkability+SelectiveDisclosure");
    expect(req.requires.get(UNLINKABILITY)).toBe("yes");
    expect(req.requires.get(SOURCE_CREDENTIAL_DISCLOSURE)).toBe("partial");
    expect(req.requires.get(REVOCATION_FRESHNESS)).toBe("yes");
  });
});

describe("profiles: composeProfileMap() takes the STRONGER demand per property", () => {
  it("max-merges overlapping properties", () => {
    const a = new Map([[SOURCE_CREDENTIAL_DISCLOSURE, "partial" as const]]);
    const b = new Map([[SOURCE_CREDENTIAL_DISCLOSURE, "yes" as const]]);
    expect(composeProfileMap(a, b).get(SOURCE_CREDENTIAL_DISCLOSURE)).toBe("yes");
    // order-independent
    expect(composeProfileMap(b, a).get(SOURCE_CREDENTIAL_DISCLOSURE)).toBe("yes");
  });

  it("maxVerdict", () => {
    expect(maxVerdict("no", "partial")).toBe("partial");
    expect(maxVerdict("yes", "partial")).toBe("yes");
    expect(maxVerdict("partial", "partial")).toBe("partial");
  });
});
