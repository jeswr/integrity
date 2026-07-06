// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
import { describe, expect, it } from "vitest";
import {
  ADVANCED_PROPERTIES,
  ALL_PROPERTIES,
  BASE_PROPERTIES,
  INTEGRITY_NS,
  rank,
  UNLINKABILITY,
} from "../src/index.js";

describe("vocab: verdict rank (total order, fail-closed)", () => {
  it("orders no < partial < yes", () => {
    expect(rank("no")).toBe(0);
    expect(rank("partial")).toBe(1);
    expect(rank("yes")).toBe(2);
  });

  it("treats undefined (absent verdict) as `no` — fail-closed", () => {
    expect(rank(undefined)).toBe(0);
  });

  it("treats any unrecognised value as `no` — fail-closed", () => {
    expect(rank("maybe" as never)).toBe(0);
    expect(rank(null as never)).toBe(0);
    expect(rank("YES" as never)).toBe(0);
  });
});

describe("vocab: property IRIs", () => {
  it("mints all properties under the @jeswr placeholder namespace (not zkp-sparql)", () => {
    expect(INTEGRITY_NS).toBe("https://jeswr.org/ns/integrity#");
    for (const p of ALL_PROPERTIES) {
      expect(p.startsWith(INTEGRITY_NS)).toBe(true);
      expect(p).not.toContain("zkp-sparql");
    }
  });

  it("has 6 base + 8 advanced = 14 distinct properties", () => {
    expect(BASE_PROPERTIES).toHaveLength(6);
    expect(ADVANCED_PROPERTIES).toHaveLength(8);
    expect(ALL_PROPERTIES).toHaveLength(14);
    expect(new Set(ALL_PROPERTIES).size).toBe(14);
  });

  it("uses the verbatim sparq sec-prop local names for advanced properties", () => {
    // A representative advanced term must keep the sparq local name (name-for-name alignment).
    expect(UNLINKABILITY).toBe(`${INTEGRITY_NS}Unlinkability`);
    expect(ADVANCED_PROPERTIES).toContain(`${INTEGRITY_NS}CircuitAudit`);
    expect(ADVANCED_PROPERTIES).toContain(`${INTEGRITY_NS}PostQuantumForgery`);
    expect(ADVANCED_PROPERTIES).toContain(`${INTEGRITY_NS}SourceCredentialDisclosure`);
  });

  it("freezes the exported property arrays", () => {
    expect(Object.isFrozen(BASE_PROPERTIES)).toBe(true);
    expect(Object.isFrozen(ADVANCED_PROPERTIES)).toBe(true);
    expect(Object.isFrozen(ALL_PROPERTIES)).toBe(true);
  });
});
