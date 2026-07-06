// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
import { describe, expect, it } from "vitest";
import {
  AUTHORSHIP_BINDING,
  CONTENT_BINDING,
  type IntegrityAttestation,
  type IntegrityPropertyIri,
  type IntegrityRequirement,
  REVOCATION_FRESHNESS,
  satisfies,
  TAMPER_EVIDENCE,
  type Verdict,
} from "../src/index.js";

function att(achieved: Record<IntegrityPropertyIri, Verdict>): IntegrityAttestation {
  return { mechanism: "test", achieved: new Map(Object.entries(achieved)) };
}
function req(requires: Record<IntegrityPropertyIri, Verdict>): IntegrityRequirement {
  return { requires: new Map(Object.entries(requires)) };
}

describe("satisfies: fail-closed predicate", () => {
  it("an EMPTY requirement is vacuously satisfied (IL0 semantics)", () => {
    expect(satisfies(att({}), req({}))).toBe(true);
    expect(satisfies(att({ [CONTENT_BINDING]: "yes" }), req({}))).toBe(true);
  });

  it("exact-match verdicts satisfy", () => {
    expect(
      satisfies(
        att({ [CONTENT_BINDING]: "yes", [TAMPER_EVIDENCE]: "yes" }),
        req({ [CONTENT_BINDING]: "yes", [TAMPER_EVIDENCE]: "yes" }),
      ),
    ).toBe(true);
  });

  it("over-satisfying (yes ≥ partial) satisfies", () => {
    expect(
      satisfies(att({ [CONTENT_BINDING]: "yes" }), req({ [CONTENT_BINDING]: "partial" })),
    ).toBe(true);
  });

  it("under-satisfying (partial < yes) FAILS", () => {
    expect(
      satisfies(att({ [CONTENT_BINDING]: "partial" }), req({ [CONTENT_BINDING]: "yes" })),
    ).toBe(false);
  });

  it("an ABSENT required property is treated as `no` — FAILS (fail-closed)", () => {
    // achieved has nothing; requirement demands partial → absent ranks 0 < 1.
    expect(satisfies(att({}), req({ [AUTHORSHIP_BINDING]: "partial" }))).toBe(false);
    expect(satisfies(att({ [CONTENT_BINDING]: "yes" }), req({ [AUTHORSHIP_BINDING]: "yes" }))).toBe(
      false,
    );
  });

  it("a `no` achieved verdict FAILS a partial/yes demand", () => {
    expect(
      satisfies(att({ [AUTHORSHIP_BINDING]: "no" }), req({ [AUTHORSHIP_BINDING]: "partial" })),
    ).toBe(false);
  });

  it("ALL demanded properties must hold — one shortfall fails the whole requirement", () => {
    const a = att({
      [CONTENT_BINDING]: "yes",
      [TAMPER_EVIDENCE]: "yes",
      [AUTHORSHIP_BINDING]: "partial",
    });
    const r = req({
      [CONTENT_BINDING]: "yes",
      [TAMPER_EVIDENCE]: "yes",
      [AUTHORSHIP_BINDING]: "yes",
    });
    expect(satisfies(a, r)).toBe(false);
  });

  it("a `no` minimum is trivially met (don't-care), even when absent", () => {
    // rank(absent)=0 >= rank("no")=0 — a "no" demand constrains nothing.
    expect(satisfies(att({}), req({ [REVOCATION_FRESHNESS]: "no" }))).toBe(true);
  });

  it("partial demand met by partial", () => {
    expect(
      satisfies(att({ [CONTENT_BINDING]: "partial" }), req({ [CONTENT_BINDING]: "partial" })),
    ).toBe(true);
  });
});
