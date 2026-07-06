// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
import { describe, expect, it } from "vitest";
import {
  CONTENT_BINDING,
  type IntegrityInput,
  type IntegrityPropertyIri,
  type IntegrityRequirement,
  type IntegrityResult,
  type IntegrityVerifier,
  isAttestation,
  TAMPER_EVIDENCE,
  type Verdict,
  verifyIntegrity,
} from "../src/index.js";

const anyInput: IntegrityInput = { content: "x", mediaType: "text/turtle" };

function req(requires: Record<IntegrityPropertyIri, Verdict>): IntegrityRequirement {
  return { requires: new Map(Object.entries(requires)) };
}

/** A provider that always attests `achieved`, tagged with a mechanism id for order assertions. */
function attestingProvider(
  mechanism: string,
  achieved: Record<IntegrityPropertyIri, Verdict>,
): IntegrityVerifier {
  return {
    mechanism,
    canAttempt: () => true,
    verify: async (): Promise<IntegrityResult> => ({
      mechanism,
      achieved: new Map(Object.entries(achieved)),
    }),
  };
}

function failingProvider(mechanism: string): IntegrityVerifier {
  return {
    mechanism,
    canAttempt: () => true,
    verify: async (): Promise<IntegrityResult> => ({
      mechanism,
      code: "digest-mismatch",
      reason: "no",
    }),
  };
}

describe("verifyIntegrity: deny-by-default dispatch", () => {
  it("empty registry → undefined", async () => {
    expect(await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [])).toBeUndefined();
  });

  it("no applicable provider (canAttempt false) → undefined", async () => {
    const p: IntegrityVerifier = {
      mechanism: "m",
      canAttempt: () => false,
      verify: async () => ({ mechanism: "m", achieved: new Map([[CONTENT_BINDING, "yes"]]) }),
    };
    expect(await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [p])).toBeUndefined();
  });

  it("provider attests BELOW the requirement → undefined (deny)", async () => {
    const p = attestingProvider("m", { [CONTENT_BINDING]: "partial" });
    expect(await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [p])).toBeUndefined();
  });

  it("provider attests a SATISFYING attestation → returns it", async () => {
    const p = attestingProvider("m", { [CONTENT_BINDING]: "yes", [TAMPER_EVIDENCE]: "yes" });
    const out = await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [p]);
    expect(out?.mechanism).toBe("m");
    expect(out?.achieved.get(CONTENT_BINDING)).toBe("yes");
  });

  it("returns the FIRST satisfying attestation (registry order = trust order)", async () => {
    const p1 = attestingProvider("first", { [CONTENT_BINDING]: "yes" });
    const p2 = attestingProvider("second", { [CONTENT_BINDING]: "yes" });
    const out = await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [p1, p2]);
    expect(out?.mechanism).toBe("first");
  });

  it("skips a non-satisfying attestation and accepts a LATER satisfying provider", async () => {
    const weak = attestingProvider("weak", { [CONTENT_BINDING]: "partial" });
    const strong = attestingProvider("strong", { [CONTENT_BINDING]: "yes" });
    const out = await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [weak, strong]);
    expect(out?.mechanism).toBe("strong");
  });

  it("skips an IntegrityFailure result and accepts a later satisfying provider", async () => {
    const out = await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [
      failingProvider("f"),
      attestingProvider("ok", { [CONTENT_BINDING]: "yes" }),
    ]);
    expect(out?.mechanism).toBe("ok");
  });
});

describe("verifyIntegrity: fail-closed on hostile/buggy providers", () => {
  it("a THROWING canAttempt is skipped (treated as not-applicable), next provider used", async () => {
    const boom: IntegrityVerifier = {
      mechanism: "boom",
      canAttempt: () => {
        throw new Error("boom");
      },
      verify: async () => ({ mechanism: "boom", achieved: new Map([[CONTENT_BINDING, "yes"]]) }),
    };
    const out = await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [
      boom,
      attestingProvider("ok", { [CONTENT_BINDING]: "yes" }),
    ]);
    expect(out?.mechanism).toBe("ok");
  });

  it("a THROWING/REJECTING verify never yields acceptance; next provider used", async () => {
    const boom: IntegrityVerifier = {
      mechanism: "boom",
      canAttempt: () => true,
      verify: async () => {
        throw new Error("kaboom");
      },
    };
    const out = await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [
      boom,
      attestingProvider("ok", { [CONTENT_BINDING]: "yes" }),
    ]);
    expect(out?.mechanism).toBe("ok");
  });

  it("a lone throwing provider yields undefined (deny), does not crash the dispatch", async () => {
    const boom: IntegrityVerifier = {
      mechanism: "boom",
      canAttempt: () => true,
      verify: async () => {
        throw new Error("kaboom");
      },
    };
    expect(
      await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [boom]),
    ).toBeUndefined();
  });

  it("a NEVER-RESOLVING provider is skipped when providerTimeoutMs is set; later provider used", async () => {
    // roborev regression: an unbounded verify() must not stall the dispatch.
    const stalled: IntegrityVerifier = {
      mechanism: "stalled",
      canAttempt: () => true,
      verify: () => new Promise<IntegrityResult>(() => {}), // never settles
    };
    const out = await verifyIntegrity(
      anyInput,
      req({ [CONTENT_BINDING]: "yes" }),
      [stalled, attestingProvider("ok", { [CONTENT_BINDING]: "yes" })],
      { providerTimeoutMs: 50 },
    );
    expect(out?.mechanism).toBe("ok");
  });

  it("a lone never-resolving provider yields undefined (deny) under a timeout", async () => {
    const stalled: IntegrityVerifier = {
      mechanism: "stalled",
      canAttempt: () => true,
      verify: () => new Promise<IntegrityResult>(() => {}),
    };
    expect(
      await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [stalled], {
        providerTimeoutMs: 50,
      }),
    ).toBeUndefined();
  });

  it("a fast provider still returns normally when a timeout is configured", async () => {
    const out = await verifyIntegrity(
      anyInput,
      req({ [CONTENT_BINDING]: "yes" }),
      [attestingProvider("ok", { [CONTENT_BINDING]: "yes" })],
      { providerTimeoutMs: 1000 },
    );
    expect(out?.mechanism).toBe("ok");
  });

  it("a late-REJECTING timed-out provider does not raise an unhandled rejection", async () => {
    let rejectLater: (e: unknown) => void = () => {};
    const slowReject: IntegrityVerifier = {
      mechanism: "slow-reject",
      canAttempt: () => true,
      verify: () =>
        new Promise<IntegrityResult>((_resolve, reject) => {
          rejectLater = reject;
        }),
    };
    const p = verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [slowReject], {
      providerTimeoutMs: 20,
    });
    expect(await p).toBeUndefined();
    // reject AFTER the race was abandoned — must be swallowed, not crash the process.
    rejectLater(new Error("late"));
    await new Promise((r) => setTimeout(r, 10));
  });

  it("a provider returning a malformed (non-attestation) object is treated as a non-result", async () => {
    const malformed: IntegrityVerifier = {
      mechanism: "bad",
      canAttempt: () => true,
      // achieved is a plain object, not a Map → not a valid attestation.
      verify: async () =>
        ({
          mechanism: "bad",
          achieved: { [CONTENT_BINDING]: "yes" },
        }) as unknown as IntegrityResult,
    };
    expect(
      await verifyIntegrity(anyInput, req({ [CONTENT_BINDING]: "yes" }), [malformed]),
    ).toBeUndefined();
  });
});

describe("isAttestation guard", () => {
  it("true only for an object with a Map `achieved`", () => {
    expect(isAttestation({ mechanism: "m", achieved: new Map() })).toBe(true);
    expect(
      isAttestation({ mechanism: "m", code: "parse-error", reason: "x" } as IntegrityResult),
    ).toBe(false);
    expect(isAttestation({ mechanism: "m", achieved: {} } as unknown as IntegrityResult)).toBe(
      false,
    );
  });
});
