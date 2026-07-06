// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
import { Parser } from "n3";
import { describe, expect, it } from "vitest";
import {
  CONTENT_BINDING,
  IL2_CONTENT_BOUND,
  IL4_AUTHOR_BOUND_FRESH,
  type IntegrityInput,
  isAttestation,
  OFFLINE_VERIFIABILITY,
  requireProfile,
  TAMPER_EVIDENCE,
  verifyIntegrity,
} from "../src/index.js";
import { computeRdfcDigest, rdfcContentHashVerifier } from "../src/rdfc.js";

const TTL = '<https://ex.example/a> <https://ex.example/p> "hello" .';

async function digestOf(
  input: IntegrityInput,
  opts?: Parameters<typeof computeRdfcDigest>[1],
): Promise<string> {
  return computeRdfcDigest(input, opts);
}

/** A provider pinned to the trusted digest of `TTL`. */
async function pinnedProvider(overrides?: Partial<Parameters<typeof rdfcContentHashVerifier>[0]>) {
  const digest = await digestOf({ content: TTL, mediaType: "text/turtle" });
  return rdfcContentHashVerifier({
    trustedReference: { digest, algorithm: "sha256" },
    ...overrides,
  });
}

describe("computeRdfcDigest", () => {
  it("returns a prefixed lowercase-hex digest", async () => {
    const d = await digestOf({ content: TTL, mediaType: "text/turtle" });
    expect(d).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("supports sha384 / sha512", async () => {
    expect(
      await digestOf({ content: TTL, mediaType: "text/turtle" }, { algorithm: "sha384" }),
    ).toMatch(/^sha384:[0-9a-f]{96}$/);
    expect(
      await digestOf({ content: TTL, mediaType: "text/turtle" }, { algorithm: "sha512" }),
    ).toMatch(/^sha512:[0-9a-f]{128}$/);
  });

  it("is CANONICAL — semantically-equal graphs with different blank labels/order hash equal", async () => {
    const a = '_:x <https://ex.example/p> _:y . _:y <https://ex.example/q> "v" .';
    const b = '_:n1 <https://ex.example/q> "v" . _:n0 <https://ex.example/p> _:n1 .';
    expect(await digestOf({ content: a, mediaType: "text/turtle" })).toBe(
      await digestOf({ content: b, mediaType: "text/turtle" }),
    );
  });

  it("throws on a parse failure (a publisher never silently pins broken RDF)", async () => {
    await expect(
      digestOf({ content: "this is not @@@ turtle", mediaType: "text/turtle" }),
    ).rejects.toThrow();
  });

  it("throws on an unsupported hash algorithm", async () => {
    await expect(
      digestOf({ content: TTL, mediaType: "text/turtle" }, { algorithm: "md5" as never }),
    ).rejects.toThrow(/unsupported hash algorithm/);
  });
});

describe("rdfcContentHashVerifier: happy path (IL2)", () => {
  it("MATCH → an IL2 attestation with the content digest, no author", async () => {
    const provider = await pinnedProvider();
    const result = await provider.verify({ content: TTL, mediaType: "text/turtle" });
    expect(isAttestation(result)).toBe(true);
    if (!isAttestation(result)) return;
    expect(result.mechanism).toBe("content-hash/rdfc-1.0");
    expect(result.achieved.get(CONTENT_BINDING)).toBe("yes");
    expect(result.achieved.get(TAMPER_EVIDENCE)).toBe("yes");
    expect(result.achieved.get(OFFLINE_VERIFIABILITY)).toBe("yes");
    expect(result.contentDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(result.author).toBeUndefined();
  });

  it("the attestation's achieved map is independent of the shared ceiling (mutable copy)", async () => {
    const provider = await pinnedProvider();
    const result = await provider.verify({ content: TTL, mediaType: "text/turtle" });
    if (!isAttestation(result)) throw new Error("expected attestation");
    // A copy — mutating it must not throw (it is not the frozen shared ceiling).
    expect(() => (result.achieved as Map<string, string>).set("x", "yes")).not.toThrow();
  });

  it("accepts a reference digest with an ALGORITHM prefix and UPPERCASE hex", async () => {
    const d = (await digestOf({ content: TTL, mediaType: "text/turtle" }))
      .replace("sha256:", "")
      .toUpperCase();
    const provider = rdfcContentHashVerifier({
      trustedReference: { digest: `sha256:${d}`, algorithm: "sha256" },
    });
    expect(isAttestation(await provider.verify({ content: TTL, mediaType: "text/turtle" }))).toBe(
      true,
    );
  });

  it("verifies from PRE-PARSED quads too", async () => {
    const quads = new Parser({ format: "text/turtle" }).parse(TTL);
    const digest = await digestOf({ quads });
    const provider = rdfcContentHashVerifier({ trustedReference: { digest, algorithm: "sha256" } });
    expect(isAttestation(await provider.verify({ quads }))).toBe(true);
  });
});

describe("rdfcContentHashVerifier: tamper detection", () => {
  it("a mutated literal → digest-mismatch (never an attestation)", async () => {
    const provider = await pinnedProvider();
    const tampered = '<https://ex.example/a> <https://ex.example/p> "HELLO" .';
    const result = await provider.verify({ content: tampered, mediaType: "text/turtle" });
    expect(isAttestation(result)).toBe(false);
    if (isAttestation(result)) return;
    expect(result.code).toBe("digest-mismatch");
  });

  it("an added triple → digest-mismatch", async () => {
    const provider = await pinnedProvider();
    const extra = `${TTL}\n<https://ex.example/a> <https://ex.example/p2> "x" .`;
    const result = await provider.verify({ content: extra, mediaType: "text/turtle" });
    expect(isAttestation(result)).toBe(false);
  });

  it("an EMPTY reference digest never matches (guarded)", async () => {
    const provider = rdfcContentHashVerifier({
      trustedReference: { digest: "", algorithm: "sha256" },
    });
    const result = await provider.verify({ content: TTL, mediaType: "text/turtle" });
    expect(isAttestation(result)).toBe(false);
    if (!isAttestation(result)) expect(result.code).toBe("digest-mismatch");
  });

  it("a different-length reference digest → mismatch, does not crash the constant-time compare", async () => {
    const provider = rdfcContentHashVerifier({
      trustedReference: { digest: "abc", algorithm: "sha256" },
    });
    const result = await provider.verify({ content: TTL, mediaType: "text/turtle" });
    expect(isAttestation(result)).toBe(false);
  });
});

describe("rdfcContentHashVerifier: untrusted-input hardening (never throws out of verify)", () => {
  it("malformed RDF → parse-error failure", async () => {
    const provider = await pinnedProvider();
    const result = await provider.verify({ content: "@@ not rdf @@", mediaType: "text/turtle" });
    expect(isAttestation(result)).toBe(false);
    if (!isAttestation(result)) expect(result.code).toBe("parse-error");
  });

  it("unsupported media type → unsupported-input failure", async () => {
    const provider = await pinnedProvider();
    const result = await provider.verify({ content: "{}", mediaType: "application/json" });
    expect(isAttestation(result)).toBe(false);
    if (!isAttestation(result)) expect(result.code).toBe("unsupported-input");
  });

  it("no quads and no content → unsupported-input failure", async () => {
    const provider = await pinnedProvider();
    const result = await provider.verify({ source: "https://ex.example/x" });
    expect(isAttestation(result)).toBe(false);
    if (!isAttestation(result)) expect(result.code).toBe("unsupported-input");
  });

  it("oversized input → input-too-large (guard fires BEFORE parsing)", async () => {
    const provider = await pinnedProvider({ maxInputBytes: 10 });
    const big = `${TTL}\n${"# padding padding padding\n".repeat(50)}`;
    const result = await provider.verify({ content: big, mediaType: "text/turtle" });
    expect(isAttestation(result)).toBe(false);
    if (!isAttestation(result)) expect(result.code).toBe("input-too-large");
  });

  it("too many quads → too-complex", async () => {
    const provider = await pinnedProvider({ maxQuads: 1 });
    const two =
      '<https://ex.example/a> <https://ex.example/p> "1" .\n<https://ex.example/a> <https://ex.example/p> "2" .';
    const result = await provider.verify({ content: two, mediaType: "text/turtle" });
    expect(isAttestation(result)).toBe(false);
    if (!isAttestation(result)) expect(result.code).toBe("too-complex");
  });

  it("too many distinct blank nodes → too-complex (topology guard, before canonicalisation)", async () => {
    const provider = await pinnedProvider({ maxBlankNodes: 2 });
    const g = "_:a <https://ex.example/p> _:b . _:b <https://ex.example/p> _:c .";
    const result = await provider.verify({ content: g, mediaType: "text/turtle" });
    expect(isAttestation(result)).toBe(false);
    if (!isAttestation(result)) expect(result.code).toBe("too-complex");
  });

  it("a POISON graph (symmetric blank-node clique) → too-complex, bailing fast (no CPU burn)", async () => {
    const provider = await pinnedProvider(); // default maxWorkFactor = 1 (O(n))
    let clique = "";
    const n = 6;
    for (let i = 0; i < n; i++)
      for (let j = 0; j < n; j++)
        if (i !== j) clique += `_:b${i} <https://ex.example/e> _:b${j} .\n`;
    const t0 = Date.now();
    const result = await provider.verify({ content: clique, mediaType: "text/turtle" });
    const elapsed = Date.now() - t0;
    expect(isAttestation(result)).toBe(false);
    if (!isAttestation(result)) expect(result.code).toBe("too-complex");
    expect(elapsed).toBeLessThan(5000); // bails via maxWorkFactor, does not hang
  });
});

describe("rdfcContentHashVerifier: construction + canAttempt", () => {
  it("throws at construction on an unsupported algorithm", () => {
    expect(() =>
      rdfcContentHashVerifier({ trustedReference: { digest: "00", algorithm: "sha1" as never } }),
    ).toThrow(/unsupported hash algorithm/);
  });

  it("canAttempt: quads → true; RDF content → true; non-RDF / no-content → false", async () => {
    const provider = await pinnedProvider();
    expect(provider.canAttempt({ quads: [] })).toBe(true);
    expect(provider.canAttempt({ content: TTL, mediaType: "text/turtle" })).toBe(true);
    expect(provider.canAttempt({ content: TTL, mediaType: "text/turtle; charset=utf-8" })).toBe(
      true,
    );
    expect(provider.canAttempt({ content: "{}", mediaType: "application/json" })).toBe(false);
    expect(provider.canAttempt({ source: "https://ex.example/x" })).toBe(false);
  });
});

describe("rdfcContentHashVerifier: integration with verifyIntegrity", () => {
  it("satisfies IL2 on a match", async () => {
    const provider = await pinnedProvider();
    const out = await verifyIntegrity(
      { content: TTL, mediaType: "text/turtle" },
      requireProfile(IL2_CONTENT_BOUND),
      [provider],
    );
    expect(out?.mechanism).toBe("content-hash/rdfc-1.0");
  });

  it("CANNOT satisfy IL4 (author-bound-fresh) — deny-by-default", async () => {
    const provider = await pinnedProvider();
    const out = await verifyIntegrity(
      { content: TTL, mediaType: "text/turtle" },
      requireProfile(IL4_AUTHOR_BOUND_FRESH),
      [provider],
    );
    expect(out).toBeUndefined();
  });
});
