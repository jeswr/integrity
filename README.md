# @jeswr/integrity

> The **integrity abstraction seam** for the `@jeswr` Solid suite. Experimental, AI-agent-generated.

**Integrity is the top-level concept: _certainty that data meets a stated integrity requirement._**
Verifiable Credentials are **one mechanism** for obtaining high-integrity data among several — as
HTTP is one transport, and as many signature algorithms serve authentication. Your code depends on
this abstraction, **never on VC directly**, exactly the way the issuer-agnostic auth verifier
depends on "a verified WebID from a trusted issuer" and never on a concrete IdP.

- **Requirement, not format.** A consumer states an `IntegrityRequirement` (a set of properties,
  each at a minimum verdict). A VC-DI proof, a content-addressed hash, an SD-JWT, a BBS proof, or a
  future ZK proof satisfy it **interchangeably**.
- **Property-profile model, not an ordinal level.** Grounded in the sparq security & integrity type
  ontologies (property × mechanism × verdict × pulls). An "integrity level" is a *named property
  set*, not a number — because the space is only partially ordered (e.g. Unlinkability ⊥
  PostQuantumForgery). See [`ALIGNMENT.md`](./ALIGNMENT.md).
- **Fail-closed + deny-by-default.** An absent property counts as `no`. `verifyIntegrity` returns an
  attestation only when a registered provider actually proves enough; otherwise `undefined`.

The **root export is zero-dependency** and browser-safe. The one built-in provider — a
trusted-reference RDFC-1.0 content-hash verifier — lives behind the `./rdfc` subexport so a
root-only consumer pulls no RDF library.

## Install (GitHub, no build step)

The package commits a self-contained `dist/`, so it installs directly from GitHub under
`ignore-scripts=true`:

```bash
npm install github:jeswr/integrity#main
```

`rdf-canonize` and `n3` are normal npm dependencies used **only** by `./rdfc`; a consumer that
imports only the root never loads them.

## Concept model

```
Integrity  = certainty that data meets a STATED integrity requirement
  ├─ PROPERTIES   the atoms (sec-prop pattern): 6 base + 8 advanced integrity properties
  ├─ REQUIREMENT  a set of (property, minVerdict) demands (sec-req pattern)
  │                 an "integrity level" = a NAMED requirement profile (IL0–IL4 + add-on flags)
  ├─ MECHANISM    VC-DI / content-hash / SD-JWT / BBS / ZK / … (sig-impl pattern)
  └─ SATISFACTION mechanism × property → verdict {yes, partial, no}   (absent ⇒ "no", fail-closed)
```

## API — root (`@jeswr/integrity`)

```ts
import {
  requireProfile, IL4_AUTHOR_BOUND_FRESH, ADDON_UNLINKABILITY,
  satisfies, verifyIntegrity,
  type IntegrityVerifier, type IntegrityRequirement, type IntegrityAttestation,
} from "@jeswr/integrity";

// A requirement: a named profile, optionally with orthogonal add-on flags.
const req: IntegrityRequirement = requireProfile(IL4_AUTHOR_BOUND_FRESH, ADDON_UNLINKABILITY);

// Deny-by-default verification over an injectable, ordered provider registry (= trust order).
const attestation = await verifyIntegrity(input, req, [providerA, providerB]);
if (attestation === undefined) {
  // No provider proved enough — refuse. (fail-closed)
} else {
  // attestation.mechanism / .achieved / .contentDigest / .author record WHAT was proven.
}

// Pure predicate, for when you already hold an attestation:
satisfies(attestation, req); // boolean
```

**Building providers.** A provider is one mechanism: `{ mechanism, canAttempt(input), verify(input) }`.
`verify` returns an `IntegrityAttestation` (evidence of exactly what was proven — never a bare
boolean) or an `IntegrityFailure` (a diagnosed non-result). `verifyIntegrity` treats a *throwing*
`canAttempt`/`verify` as fail-closed, so a buggy or hostile provider can never crash the dispatch or
mask a later good provider.

### The profile ladder (§A.3)

| Profile | Required properties (min verdict `yes`) |
|---|---|
| `IL0_NONE` | ∅ — data as found |
| `IL1_TRANSPORT` | TransportOriginAuth |
| `IL2_CONTENT_BOUND` | ContentBinding, TamperEvidence, OfflineVerifiability |
| `IL3_AUTHOR_BOUND` | IL2 ∪ {AuthorshipBinding} |
| `IL4_AUTHOR_BOUND_FRESH` | IL3 ∪ {RevocationFreshness} — **the mandate/credential default** |

Orthogonal add-on flags compose into any base: `ADDON_SELECTIVE_DISCLOSURE`
(SourceCredentialDisclosure ≥ partial), `ADDON_UNLINKABILITY`, `ADDON_POST_QUANTUM_FORGERY`,
`ADDON_CIRCUIT_AUDIT`.

### The mechanism → property assertion table (§A.4)

`MECHANISM_ASSERTIONS` ships the §A.4 matrix as data (each advanced cell cites its sparq `sig-impl:`
assertion). It is a **capability CEILING** — the best a mechanism can confer when its verification
fully succeeds — **not an attestation**. A provider must verify each property for real and only
attest what it proved.

## API — `@jeswr/integrity/rdfc` (built-in content-hash provider)

```ts
import { rdfcContentHashVerifier, computeRdfcDigest } from "@jeswr/integrity/rdfc";

// A publisher pins the canonical digest of some RDF it controls:
const digest = await computeRdfcDigest({ content: turtle, mediaType: "text/turtle" });
// → "sha256:<hex>"

// A verifier checks untrusted data against that trusted reference:
const provider = rdfcContentHashVerifier({
  trustedReference: { digest, algorithm: "sha256" },
});
const result = await provider.verify({ content: maybeTampered, mediaType: "text/turtle" });
// match → IL2 attestation (ContentBinding/TamperEvidence/OfflineVerifiability); mismatch/parse/
// oversize/poison → an IntegrityFailure. Never attests authorship (no signature is checked).
```

This is the exact mechanism the suite's hash-pinned protocol documents (`solid-a2a`,
`a2a-rdf-extension`) already use: RDFC-1.0 canonicalisation → digest → compare.

### Security — untrusted RDF input

The input is hostile by assumption (you are verifying data you do not yet trust). RDFC-1.0 has known
"poison graph" super-polynomial blow-up on adversarial blank-node topologies. Defences, all bounded
and fail-closed (configurable on `rdfcContentHashVerifier`):

1. a byte-size cap **before** parsing (`maxInputBytes`, default 5 MB);
2. a quad-count cap and a distinct-blank-node cap **after** parsing (`maxQuads` 100k, `maxBlankNodes` 10k);
3. `rdf-canonize`'s own `maxWorkFactor` complexity limit (default O(n)) — it **bails** on a poison
   graph rather than burning CPU;
4. a wall-clock `AbortSignal.timeout` on canonicalisation (`canonicalizeTimeoutMs`, default 10 s);
5. any parse / size / complexity / timeout / mismatch → an `IntegrityFailure`, never a thrown error
   into the caller and never a partial/accepting result.

The provider performs **no network I/O** and never dereferences `input.source`.

## Dependency direction (load-bearing)

`@jeswr/integrity` **NEVER imports `@jeswr/solid-vc`.** The solid-vc `./integrity` provider (a
separate follow-on) depends on **this** package, not the reverse — so "code never depends on VC
directly" is structurally true.

## Gate

`npm run gate` = `lint` (Biome) → `typecheck` (tsc) → `test` (vitest) → `build` → `check:dist`
(committed `dist/` matches a fresh build) → `check:api` (api-extractor report) → `publint --strict`
→ `attw`. Every commit is also reviewed by roborev (codex).

## Status & follow-ons

Prototype; IRIs are `w3id.org/jeswr` placeholders pending the `zkp-sparql` public-flip (see
[`ALIGNMENT.md`](./ALIGNMENT.md) and sparq-org/sparq#1682). Downstream consumers, each a separate
piece of work that depends on this package:

- **`@jeswr/solid-vc` `./integrity` adapter** — `solidVcIntegrityVerifier(options): IntegrityVerifier`
  wrapping `verifyCredential`, reporting achieved properties per cryptosuite.
- **personal-agent mandate verifier** — swap `createSolidVcMandateVerifier` for a
  `verifyIntegrity`-based verifier defaulting to `IL4_AUTHOR_BOUND_FRESH`.
- **codegen signed-manifest** and **concept-hash annotation-signing** — adopt the abstraction from
  birth (the concept-hash binding is exactly the `./rdfc` provider at IL2).

## License

MIT © Jesse Wright
