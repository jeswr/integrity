# ALIGNMENT — `@jeswr/integrity` IRIs ↔ the sparq security & integrity ontologies

`@jeswr/integrity` models integrity the way the sparq security & integrity type ontologies do —
**property × mechanism × verdict × pulls** — rather than inventing an ordinal integrity-level
lattice. Those ontologies (`jeswr/sparql-zkp-ontologies`: `sec-prop:`, `sig-impl:`, `sec-req:`)
are in a **PRIVATE, do-not-publish repo**. Their README is explicit:

> **PRIVATE / UNPUBLISHED** … IRIs minted under `https://w3id.org/zkp-sparql/…` are placeholders
> pending a public-flip decision … **Do not cite, redistribute, or publish** these vocabularies.

So this package **mints its own IRIs** under the suite house-rule namespace
`https://jeswr.org/ns/integrity#` (jeswr namespaces are minted under `jeswr.org` and served via
the portfolio `/ns` redirect layer — never `w3id.org`) and mirrors the STRUCTURE, deferring
term-level `owl:equivalentClass` / `owl:equivalentProperty` alignment until the `zkp-sparql`
public-flip (**tracked at sparq-org/sparq#1682**). Nothing here cites or redistributes a
`zkp-sparql` IRI. A minimal vocabulary document resolves the namespace to real Turtle —
[`integrity.ttl`](./integrity.ttl) — describing the 14 property IRIs plus the IL0–IL4 profiles
and add-on flags; each term will carry an `owl:equivalentProperty`/`equivalentClass` to the
matching sparq `sec-prop:`/`sig-impl:` term once sparq-org/sparq#1682 makes them public.

Once the flip lands, the intended alignment is an `owl:equivalent*` axiom per row below (the
advanced-tier rows are name-for-name), plus reconciliation of the six proposed **base** properties
(§A.2) — either they are added to `sec-prop:` or this package's base namespace becomes canonical.

## Verdict enum

`@jeswr/integrity` `Verdict` = `"yes" | "partial" | "no"` — **verbatim** the sparq
`sig-impl:Assertion` verdict enum.

## Advanced-tier properties (name-for-name mirror of `sec-prop:`)

| `@jeswr/integrity#` (this package) | sparq `sec-prop:` term (PRIVATE) | sparq `category` |
|---|---|---|
| `Unlinkability` | `sec-prop:Unlinkability` | informationDisclosure |
| `SourceCredentialDisclosure` | `sec-prop:SourceCredentialDisclosure` | informationDisclosure |
| `PostQuantumForgery` | `sec-prop:PostQuantumForgery` | formalAnalysisPriority |
| `PostQuantumSnooping` | `sec-prop:PostQuantumSnooping` | formalAnalysisPriority |
| `SignatureTypeLeakage` | `sec-prop:SignatureTypeLeakage` | informationDisclosure |
| `ProofSizeLeakage` | `sec-prop:ProofSizeLeakage` | informationDisclosure |
| `ValidityPeriodLeakage` | `sec-prop:ValidityPeriodLeakage` | informationDisclosure |
| `CircuitAudit` | `sec-prop:CircuitAudit` | deploymentSpec |

## Base-tier properties (PROPOSED sparq-side extension — §A.2)

The base integrity properties every requirement in this suite actually gates on are **presupposed
but unminted** in `sec-prop:` (the eight advanced properties are the privacy/PQ/leakage tier above
them). This package proposes adding these six as instances of the existing
`sec-prop:SecurityProperty` class (zero new classes). Until then they live only under
`https://jeswr.org/ns/integrity#` and are marked `PLACEHOLDER-pending-reconciliation` in code.

| `@jeswr/integrity#` (this package) | Meaning | Status |
|---|---|---|
| `TransportOriginAuth` | integrity/origin for the retrieval channel only (TLS, DPoP-bound); does not survive copying | proposed `sec-prop:` extension |
| `ContentBinding` | bound to a specific canonical content (RDFC-1.0 digest / bytes hash) | proposed `sec-prop:` extension |
| `TamperEvidence` | any post-attestation modification is detectable by a holder | proposed `sec-prop:` extension |
| `AuthorshipBinding` | content bound to an identified key/identity (issuer / WebID) | proposed `sec-prop:` extension |
| `OfflineVerifiability` | verification needs no callback to the origin at check time | proposed `sec-prop:` extension |
| `RevocationFreshness` | validity window + status (revocation/suspension) checked, fail-closed | proposed `sec-prop:` extension |

## Mechanisms ↔ `sig-impl:SignatureImplementation`

The `MECHANISM_ASSERTIONS` table (`src/mechanisms.ts`, §A.4) mirrors `sig-impl:`'s reified
`(implementation, property) → verdict` assertions. Each advanced-tier cell cites the `sig-impl:`
assertion it reproduces, e.g.:

| this package `MECH_*` | sparq `sig-impl:` implementation | cited assertions (examples) |
|---|---|---|
| `vc-di/eddsa-rdfc-2022`, `jws/ed25519-rdfc-1.0` | `sig-impl:Ed25519` (family `schnorr`, postQuantum false) | `assert-ed25519-unlinkability` = no |
| `vc-di/ecdsa-rdfc-2019` | `sig-impl:Ecdsa` (family `ecdsa`, postQuantum false) | `assert-ecdsa-unlinkability` = no |
| `vc-di/bbs` | `sig-impl:BbsPlus` (family `bbs`, postQuantum false) | `assert-bbs-unlinkability` = yes, `assert-bbs-pq-forgery` = no |
| `sd-jwt-vc` | `sig-impl:SdJwtVc` (family `sdJwt`) | `assert-sdjwt-source-disclosure` = partial |
| `content-hash/rdfc-1.0` | — (hash, not a signature scheme; `sec-prop:`/`sig-impl:` cover signatures) | `PostQuantumForgery` = yes by construction |
| `zk-sparql` | the SPARQ ZK suite (future) | Unlinkability = yes (design goal); `CircuitAudit` applies (open) |
| `ml-dsa` | **not yet a `sig-impl:` instance** (§E ask (c)) | `PostQuantumForgery` = yes |

## Requirements ↔ `sec-req:Requirement`

An `IntegrityRequirement` is a set of `(property, minVerdict)` demands — the `sec-req:Requirement`
"pulls on properties" pattern. A named **profile** (IL0–IL4 + add-on flags) is a reusable
requirement; the open sparq-side question (§A.2 / §E) is whether to reuse `sec-req:Requirement` for
non-regulatory profiles or mint `IntegrityProfile ⊑ Requirement`. This package uses named
string profiles for now and will adopt whichever the sparq ontology blesses.

## Pending items (need the maintainer / the sparq agent — §E of the design)

- Confirm the ontology identification (`jeswr/sparql-zkp-ontologies` sec-prop/sig-impl/sec-req).
- Add the six base properties to `sec-prop:` (or confirm they are deliberately presupposed).
- Bless `sec-req:Requirement` reuse for integrity profiles, or mint `IntegrityProfile`.
- Add an ML-DSA / FIPS 204 instance to `sig-impl:` (the PQ-yes column has no instance today).
- The public-flip timing for the `w3id.org/zkp-sparql` IRIs (blocks the `owl:equivalent*` axioms).
