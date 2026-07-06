// AUTHORED-BY Claude Sonnet 5
/**
 * gen-vocab-ttl — generate `integrity.ttl` (the vocabulary document the `https://jeswr.org/ns/integrity#`
 * namespace resolves to) from the SOURCE-OF-TRUTH TypeScript constants in `src/vocab.ts` and
 * `src/profiles.ts` (imported from the built `dist/`, never hand-typed IRIs). Serialises with
 * `n3.Writer` — this repo's house rule is "never hand-concat / hand-build RDF triples".
 *
 * Run after `npm run build` (so `dist/` reflects any vocab/profile change), then commit the
 * regenerated `integrity.ttl` alongside the source change. Exits non-zero on any n3 Writer error.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DataFactory, Writer } from "n3";

import {
  ADDON_CIRCUIT_AUDIT,
  ADDON_POST_QUANTUM_FORGERY,
  ADDON_SELECTIVE_DISCLOSURE,
  ADDON_UNLINKABILITY,
  IL0_NONE,
  IL1_TRANSPORT,
  IL2_CONTENT_BOUND,
  IL3_AUTHOR_BOUND,
  IL4_AUTHOR_BOUND_FRESH,
  INTEGRITY_ADDONS,
  INTEGRITY_NS,
  INTEGRITY_PROFILES,
} from "../dist/index.js";

const { namedNode, literal, blankNode, quad } = DataFactory;

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ONTOLOGY_IRI = INTEGRITY_NS.slice(0, -1); // drop the trailing '#'

const PREFIXES = {
  integrity: INTEGRITY_NS,
  rdf: "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
  rdfs: "http://www.w3.org/2000/01/rdf-schema#",
  owl: "http://www.w3.org/2002/07/owl#",
  dct: "http://purl.org/dc/terms/",
  xsd: "http://www.w3.org/2001/XMLSchema#",
};

const RDF_TYPE = namedNode(`${PREFIXES.rdf}type`);
const RDFS_LABEL = namedNode(`${PREFIXES.rdfs}label`);
const RDFS_COMMENT = namedNode(`${PREFIXES.rdfs}comment`);
const RDFS_IS_DEFINED_BY = namedNode(`${PREFIXES.rdfs}isDefinedBy`);
const RDFS_SUBCLASS_OF = namedNode(`${PREFIXES.rdfs}subClassOf`);
const RDFS_DOMAIN = namedNode(`${PREFIXES.rdfs}domain`);
const RDFS_RANGE = namedNode(`${PREFIXES.rdfs}range`);
const OWL_CLASS = namedNode(`${PREFIXES.owl}Class`);
const OWL_ONTOLOGY = namedNode(`${PREFIXES.owl}Ontology`);
const RDF_PROPERTY = namedNode(`${PREFIXES.rdf}Property`);
const DCT_TITLE = namedNode(`${PREFIXES.dct}title`);
const DCT_DESCRIPTION = namedNode(`${PREFIXES.dct}description`);
const OWL_VERSION_INFO = namedNode(`${PREFIXES.owl}versionInfo`);

const ns = (localName) => namedNode(`${INTEGRITY_NS}${localName}`);

// --- The 14 property terms: label + comment, mirroring src/vocab.ts JSDoc verbatim -----------
const BASE_PROPERTY_DOCS = {
  TransportOriginAuth: {
    label: "Transport Origin Auth",
    comment:
      "Integrity/origin assured only for the retrieval channel (TLS, DPoP-bound); does not survive copying.",
  },
  ContentBinding: {
    label: "Content Binding",
    comment:
      "The artifact is bound to a specific canonical content (RDFC-1.0 digest / bytes hash).",
  },
  TamperEvidence: {
    label: "Tamper Evidence",
    comment: "Any post-attestation modification is detectable by a holder.",
  },
  AuthorshipBinding: {
    label: "Authorship Binding",
    comment: "The content is bound to an identified key/identity (issuer / WebID).",
  },
  OfflineVerifiability: {
    label: "Offline Verifiability",
    comment: "Verification needs no callback to the origin at check time.",
  },
  RevocationFreshness: {
    label: "Revocation Freshness",
    comment: "Validity window + status (revocation / suspension) checked, fail-closed.",
  },
};

const ADVANCED_PROPERTY_DOCS = {
  Unlinkability: {
    label: "Unlinkability",
    comment:
      "Multiple presentations of the same credential/content cannot be linked to one another (category: informationDisclosure).",
    aligns: "Unlinkability",
  },
  SourceCredentialDisclosure: {
    label: "Source Credential Disclosure",
    comment:
      "The verifier learns no more about the source credential than the disclosed claims — selective disclosure (category: informationDisclosure).",
    aligns: "SourceCredentialDisclosure",
  },
  PostQuantumForgery: {
    label: "Post-Quantum Forgery Resistance",
    comment:
      "Resistant to forgery by a quantum-capable adversary (category: formalAnalysisPriority).",
    aligns: "PostQuantumForgery",
  },
  PostQuantumSnooping: {
    label: "Post-Quantum Snooping Resistance",
    comment:
      "Resistant to retroactive decryption/linkage by a quantum-capable adversary — harvest-now-decrypt-later (category: formalAnalysisPriority).",
    aligns: "PostQuantumSnooping",
  },
  SignatureTypeLeakage: {
    label: "Signature Type Leakage Resistance",
    comment:
      "The signature/proof does not reveal which cryptosuite or algorithm produced it (category: informationDisclosure).",
    aligns: "SignatureTypeLeakage",
  },
  ProofSizeLeakage: {
    label: "Proof Size Leakage Resistance",
    comment:
      "The proof size does not reveal information about the underlying claims (category: informationDisclosure).",
    aligns: "ProofSizeLeakage",
  },
  ValidityPeriodLeakage: {
    label: "Validity Period Leakage Resistance",
    comment:
      "The validity period does not reveal information beyond what is disclosed (category: informationDisclosure).",
    aligns: "ValidityPeriodLeakage",
  },
  CircuitAudit: {
    label: "Circuit Audit",
    comment:
      "The mechanism's circuit/implementation has undergone (or requires) an independent audit (category: deploymentSpec).",
    aligns: "CircuitAudit",
  },
};

// Clean IRI-safe local names for the orthogonal add-on flags (the TS code-level labels keep
// their `+Name` form — that string is preserved in rdfs:label for traceability, not the IRI).
const ADDON_DOCS = [
  {
    codeLabel: ADDON_SELECTIVE_DISCLOSURE,
    localName: "SelectiveDisclosureAddon",
    comment: "Orthogonal add-on: demands SourceCredentialDisclosure at minimum `partial`.",
  },
  {
    codeLabel: ADDON_UNLINKABILITY,
    localName: "UnlinkabilityAddon",
    comment: "Orthogonal add-on: demands Unlinkability at `yes`.",
  },
  {
    codeLabel: ADDON_POST_QUANTUM_FORGERY,
    localName: "PostQuantumForgeryAddon",
    comment: "Orthogonal add-on: demands PostQuantumForgery at `yes`.",
  },
  {
    codeLabel: ADDON_CIRCUIT_AUDIT,
    localName: "CircuitAuditAddon",
    comment: "Orthogonal add-on: demands CircuitAudit at `yes`.",
  },
];

const PROFILE_DOCS = [
  {
    codeLabel: IL0_NONE,
    comment: "No integrity properties demanded — the null profile.",
  },
  {
    codeLabel: IL1_TRANSPORT,
    comment: "Transport-only integrity: TransportOriginAuth at `yes`. Off the IL2 nesting chain.",
  },
  {
    codeLabel: IL2_CONTENT_BOUND,
    comment:
      "Content-bound: ContentBinding + TamperEvidence + OfflineVerifiability all at `yes`, given a trusted reference.",
  },
  {
    codeLabel: IL3_AUTHOR_BOUND,
    comment: "IL2 plus AuthorshipBinding at `yes`.",
  },
  {
    codeLabel: IL4_AUTHOR_BOUND_FRESH,
    comment: "IL3 plus RevocationFreshness at `yes`.",
  },
];

function main() {
  const quads = [];
  const push = (...args) => quads.push(quad(...args));

  // --- Ontology header ------------------------------------------------------------------------
  const ontology = namedNode(ONTOLOGY_IRI);
  push(ontology, RDF_TYPE, OWL_ONTOLOGY);
  push(ontology, DCT_TITLE, literal("The @jeswr/integrity vocabulary", "en"));
  push(
    ontology,
    DCT_DESCRIPTION,
    literal(
      "Integrity properties, IL0-IL4 profiles, and orthogonal add-on flags for the @jeswr/integrity abstraction seam. Mirrors the STRUCTURE of the private sparq security & integrity ontologies (sec-prop / sig-impl / sec-req); term-level owl:equivalent* alignment is pending their public-flip (sparq-org/sparq#1682) — see https://github.com/jeswr/integrity/blob/main/ALIGNMENT.md.",
      "en",
    ),
  );
  push(ontology, OWL_VERSION_INFO, literal("0.1.0"));

  // --- Classes ---------------------------------------------------------------------------------
  const ClassProperty = ns("IntegrityProperty");
  const ClassProfile = ns("IntegrityProfile");
  const ClassAddon = ns("Addon");

  push(ClassProperty, RDF_TYPE, OWL_CLASS);
  push(ClassProperty, RDFS_LABEL, literal("Integrity Property", "en"));
  push(
    ClassProperty,
    RDFS_COMMENT,
    literal(
      "A named property a mechanism may attain (yes), partially attain (partial), or fail (no). Mirrors the sparq sec-prop:SecurityProperty pattern.",
      "en",
    ),
  );
  push(ClassProperty, RDFS_IS_DEFINED_BY, ontology);

  push(ClassProfile, RDF_TYPE, OWL_CLASS);
  push(ClassProfile, RDFS_LABEL, literal("Integrity Profile", "en"));
  push(
    ClassProfile,
    RDFS_COMMENT,
    literal(
      "A named, reusable set of (property, minimum verdict) demands — the IL0-IL4 ladder. NOT an ordinal enum: profiles happen to nest, add-ons are orthogonal. Mirrors the sparq sec-req:Requirement 'pulls on properties' pattern.",
      "en",
    ),
  );
  push(ClassProfile, RDFS_IS_DEFINED_BY, ontology);

  push(ClassAddon, RDF_TYPE, OWL_CLASS);
  push(ClassAddon, RDFS_LABEL, literal("Integrity Add-on", "en"));
  push(
    ClassAddon,
    RDFS_COMMENT,
    literal(
      "An orthogonal single-property demand composed into any base IntegrityProfile (e.g. +Unlinkability).",
      "en",
    ),
  );
  push(ClassAddon, RDFS_SUBCLASS_OF, ClassProfile);
  push(ClassAddon, RDFS_IS_DEFINED_BY, ontology);

  // --- The `requires` reification predicates ----------------------------------------------------
  const PropRequires = ns("requires");
  const PropOnProperty = ns("onProperty");
  const PropMinVerdict = ns("minVerdict");

  push(PropRequires, RDF_TYPE, RDF_PROPERTY);
  push(PropRequires, RDFS_LABEL, literal("requires", "en"));
  push(
    PropRequires,
    RDFS_COMMENT,
    literal(
      "Links an IntegrityProfile/Addon to one (property, minimum verdict) requirement node.",
      "en",
    ),
  );
  push(PropRequires, RDFS_DOMAIN, ClassProfile);
  push(PropRequires, RDFS_IS_DEFINED_BY, ontology);

  push(PropOnProperty, RDF_TYPE, RDF_PROPERTY);
  push(PropOnProperty, RDFS_LABEL, literal("on property", "en"));
  push(
    PropOnProperty,
    RDFS_COMMENT,
    literal("The IntegrityProperty a requirement node pulls on.", "en"),
  );
  push(PropOnProperty, RDFS_RANGE, ClassProperty);
  push(PropOnProperty, RDFS_IS_DEFINED_BY, ontology);

  push(PropMinVerdict, RDF_TYPE, RDF_PROPERTY);
  push(PropMinVerdict, RDFS_LABEL, literal("minimum verdict", "en"));
  push(
    PropMinVerdict,
    RDFS_COMMENT,
    literal(
      'The minimum Verdict demanded — one of "yes", "partial", "no" (sparq sig-impl:Assertion enum).',
      "en",
    ),
  );
  push(PropMinVerdict, RDFS_IS_DEFINED_BY, ontology);

  // --- The 14 property terms --------------------------------------------------------------------
  for (const [localName, doc] of Object.entries(BASE_PROPERTY_DOCS)) {
    const term = ns(localName);
    push(term, RDF_TYPE, RDF_PROPERTY);
    push(term, RDF_TYPE, ClassProperty);
    push(term, RDFS_LABEL, literal(doc.label, "en"));
    push(
      term,
      RDFS_COMMENT,
      literal(`${doc.comment} PROPOSED base property — not yet in sparq sec-prop:.`, "en"),
    );
    push(term, RDFS_IS_DEFINED_BY, ontology);
  }
  for (const [localName, doc] of Object.entries(ADVANCED_PROPERTY_DOCS)) {
    const term = ns(localName);
    push(term, RDF_TYPE, RDF_PROPERTY);
    push(term, RDF_TYPE, ClassProperty);
    push(term, RDFS_LABEL, literal(doc.label, "en"));
    push(
      term,
      RDFS_COMMENT,
      literal(
        `${doc.comment} Aligns to the private sparq sec-prop:${doc.aligns} term (owl:equivalentProperty pending sparq-org/sparq#1682).`,
        "en",
      ),
    );
    push(term, RDFS_IS_DEFINED_BY, ontology);
  }

  // --- IL0-IL4 profiles, each with its requirement blank nodes ----------------------------------
  for (const { codeLabel, comment } of PROFILE_DOCS) {
    const profileIri = ns(codeLabel);
    push(profileIri, RDF_TYPE, ClassProfile);
    push(profileIri, RDFS_LABEL, literal(codeLabel, "en"));
    push(profileIri, RDFS_COMMENT, literal(comment, "en"));
    push(profileIri, RDFS_IS_DEFINED_BY, ontology);

    const requirementMap = INTEGRITY_PROFILES[codeLabel];
    for (const [propertyIri, verdict] of requirementMap) {
      const reqNode = blankNode();
      push(profileIri, PropRequires, reqNode);
      push(reqNode, PropOnProperty, namedNode(propertyIri));
      push(reqNode, PropMinVerdict, literal(verdict));
    }
  }

  // --- The orthogonal add-on flags ---------------------------------------------------------------
  for (const { codeLabel, localName, comment } of ADDON_DOCS) {
    const addonIri = ns(localName);
    push(addonIri, RDF_TYPE, ClassAddon);
    push(addonIri, RDFS_LABEL, literal(codeLabel, "en"));
    push(addonIri, RDFS_COMMENT, literal(comment, "en"));
    push(addonIri, RDFS_IS_DEFINED_BY, ontology);

    const requirementMap = INTEGRITY_ADDONS[codeLabel];
    for (const [propertyIri, verdict] of requirementMap) {
      const reqNode = blankNode();
      push(addonIri, PropRequires, reqNode);
      push(reqNode, PropOnProperty, namedNode(propertyIri));
      push(reqNode, PropMinVerdict, literal(verdict));
    }
  }

  const writer = new Writer({ prefixes: PREFIXES, format: "text/turtle" });
  writer.addQuads(quads);
  writer.end((error, result) => {
    if (error) {
      console.error(error);
      process.exitCode = 1;
      return;
    }
    const header =
      "# @jeswr/integrity vocabulary — https://jeswr.org/ns/integrity#\n" +
      "# GENERATED by scripts/gen-vocab-ttl.mjs from src/vocab.ts + src/profiles.ts — do not hand-edit.\n" +
      "# Run `npm run build && node scripts/gen-vocab-ttl.mjs` to regenerate after a vocab/profile change.\n\n";
    writeFileSync(join(root, "integrity.ttl"), header + result, "utf8");
    // eslint-disable-next-line no-console
    console.log(`Wrote ${join(root, "integrity.ttl")} (${quads.length} triples)`);
  });
}

main();
