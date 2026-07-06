/**
 * Internal helpers — NOT part of the public API (not re-exported from `index.ts`).
 */
import type { IntegrityPropertyIri, Verdict } from "./vocab.js";
/**
 * Build a genuinely IMMUTABLE verdict Map (a `ReadonlyMap` whose `set`/`delete`/`clear` throw),
 * so a shared exported constant (a profile, an add-on, a mechanism ceiling) cannot be corrupted
 * for every consumer by a stray cast-and-mutate. Remains a `Map` instance so structural checks
 * (e.g. `isAttestation`) still hold.
 */
export declare function frozenVerdictMap(entries: Iterable<readonly [IntegrityPropertyIri, Verdict]>): ReadonlyMap<IntegrityPropertyIri, Verdict>;
