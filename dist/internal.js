// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * Internal helpers — NOT part of the public API (not re-exported from `index.ts`).
 */
/**
 * Build a genuinely IMMUTABLE verdict Map (a `ReadonlyMap` whose `set`/`delete`/`clear` throw),
 * so a shared exported constant (a profile, an add-on, a mechanism ceiling) cannot be corrupted
 * for every consumer by a stray cast-and-mutate. Remains a `Map` instance so structural checks
 * (e.g. `isAttestation`) still hold.
 */
export function frozenVerdictMap(entries) {
    const m = new Map(entries);
    const block = () => {
        throw new TypeError("@jeswr/integrity: this verdict map is immutable");
    };
    m.set = block;
    m.delete = block;
    m.clear = block;
    return m;
}
