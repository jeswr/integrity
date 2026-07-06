// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * build-dist — produce the committed `dist/` for GitHub-branch installs under
 * `ignore-scripts=true`.
 *
 * WHY a committed dist/: a consumer can `npm install github:jeswr/integrity#main` and import the
 * package with no build step (their `ignore-scripts=true` never runs our `prepare`/`build`). The
 * dist stays in sync with src via `scripts/check-dist-fresh.mjs`.
 *
 * Build model — plain `tsc` (NOT a bundler). The runtime deps of the `./rdfc` entry
 * (`rdf-canonize`, `n3`) are ON npm and stay EXTERNAL, resolved by the consumer exactly like any
 * normal dependency (`ignore-scripts` skips lifecycle hooks, not dependency resolution). The
 * browser-safe root entry imports NONE of them, so a root-only consumer never loads them. Node
 * builtins used by `./rdfc` (`node:crypto`) are always external.
 *
 * `tsc` emits both the JavaScript and the `.d.ts` declarations (no source/declaration maps — the
 * committed dist stays minimal and deterministic).
 */
import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const defaultOut = join(root, "dist");

function main(outDir) {
  rmSync(outDir, { recursive: true, force: true });
  execFileSync(
    "node",
    [
      join(root, "node_modules", "typescript", "bin", "tsc"),
      "-p",
      join(root, "tsconfig.build.json"),
      "--outDir",
      outDir,
    ],
    { cwd: root, stdio: ["ignore", "ignore", "inherit"] },
  );
}

const argDir = process.argv[2];
main(argDir ? (isAbsolute(argDir) ? argDir : resolve(process.cwd(), argDir)) : defaultOut);
