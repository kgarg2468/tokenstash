#!/usr/bin/env node
// Thin launcher. The binary ships in a per-platform package selected by npm/bun/pnpm/yarn
// through `optionalDependencies` + `os`/`cpu` — no lifecycle scripts, so package managers
// that refuse dependency postinstalls (bun, pnpm ≥ 10, `npm ci --ignore-scripts`) still
// get a working install. TOKENSTASH_BINARY overrides (brew/cargo installs, tests).
const path = require("path"), { spawnSync } = require("child_process");
const platform = { darwin: "darwin", linux: "linux" }[process.platform];
const arch = { x64: "x64", arm64: "arm64" }[process.arch];
let bin = process.env.TOKENSTASH_BINARY;
if (!bin) {
  if (!platform || !arch) {
    console.error(`tokenstash: no prebuilt binary for ${process.platform}/${process.arch} (Windows is not supported). From source: cargo install --git https://github.com/kgarg2468/tokenstash tokenstash`);
    process.exit(1);
  }
  const pkg = `tokenstash-${platform}-${arch}`;
  try {
    bin = require.resolve(`${pkg}/bin/tokenstash`);
  } catch {
    console.error(`tokenstash: the platform package ${pkg} is not installed.\n  Optional dependencies were skipped (\`--no-optional\`, \`omit=optional\`, or an unsupported platform).\n  Reinstall with optional dependencies enabled, or from source: cargo install --git https://github.com/kgarg2468/tokenstash tokenstash`);
    process.exit(1);
  }
}
// The terminal delivers Ctrl-C to the whole foreground group: let the child (which may hold
// a masked prompt in raw mode) handle it and clean up; then re-raise its signal so callers
// see an interrupt, not exit 1.
for (const s of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(s, () => {});
const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (r.error) { console.error(`tokenstash: cannot run ${bin}: ${r.error.message}`); process.exit(1); }
if (r.signal) { process.removeAllListeners(r.signal); process.kill(process.pid, r.signal); }
process.exit(r.status ?? 1);
