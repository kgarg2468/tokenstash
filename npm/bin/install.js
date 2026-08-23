#!/usr/bin/env node
// Download the release binary for this platform into ./bin/ and verify its SHA-256 against the
// digest embedded in this npm package at publish time (checksums.json). The digest is NOT
// fetched from the release, so a tampered GitHub asset fails verification unless the npm
// package itself was also compromised. No runtime dependency: the binary is a static Rust
// build. Set TOKENSTASH_BINARY to skip (brew/cargo installs). Any failure exits non-zero so
// npm reports a failed install instead of a broken one.
const fs = require("fs"), path = require("path"), https = require("https"), crypto = require("crypto"), { execFileSync } = require("child_process");
if (process.env.TOKENSTASH_BINARY) process.exit(0);
const pkg = require("../package.json");
const plat = { darwin: "darwin", linux: "linux" }[process.platform];
const arch = { x64: "x64", arm64: "arm64" }[process.arch];
const fail = (msg) => { console.error(`tokenstash: ${msg}\n  fallback: cargo install tokenstash`); process.exit(1); };
if (!plat || !arch) fail(`no prebuilt binary for ${process.platform}/${process.arch}`);
const asset = `tokenstash-${plat}-${arch}.tar.gz`;
const base = `https://github.com/kgarg2468/tokenstash/releases/download/v${pkg.version}/${asset}`;
const dest = path.join(__dirname, "tokenstash");
let checksums = {};
try { checksums = require("../checksums.json"); } catch { fail("checksums.json missing from package; refusing to install an unverifiable binary"); }
const expected = checksums[asset];
if (!/^[a-f0-9]{64}$/.test(expected || "")) fail(`no pinned checksum for ${asset} in this package version`);

function fetch(url, n = 0) {
  return new Promise((resolve, reject) => {
    https.get(url, (r) => {
      if ([301, 302, 303, 307, 308].includes(r.statusCode) && n < 5) return resolve(fetch(r.headers.location, n + 1));
      if (r.statusCode !== 200) return reject(new Error(`HTTP ${r.statusCode} for ${url}`));
      const chunks = [];
      r.on("data", (c) => chunks.push(c));
      r.on("end", () => resolve(Buffer.concat(chunks)));
      r.on("error", reject);
    }).on("error", reject);
  });
}

(async () => {
  try {
    const archive = await fetch(base);
    const actual = crypto.createHash("sha256").update(archive).digest("hex");
    if (actual !== expected) throw new Error(`checksum mismatch for ${asset}: expected ${expected}, got ${actual}`);
    const tmp = dest + ".tar.gz";
    fs.writeFileSync(tmp, archive);
    // argv form: no shell, so metacharacters in the install path are never interpreted
    execFileSync("tar", ["-xzf", tmp, "-C", __dirname], { stdio: "inherit" });
    fs.unlinkSync(tmp);
    fs.chmodSync(dest, 0o755);
    console.log("tokenstash: installed (sha256 verified). Run `tokenstash init`.");
  } catch (e) {
    fail(`install failed: ${e.message}`);
  }
})();
