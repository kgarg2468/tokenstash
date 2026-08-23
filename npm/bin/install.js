#!/usr/bin/env node
// Download the release binary for this platform into ./bin/ and verify its SHA-256 against the
// checksum published alongside it. No runtime dependency: the binary is a static Rust build.
// Set TOKENSTASH_BINARY to skip (brew/cargo installs). Any failure exits non-zero so npm
// reports a failed install instead of a broken one.
const fs = require("fs"), path = require("path"), https = require("https"), crypto = require("crypto"), { execSync } = require("child_process");
if (process.env.TOKENSTASH_BINARY) process.exit(0);
const pkg = require("../package.json");
const plat = { darwin: "darwin", linux: "linux" }[process.platform];
const arch = { x64: "x64", arm64: "arm64" }[process.arch];
const fail = (msg) => { console.error(`tokenstash: ${msg}\n  fallback: cargo install tokenstash`); process.exit(1); };
if (!plat || !arch) fail(`no prebuilt binary for ${process.platform}/${process.arch}`);
const base = `https://github.com/kgarg2468/tokenstash/releases/download/v${pkg.version}/tokenstash-${plat}-${arch}.tar.gz`;
const dest = path.join(__dirname, "tokenstash");

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
    const [archive, sums] = await Promise.all([fetch(base), fetch(base + ".sha256")]);
    const expected = sums.toString("utf8").trim().split(/\s+/)[0];
    const actual = crypto.createHash("sha256").update(archive).digest("hex");
    if (!/^[a-f0-9]{64}$/.test(expected)) throw new Error("checksum file is malformed");
    if (actual !== expected) throw new Error(`checksum mismatch: expected ${expected}, got ${actual}`);
    const tmp = dest + ".tar.gz";
    fs.writeFileSync(tmp, archive);
    execSync(`tar -xzf "${tmp}" -C "${__dirname}"`);
    fs.unlinkSync(tmp);
    fs.chmodSync(dest, 0o755);
    console.log("tokenstash: installed (sha256 verified). Run `tokenstash init`.");
  } catch (e) {
    fail(`install failed: ${e.message}`);
  }
})();
