#!/usr/bin/env node
// Download the release binary for this platform into ./bin/. No runtime dependency: the
// binary is a static Rust build. Set TOKENSTASH_BINARY to skip (e.g. brew/cargo installs).
const fs = require("fs"), path = require("path"), https = require("https"), crypto = require("crypto"), { execSync } = require("child_process");
if (process.env.TOKENSTASH_BINARY) process.exit(0);
const pkg = require("../package.json");
const plat = { darwin: "darwin", linux: "linux" }[process.platform];
const arch = { x64: "x64", arm64: "arm64" }[process.arch];
if (!plat || !arch) { console.error(`tokenstash: no prebuilt binary for ${process.platform}/${process.arch}; install with cargo: cargo install tokenstash`); process.exit(0); }
const base = `https://github.com/kgarg2468/tokenstash/releases/download/v${pkg.version}/tokenstash-${plat}-${arch}`;
const url = `${base}.tar.gz`;
const dest = path.join(__dirname, "tokenstash");
function get(u, cb, n = 0, failHard = false) {
  https.get(u, (r) => {
    if ([301, 302, 303, 307, 308].includes(r.statusCode) && n < 5) return get(r.headers.location, cb, n + 1, failHard);
    if (r.statusCode !== 200) {
      console.error(`tokenstash: download failed (${r.statusCode}) ${u}`);
      process.exit(failHard ? 1 : 0);
    }
    cb(r);
  }).on("error", (e) => { console.error("tokenstash: download error:", e.message); process.exit(failHard ? 1 : 0); });
}
function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}
function timingSafeEq(a, b) {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
get(url, (res) => {
  // keep the download COMPRESSED: the published digest covers exactly these bytes
  const gz = dest + ".tar.gz";
  const out = fs.createWriteStream(gz);
  res.pipe(out).on("finish", () => {
    // verify the published digest before anything extracted is ever executed
    get(`${url}.sha256`, (sumRes) => {
      let expected = "";
      sumRes.on("data", (c) => { expected += c; });
      sumRes.on("end", () => {
        expected = (expected.match(/^[a-f0-9]{64}/m) || [])[0];
        const actual = sha256(gz);
        if (!expected || !timingSafeEq(actual, expected)) {
          console.error(`tokenstash: checksum mismatch — got ${actual}, want ${expected}. Not installing.`);
          try { fs.unlinkSync(gz); } catch {}
          process.exit(1);
        }
        execSync(`tar -xzf "${gz}" -C "${__dirname}"`); fs.unlinkSync(gz); fs.chmodSync(dest, 0o755);
        console.log("tokenstash: installed (checksum verified). Run `tokenstash init`.");
      });
    }, 0, true);
  });
});
