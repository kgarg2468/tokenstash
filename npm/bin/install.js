#!/usr/bin/env node
// Download the release binary for this platform into ./bin/. No runtime dependency: the
// binary is a static Rust build. Set TOKENSTASH_BINARY to skip (e.g. brew/cargo installs).
const fs = require("fs"), path = require("path"), https = require("https"), zlib = require("zlib"), { execSync } = require("child_process");
if (process.env.TOKENSTASH_BINARY) process.exit(0);
const pkg = require("../package.json");
const plat = { darwin: "darwin", linux: "linux" }[process.platform];
const arch = { x64: "x64", arm64: "arm64" }[process.arch];
if (!plat || !arch) { console.error(`tokenstash: no prebuilt binary for ${process.platform}/${process.arch}; install with cargo: cargo install tokenstash`); process.exit(0); }
const url = `https://github.com/tokenstash/tokenstash/releases/download/v${pkg.version}/tokenstash-${plat}-${arch}.tar.gz`;
const dest = path.join(__dirname, "tokenstash");
function get(u, cb, n = 0) {
  https.get(u, (r) => {
    if ([301, 302, 303, 307, 308].includes(r.statusCode) && n < 5) return get(r.headers.location, cb, n + 1);
    if (r.statusCode !== 200) { console.error(`tokenstash: download failed (${r.statusCode}) ${u}`); process.exit(0); }
    cb(r);
  }).on("error", (e) => { console.error("tokenstash: download error:", e.message); process.exit(0); });
}
get(url, (res) => {
  const tmp = dest + ".tar";
  const out = fs.createWriteStream(tmp);
  res.pipe(zlib.createGunzip()).pipe(out).on("finish", () => {
    execSync(`tar -xf "${tmp}" -C "${__dirname}"`); fs.unlinkSync(tmp); fs.chmodSync(dest, 0o755);
    console.log("tokenstash: installed. Run `tokenstash init`.");
  });
});
