#!/usr/bin/env node
const path = require("path"), { spawnSync } = require("child_process");
const bin = process.env.TOKENSTASH_BINARY || path.join(__dirname, "tokenstash");
const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (r.error) { console.error("tokenstash: binary missing — run `npm rebuild tokenstash` or `cargo install tokenstash`"); process.exit(1); }
process.exit(r.status ?? 1);
