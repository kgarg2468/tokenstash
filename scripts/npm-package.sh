#!/usr/bin/env bash
# Assemble the npm packages for one release from the release tarballs, then (optionally)
# publish them. Layout: one binary package per platform (tokenstash-<os>-<arch>, no scripts,
# `os`/`cpu` pinned so package managers pick exactly one) plus the `tokenstash` launcher
# package that lists them as optionalDependencies at the same exact version.
#
#   scripts/npm-package.sh <version> <dir-with-tokenstash-*.tar.gz> <out-dir>
#   NPM_PUBLISH=1 scripts/npm-package.sh ...   # also `npm publish --access public` each one
#
# Platform packages are published first; the launcher last, so a partially failed release
# never leaves a launcher that resolves to a missing platform package.
set -euo pipefail
version="${1:?version}"; src="${2:?tarball dir}"; out="${3:?out dir}"
here="$(cd "$(dirname "$0")/.." && pwd)"
node_os() { case "$1" in darwin) echo darwin ;; linux) echo linux ;; esac; }
node_cpu() { case "$1" in x64) echo x64 ;; arm64) echo arm64 ;; esac; }
publish() { if [ "${NPM_PUBLISH:-}" = 1 ]; then (cd "$1" && npm publish --access public); fi; }
rm -rf "$out"; mkdir -p "$out"
for name in linux-x64 linux-arm64 darwin-arm64 darwin-x64; do
  os="${name%-*}"; cpu="${name#*-}"
  tar="$src/tokenstash-$name.tar.gz"; [ -f "$tar" ] || { echo "missing $tar" >&2; exit 1; }
  pkg="$out/tokenstash-$name"; mkdir -p "$pkg/bin"
  tar -xzf "$tar" -C "$pkg/bin" tokenstash
  chmod 755 "$pkg/bin/tokenstash"
  cp "$here/LICENSE" "$pkg/"
  cat > "$pkg/package.json" <<JSON
{
  "name": "tokenstash-$name",
  "version": "$version",
  "description": "tokenstash binary for $(node_os "$os")/$(node_cpu "$cpu"). Install \`tokenstash\` instead.",
  "license": "MIT",
  "repository": { "type": "git", "url": "git+https://github.com/kgarg2468/tokenstash.git" },
  "os": ["$(node_os "$os")"],
  "cpu": ["$(node_cpu "$cpu")"],
  "files": ["bin", "LICENSE"],
  "preferUnplugged": true
}
JSON
  printf '# tokenstash-%s\n\nPrebuilt `tokenstash` binary for this platform. Install the `tokenstash` package instead; it selects this one automatically.\n' "$name" > "$pkg/README.md"
  publish "$pkg"
done
main="$out/tokenstash"; mkdir -p "$main"
cp -r "$here/npm/tokenstash/bin" "$main/"
cp "$here/LICENSE" "$here/README.md" "$main/"
python3 - "$here/npm/tokenstash/package.json" "$main/package.json" "$version" <<'PY'
import json, sys
p = json.load(open(sys.argv[1])); v = sys.argv[3]
p["version"] = v
p["optionalDependencies"] = {k: v for k in p["optionalDependencies"]}
json.dump(p, open(sys.argv[2], "w"), indent=2); open(sys.argv[2], "a").write("\n")
PY
publish "$main"
echo "assembled in $out"; ls "$out"
