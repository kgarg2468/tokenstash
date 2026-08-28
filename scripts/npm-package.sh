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
# Skip a package already on the registry at this version so a re-run after a partial
# failure finishes the set instead of dying on E403. Never unpublish: npm forbids re-using
# name@version forever, and the launcher pins exact versions — ship a patch release instead.
publish() {
  [ "${NPM_PUBLISH:-}" = 1 ] || return 0
  local name; name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$1/package.json")
  if npm view "$name@$version" version >/dev/null 2>&1; then echo "$name@$version already published; skipping"; return 0; fi
  (cd "$1" && npm publish --access public)
}
rm -rf "$out"; mkdir -p "$out"
for name in linux-x64 linux-arm64 darwin-arm64 darwin-x64; do
  os="${name%-*}"; cpu="${name#*-}"   # already npm's os/cpu vocabulary (darwin|linux, x64|arm64)
  tar="$src/tokenstash-$name.tar.gz"; [ -f "$tar" ] || { echo "missing $tar" >&2; exit 1; }
  pkg="$out/tokenstash-$name"; mkdir -p "$pkg/bin"
  tar -xzf "$tar" -C "$pkg/bin" tokenstash
  chmod 755 "$pkg/bin/tokenstash"
  cp "$here/LICENSE" "$pkg/"
  cat > "$pkg/package.json" <<JSON
{
  "name": "tokenstash-$name",
  "version": "$version",
  "description": "tokenstash binary for $os/$cpu. Install \`tokenstash\` instead.",
  "license": "MIT",
  "repository": { "type": "git", "url": "git+https://github.com/kgarg2468/tokenstash.git" },
  "os": ["$os"],
  "cpu": ["$cpu"],
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
if [ "${NPM_PUBLISH:-}" = 1 ]; then
  for name in linux-x64 linux-arm64 darwin-arm64 darwin-x64 ""; do
    pkg="tokenstash${name:+-$name}"
    npm view "$pkg@$version" version >/dev/null 2>&1 || { echo "$pkg@$version is not on the registry" >&2; exit 1; }
  done
fi
echo "assembled in $out"; ls "$out"
