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
# failure finishes the set instead of dying on E403 — but only if what is there is OURS:
# the published tarball's payload (the binary, or the launcher script) must equal what we
# are about to publish. A squatted or foreign name@version stops the release. Never
# unpublish: npm forbids re-using name@version forever and the launcher pins exact
# versions — ship a patch release instead.
same_payload() { # <pkg dir> <payload path inside the package>
  local dir="$1" payload="$2" url tmp ok=1
  url=$(npm view "$name@$version" dist.tarball 2>/dev/null) || return 1
  tmp=$(mktemp -d)
  if curl -fsSL "$url" -o "$tmp/pkg.tgz" && tar -xzf "$tmp/pkg.tgz" -C "$tmp" "package/$payload" 2>/dev/null \
     && cmp -s "$tmp/package/$payload" "$dir/$payload"; then ok=0; fi
  rm -rf "$tmp"; return $ok
}
publish() { # <pkg dir> <payload path>
  [ "${NPM_PUBLISH:-}" = 1 ] || return 0
  local name; name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$1/package.json")
  if npm view "$name@$version" version >/dev/null 2>&1; then
    if same_payload "$1" "$2"; then echo "$name@$version already published with this payload; skipping"; return 0; fi
    echo "$name@$version exists on the registry with a DIFFERENT payload — not ours; refusing to continue" >&2; exit 1
  fi
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
  publish "$pkg" bin/tokenstash
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
publish "$main" bin/tokenstash.js
if [ "${NPM_PUBLISH:-}" = 1 ]; then
  # Final check: every package resolves AND carries our payload.
  for name in linux-x64 linux-arm64 darwin-arm64 darwin-x64; do
    name="tokenstash-$name"; same_payload "$out/$name" bin/tokenstash || { echo "$name@$version is missing or not ours" >&2; exit 1; }
  done
  name=tokenstash; same_payload "$main" bin/tokenstash.js || { echo "tokenstash@$version is missing or not ours" >&2; exit 1; }
fi
echo "assembled in $out"; ls "$out"
