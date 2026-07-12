#!/bin/sh
# installer-verify.sh — regression guard for the p2p installer's SOURCE integrity check
# (findings INST-1 / INST-2). Proves `init` fails CLOSED: it installs a good, checksum-
# matching source archive and REFUSES every tampered / unverifiable variant, leaving NO
# app on disk when it refuses. This is the CAG check-6 monitoring hook for the fix — a
# future edit to `init` that reopens the hole makes this test fail.
#
# Self-contained + hermetic: it builds its own file:// fixtures (from HEAD) and runs `init`
# into THROWAWAY HOME/P2P_HOME/P2P_BIN_DIR under a mktemp dir. It NEVER touches the real
# ~/.p2p and never needs the network (all archives/manifests are local file:// URLs).
#
#   usage:  sh test/installer-verify.sh      # exit 0 = all cases pass; nonzero = a failure
#
# POSIX sh only. Requires git + tar + shasum + node>=22 to self-test; SKIPs (exit 0) if a
# prerequisite is missing so it never red-flags an under-provisioned CI box.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
INIT="$REPO/init"
[ -f "$INIT" ] || { echo "SKIP: $INIT not found"; exit 0; }

for t in git tar shasum node awk grep basename mktemp; do
  command -v "$t" >/dev/null 2>&1 || { echo "SKIP: required tool '$t' not found"; exit 0; }
done
NODEMAJ="$(node -e 'process.stdout.write(String(process.versions.node.split(".")[0]))' 2>/dev/null || echo 0)"
[ "$NODEMAJ" -ge 22 ] 2>/dev/null || { echo "SKIP: node >= 22 required (found major=$NODEMAJ)"; exit 0; }

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/p2p-instverify.XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT
DIST="$ROOT/dist"; mkdir -p "$DIST" "$ROOT/tamper"

# ── fixtures ──────────────────────────────────────────────────────────────────
git -C "$REPO" archive --format=tar --prefix=p2p-test/ HEAD | gzip -n > "$DIST/src.tar.gz" \
  || { echo "SKIP: could not build a source archive from HEAD"; exit 0; }
( cd "$DIST" && shasum -a 256 src.tar.gz > SHASUMS256.txt )         # matching manifest
cp "$DIST/src.tar.gz" "$ROOT/tamper/src.tar.gz"                     # same basename, corrupted:
printf 'X' >> "$ROOT/tamper/src.tar.gz"                             #   one appended byte → hash differs
printf '%064d  some-other-file.tar.gz\n' 0 > "$DIST/nomatch.txt"    # manifest with no entry for src.tar.gz

# curated hash-tool-FREE PATH for the no-tool case (everything init needs, minus
# sha256sum/shasum/openssl, plus node). Symlink real binaries so it is location-portable.
STUB="$ROOT/stubbin"; mkdir -p "$STUB"
for t in sh env uname mktemp date mkdir chmod rm mv cat sed grep awk head basename tar curl wget printf ln node; do
  p="$(command -v "$t" 2>/dev/null)" && ln -sf "$p" "$STUB/$t"
done
STUB_OK=1
for t in sh uname mktemp date mkdir chmod rm mv cat sed grep awk head basename tar node; do
  [ -e "$STUB/$t" ] || STUB_OK=0
done
{ [ -e "$STUB/curl" ] || [ -e "$STUB/wget" ]; } || STUB_OK=0

REALPATH="/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
PASS=0; FAIL=0
url() { printf 'file://%s' "$1"; }                                 # $1 must be absolute

# run init in an isolated throwaway home. sets globals RC + APP.
# args: <tag> <PATH> <P2P_SRC> <P2P_SRC_SUMS (may be empty)>
run_case() {
  _tag="$1"; _path="$2"; _src="$3"; _sums="$4"
  _h="$ROOT/home_$_tag"; rm -rf "$_h"; mkdir -p "$_h/.local/bin"
  # BIN_DIR is prepended to PATH so ON_PATH=1 → init never edits a shell rc file
  HOME="$_h" \
  PATH="$_h/.local/bin:$_path" \
  P2P_HOME="$_h/.p2p" P2P_BIN_DIR="$_h/.local/bin" \
  P2P_SRC="$_src" P2P_SRC_SUMS="$_sums" \
  sh "$INIT" > "$ROOT/$_tag.out" 2>&1
  RC=$?
  APP="$_h/.p2p/app/package.json"
}

# args: <tag> <install|reject> <needle-in-output>
assert() {
  _tag="$1"; _expect="$2"; _needle="$3"; _ok=1
  if [ "$_expect" = install ]; then
    { [ "$RC" -eq 0 ] && [ -f "$APP" ]; } || _ok=0
  else
    { [ "$RC" -ne 0 ] && [ ! -f "$APP" ]; } || _ok=0
  fi
  grep -qF "$_needle" "$ROOT/$_tag.out" || _ok=0
  if [ "$_ok" -eq 1 ]; then
    PASS=$((PASS+1)); printf '  PASS  %-11s rc=%s app=%s\n' "$_tag" "$RC" "$([ -f "$APP" ] && echo yes || echo no)"
  else
    FAIL=$((FAIL+1)); printf '  FAIL  %-11s rc=%s app=%s  (see %s/%s.out)\n' "$_tag" "$RC" "$([ -f "$APP" ] && echo yes || echo no)" "$ROOT" "$_tag"
  fi
}

echo "installer source-integrity regression (INST-1/INST-2) — 6 cases"

# 1. good archive + matching manifest → installs
run_case good      "$REALPATH" "$(url "$DIST/src.tar.gz")"        "$(url "$DIST/SHASUMS256.txt")"
assert   good      install  "source sha256 verified"

# 2. tampered archive, manifest unchanged → checksum mismatch → reject
run_case tampered  "$REALPATH" "$(url "$ROOT/tamper/src.tar.gz")" "$(url "$DIST/SHASUMS256.txt")"
assert   tampered  reject   "MISMATCH"

# 3. manifest present but has no entry for the archive → reject
run_case noentry   "$REALPATH" "$(url "$DIST/src.tar.gz")"        "$(url "$DIST/nomatch.txt")"
assert   noentry   reject   "no SHA256 entry"

# 4. manifest unreachable → reject
run_case nomanifest "$REALPATH" "$(url "$DIST/src.tar.gz")"       "$(url "$ROOT/does-not-exist.txt")"
assert   nomanifest reject  "could not fetch the source checksum manifest"

# 5. no hash tool present → reject (fail-closed; this is the INST-2 half)
if [ "$STUB_OK" -eq 1 ]; then
  run_case notool  "$STUB"    "$(url "$DIST/src.tar.gz")"         "$(url "$DIST/SHASUMS256.txt")"
  assert   notool  reject   "no sha256 tool"
else
  echo "  SKIP  notool      (could not build a hash-tool-free stub PATH on this box)"
fi

# 6. trusted local directory → installs, and applies NO checksum (by design)
run_case localdir  "$REALPATH" "$REPO" ""
_ok=1
{ [ "$RC" -eq 0 ] && [ -f "$APP" ]; } || _ok=0
grep -qF "copying p2p source"        "$ROOT/localdir.out" || _ok=0
grep -qF "verifying source integrity" "$ROOT/localdir.out" && _ok=0   # must NOT verify a local dir
if [ "$_ok" -eq 1 ]; then
  PASS=$((PASS+1)); printf '  PASS  %-11s rc=%s app=yes (trusted, no checksum)\n' localdir "$RC"
else
  FAIL=$((FAIL+1)); printf '  FAIL  %-11s rc=%s  (see %s/localdir.out)\n' localdir "$RC" "$ROOT"
fi

echo "----"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
