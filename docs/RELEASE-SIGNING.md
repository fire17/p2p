# Release signing & source integrity

The installers (`init`, `init.ps1`) fetch the p2p application source and run it. If that
source is not verified, a compromised `main`, a malicious merged PR, a stolen token, or a
CA-level MITM of the download is **arbitrary code execution on every installing machine** —
and it happens *before* any of the protocol's crypto can protect anything (finding INST-1).

To close that, the installer treats the app source the same way it already treats the Node
runtime: **pin to an immutable release tag, then SHA256-verify the downloaded archive
against a `SHASUMS256.txt` manifest before extracting it, and fail closed** if anything is
missing or wrong. This document is the release-time procedure that produces the pinned
archives and the manifest the installer verifies against.

---

## What the installer expects at each release

For a release tag `vX.Y.Z`, upload these as **release assets** on
`github.com/fire17/p2p/releases/tag/vX.Y.Z`:

| Asset | Consumed by | Purpose |
|---|---|---|
| `p2p-vX.Y.Z.tar.gz` | `init` (Linux/macOS) | pinned source archive |
| `p2p-vX.Y.Z.zip` | `init.ps1` (Windows) | pinned source archive |
| `SHASUMS256.txt` | both | SHA256 of both archives |
| `SHASUMS256.txt.minisig` *(recommended)* | manual / future installer | detached signature over the manifest |

The installer defaults resolve to those exact URLs (see the config block in `init` /
`init.ps1`):

```
P2P_REF       = vX.Y.Z                                                    # the newest release
P2P_SRC       = …/releases/download/$P2P_REF/p2p-$P2P_REF.tar.gz          # (.zip on Windows)
P2P_SRC_SUMS  = …/releases/download/$P2P_REF/SHASUMS256.txt
```

`P2P_REF` is baked into the copy of `init` served from `p2p.akeyo.io/init`. Bumping it to
the new tag at release time is what keeps `curl … | sh` on the latest version **without**
reintroducing a floating branch: every install pins to a checksummed, immutable tag.

---

## Regenerating the manifest (the release step)

Run from a clean checkout at the tagged commit. The archives are built with `git archive`
piped through `gzip -n`, which is **byte-for-byte reproducible** for a given tag (`-n` drops
gzip's embedded timestamp/name) — so anyone can rebuild the identical archive and confirm
the hash. Do **not** use GitHub's auto-generated `…/archive/refs/tags/…` archives for the
checksum: GitHub does not guarantee those bytes are stable over time (it has changed its
archive compression before, silently breaking pinned checksums). Ship your own asset.

```sh
VER=v0.2.0                       # the tag being released
PREFIX="p2p-$VER/"               # single top-level dir → installer strips it with --strip-components 1
OUT="dist"; mkdir -p "$OUT"

# 1. reproducible source archives, straight from the tagged tree
git archive --format=tar --prefix="$PREFIX" "$VER" | gzip -n > "$OUT/p2p-$VER.tar.gz"
git archive --format=zip --prefix="$PREFIX" "$VER"          > "$OUT/p2p-$VER.zip"

# 2. the manifest — bare basenames only (cd into the dir so no path prefix is recorded).
#    Format is "<sha256>␣␣<name>", identical to nodejs.org's SHASUMS256.txt, so the
#    installer's grep/verify logic is the same for source as for the runtime.
( cd "$OUT" && shasum -a 256 "p2p-$VER.tar.gz" "p2p-$VER.zip" > SHASUMS256.txt )   # or: sha256sum …
cat "$OUT/SHASUMS256.txt"

# 3. (recommended) sign the MANIFEST, not each archive — one signature covers both.
minisign -Sm "$OUT/SHASUMS256.txt"        # produces SHASUMS256.txt.minisig

# 4. upload all of dist/* as assets on the vX.Y.Z GitHub release, then bump P2P_REF in the
#    init / init.ps1 that the site serves.
```

Verify locally before uploading (this is exactly what the installer does):

```sh
( cd dist && shasum -a 256 -c SHASUMS256.txt )    # must print "OK" for every line
```

### Windows smoke run (required before advertising the Windows path as hardened)

`init.ps1`'s source-verify path (`VerifySourceArchive`) is the symmetric twin of the POSIX
one, but it has **not** been executed on a real Windows/PowerShell host — the fix was
developed and end-to-end verified on macOS, and `test/installer-verify.sh` only exercises
`init`. Before a release advertises Windows as integrity-checked, do a one-time `pwsh` smoke
run on a real Windows box (PowerShell 5.1 and 7): a good `.zip` asset installs, a tampered
`.zip` is rejected with `source checksum MISMATCH`, and a manifest with no matching entry is
rejected — mirroring the good / tampered / no-entry cases that `test/installer-verify.sh`
runs against `init`. `Get-FileHash` ships with PowerShell 5.1+, so there is no "no hash tool"
case to test on Windows.

---

## What a same-repo checksum does and does not protect against

Be honest about the threat model — a checksum committed/hosted **in the same repo it
protects** is not a signature.

**It stops:**
- a tampered *download* — a MITM of `codeload`/`objects.githubusercontent.com`, a poisoned
  CDN/mirror, a corrupted transfer. The bytes won't match the manifest → install aborts.
- accidental drift — wrong tag, truncated archive, a re-generated archive with different
  bytes.
- (with `init`/`init.ps1`) the old **fail-open** holes: no hash tool present, or no manifest
  entry, now `die`/`Fail` instead of proceeding (findings INST-1 tightening + INST-2).

**It does NOT stop:**
- an attacker who can **rewrite the source repo/release itself** (stolen push token,
  malicious maintainer, account compromise). They rewrite `SHASUMS256.txt` in the same
  breath as the source, and the checksum matches their tampered archive. The manifest and
  the thing it vouches for share one trust root — so it verifies *integrity of transport*,
  not *authenticity of origin*.

## Recommendation: sign the manifest (next step)

Add a signature whose key lives **outside** the repo, so a repo compromise alone cannot
forge it:

- **minisign / signify** — smallest lift. One keypair; publish the public key in the README
  and out-of-band. `minisign -Sm SHASUMS256.txt` at release; the installer (or the user)
  runs `minisign -Vm SHASUMS256.txt -P <pubkey>` before trusting it. The private key is
  never in the repo.
- **`git tag -s` + `git verify-tag`** — if the release tag itself is GPG/SSH-signed, the
  build machine can `git verify-tag "$VER"` and derive the archive from the *verified* tag,
  giving origin authenticity from the tag down. Good when releases are already tag-driven.
- **sigstore / cosign (keyless)** — strongest supply-chain story (OIDC identity + a public
  transparency log, no long-lived private key), but adds tooling and a network dependency at
  verify time; heavier than this project currently needs.

Recommended path: ship the reproducible archives + `SHASUMS256.txt` now (this closes the
transport hole and the fail-open holes), and add a **minisign signature over the manifest**
as the immediate next step to close the origin-authenticity gap. The installer already
fetches the manifest as a separate object, so adding a `.minisig` verify step later is a
localized change (verify the signature over `src.sums` before reading a hash out of it),
with the minisign public key pinned in the installer.
