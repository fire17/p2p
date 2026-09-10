# One-line Agent Tunnel join

The generated Pages routes install Bun and p2p v0.3.6, connect an encrypted chat
daemon, and send an acknowledged machine introduction. Terminal access remains
off for a new connection. The installed release includes terminal commands, but
joining does not authorize incoming instructions or enable a remote shell. Existing
owner activation on a reused session is left unchanged.

```sh
curl -fsSL https://p2p.akeyo.io/join/0TMWBQG67V37JZ3GPRWVSSTSBJ | sh
```

```powershell
irm https://p2p.akeyo.io/join/0TMWBQG67V37JZ3GPRWVSSTSBJ.ps1 | iex
```

These URLs become usable only after their generated files reach the Pages
publishing branch. A missing route currently returns 404. With the POSIX pipe,
curl reports a failed download but the pipeline's final exit code is sh's; use
`set -o pipefail` in a supporting parent shell when scripting that download.

Each listener currently accepts one peer. Use its route on the intended machine;
mint a separate listener for another machine. The bootstrap checks every local
session for an already authenticated connection to the requested peer, including
one created by the older two-command prompt. It reuses that daemon. Otherwise it
creates `join-<KEY>` with the same named persistent identity profile. Rerunning
after stopping preserves that identity. It does not stop another connection.

The banner explains that hostname, username, OS, architecture and Bun version are
sent to the requested peer. `AGENT=bootstrap` describes this bootstrap, without
claiming that an AI agent is running. Data is serialized as JSON inside a UTF-8
message file, passed through `tunnel send --file`, and acknowledged before success
is printed. No command or message is evaluated as shell source.

The chat daemon survives the bootstrap's exit but is not registered as a service
and does not automatically resume after a reboot. Status, receive and stop
commands with the actual session name are printed. An offline listener or an
occupied listener causes a bounded connection failure; a delivery failure reports
that the daemon is connected but identification was not acknowledged.

## Integrity and scope

Both scripts download their platform installer from the exact v0.3.6 source
commit `c26fde63ea01164bcbdb470e3c6a6f69682f748b`, check an embedded SHA256, and
execute only after a match. The installer then verifies the published source
archive and Bun download against their existing checksum manifests. The
bootstrap forces the v0.3.6 source URL and Bun runtime; it does not downgrade a
newer installed p2p version. Existing installer mirror settings remain subject to
the installer's checksum checks. The initial HTTPS join script and the publisher
remain the trust boundary; a checksum does not authenticate a compromised site.

PowerShell invokes the installer in a child shell to contain its `exit` calls and
restores the process environment variables it temporarily sets. Both scripts
clean only their own temporary directory. Identity files and existing histories
remain managed by p2p. No microphone, login, DNS or terminal-permission change is
part of this bootstrap.

## Hosting and adding another listener

Observed on 2026-09-11: `p2p.akeyo.io` is a CNAME to `fire17.github.io`;
`akeyo.io` uses `dns1.registrar-servers.com` / `dns2.registrar-servers.com`.
The repository Pages API reports legacy publishing from `main:/`, HTTPS enforced.
The site serves scripts as `application/octet-stream`; actual PowerShell 7
`Invoke-RestMethod` returns their text, while the bootstrap uses `-OutFile` for
binary-safe installer downloads.

[GitHub Pages is static hosting](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).
It cannot run a handler that extracts an arbitrary KEY from the request URL and
generates a script. A custom 404 cannot supply this contract: curl `-f` rejects
it, and a shell receiving a pipe cannot recover the original request URL.

Generate exact extensionless and `.ps1` files, then review and publish them through
the normal repository process:

```sh
node tools/render-join.mjs join KEY [ANOTHER_KEY ...]
```

The generator requires canonical version-0 contact keys and verifies their typo
checksum before constructing paths or writing files. It validates all keys before
writing a batch. Existing routes for other keys remain unchanged. There are no
secrets in a listener contact key, but publishing a route makes that contact
discoverable. Revoke a listener by stopping it or rotating its identity; cached
scripts cannot be recalled.

For immediate new-key URLs without a Pages deployment, a future dynamic service
must serve the same templates behind `/join/`. That requires an explicit hosting
and DNS/proxy decision. No dynamic edge service, credentials, infrastructure
purchase or DNS change has been made for this implementation.

## Validation

```sh
P2P_TEST_BUN=/absolute/path/to/bun P2P_REQUIRE_JOIN_BUN=1 \
  node --test test/join-bootstrap.test.js
```

On actual Windows, also set `P2P_REQUIRE_WINDOWS_SHELLS=1`; this requires both
Windows PowerShell 5.1 and PowerShell 7 and fails instead of skipping either.
Run on macOS, Linux and Windows alongside the existing real installer/Bun
portability tests. The join test serves the actual `curl | sh` / `irm | iex`
entrypoints and a minimal verified installer fixture over loopback HTTP; the
resulting join uses actual Bun and the real encrypted p2p transport. It proves
installer-byte rejection, child failure, caller environment restoration,
spaces/Unicode in the installation path, acknowledged identity, stable profile
restart and reuse of older default sessions. The minimal installer fixture does
not independently prove clean-machine runtime download; that is covered by the
separate installer portability suite.

Local macOS Node/Bun/PowerShell checks are fixture evidence. Public route behavior
and Windows/Linux results still require publication/CI verification before those
platforms or URLs are reported as proven.
