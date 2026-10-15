# peerbridge v0.3 backlog (from the remote helper agent gating, 2026-10-15)

| Item | Status | Notes |
|---|---|---|
| `pb doctor` (ASCII health report) | DONE in v0.2.2 | Reports platform, AF_UNIX, codex + daemon version, transport, daemon RPC, CC dirs and peers, policy, hub, and this thread. |
| `codex-unsandboxed.cmd` (native Windows twin of mode b) | DONE in v0.2.2, untested live | Fixed argv, ASCII only. Never run it elevated. |
| Native-Windows Claude<->Codex stubs on named pipes | NOT STARTED | Needs a live Windows box. Details below. |

Facts for the named-pipe stub (research/lane-C-windows.md, read from the Windows binaries, not run live):
- The CC pipe is `\\.\pipe\LOCAL\cc-msg-<32hex>`. Auth is ALWAYS required. The sender refuses a pipe unless a key file with a live owner pid exists.
- Liveness uses `procStartFt` (GetProcessTimes creation FILETIME) instead of `procStart`. `pidDomain` = `win32:<hostname lowercased>`.
- The key filename uses sha256 of the lowercased pipe path.
- The pipe must be byte mode. Use `_winapi`/ctypes CreateNamedPipe; asyncio's PipeServer uses message mode. Needs a test.
- Hub on Windows: replace `fcntl` with msvcrt locking, drop SIGHUP, and use a Scheduled Task at logon (not a service: a service lives in another session's `LOCAL\` namespace).
- The Codex daemon on Windows is AF_UNIX. Python has no AF_UNIX there, so use `codex app-server proxy` (already the cxrpc fallback).
- Native-Windows CC and WSL CC cannot see each other: separate registries and transports.

## First real Windows data (a Windows 11 test desktop, 2026-10-15 ~22:58, via the remote helper agent, read-only)

- The only Codex there is the **desktop app**, which runs a private stdio app-server. No CLI `codex` was ever opened, so the shared daemon never started: `app-server-control\` is empty, and the proxy fails with os error 10050.
- The desktop app uses the shared daemon only if `CODEX_APP_SERVER_USE_LOCAL_DAEMON=1` **and platform != win32** (lane A [CODE]). So **on Windows, desktop-app threads cannot be bridged**. Only CLI `codex` sessions can (non-elevated, without -c/--enable/--disable).
- In WSL, `codex` resolves to the Windows npm shim (interop). cxsend/pb in WSL therefore reach the **Windows** daemon through `codex app-server proxy` over interop stdio [INFERRED].
  - For hub-in-WSL, the rollout paths the daemon reports are Windows paths, so the sandbox outbox channel needs `wslpath` translation (v0.3).
- v0.2.3 adds a hint on no-daemon errors (cxsend/cxrpc) and `pb doctor` lines for "other app-servers" and FIX.
- v0.3 candidate (needs a Windows test): run a shared `codex app-server --listen ws://127.0.0.1:<port>` with auth, point the desktop app at it with `CODEX_APP_SERVER_WS_URL`, and have peerbridge connect to the same WS. Whether the app honours WS_URL on win32 is unknown.
