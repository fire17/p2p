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
