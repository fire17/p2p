# peerbridge on Windows (draft)

2026-10-15, claude-opus-5-5. Status: **DESIGN DRAFT, nothing verified on Windows.** The evidence and command citations are in `research/lane-C-windows.md`. Tags: [CODE] read from the 0.162.1 `codex.exe` and 2.1.301 `claude.exe` Windows builds; [WEB] public issue or PR; [INFERRED] reasoning only.

Target: Windows test machines, Windows, possibly with WSL.

## What each harness gives us on Windows

| | Native Windows | WSL |
|---|---|---|
| Codex shared daemon | Yes, since PR #42405 (2026-09-03). **AF_UNIX** socket `%USERPROFILE%\.codex\app-server-control\app-server-control.sock` via `uds_windows`, not a named pipe [CODE][WEB]. Refuses elevated starts and clients (`elevated_windows`) [CODE]. | Same as Linux/Mac: `~/.codex/app-server-control/app-server-control.sock` |
| `codex app-server proxy` | Yes (`stdio-to-uds` over `uds_windows`) [CODE] | Yes |
| `codex queue` (Codex⇄Codex) | Yes [CODE] | Yes |
| Claude Code peer inbox | **Named pipe** `\\.\pipe\LOCAL\cc-msg-<32hex>`; registry `%USERPROFILE%\.claude\sessions\<pid>.json`; auth always required; `procStartFt` = FILETIME; `pidDomain` = `win32:<hostname>` [CODE] | `$XDG_RUNTIME_DIR/cc-socks/<pid>.sock` (else `/tmp/cc-socks-<uid>/`); `pidDomain` = `linux:<machine-id>:<pidns>` [CODE/INFERRED] |
| Python AF_UNIX | **No** (CPython gh-77589 still a draft) [WEB] | Yes |

Native-Windows CC and WSL CC cannot see each other: separate registries, separate transports, and different `pidDomain` [INFERRED from CODE]. Codex threads can cross the boundary, but only over stdio (`wsl.exe -e codex app-server proxy` / `cmd.exe /c codex app-server proxy`) [INFERRED].

## Port shape

Rule: each side runs its own hub for the agents on that side. The boundary is crossed only over stdio.

1. **Codex RPC:** `cxrpc.py` already falls back to `codex app-server proxy` when `socket.AF_UNIX` is missing (`cxrpc.py:72`). Set `PEERBRIDGE_CODEX_BIN` to the real `codex.exe`.
2. **Stub on Windows**, a new code path:
   - Serve `\\.\pipe\LOCAL\cc-msg-<secrets.token_hex(16)>`. Prefer a byte-mode pipe via `_winapi`/ctypes. asyncio's `PipeServer` is message-mode; test it before relying on it.
   - Write `<pid>.json` with `messagingSocketPath` = that path, `procStartFt` = the GetProcessTimes creation FILETIME as a decimal string, and `pidDomain` = `win32:` + `socket.gethostname().lower()`.
   - Write the key `<pid>.<sha256("\\\\.\\pipe\\local\\cc-msg-<hex>")>.key` = `{peerToken, procStartFt, pidDomain}`.
   - Require the token on every inbound frame. CC on Windows always sends one.
3. **Hub:**
   - Replace the AF_UNIX hub listener with the stubs' stdio, or with 127.0.0.1 TCP plus a token.
   - Replace `fcntl.flock` with `msvcrt.locking` on `%LOCALAPPDATA%\peerbridge\hub.lock`.
   - Drop `SIGHUP`.
4. **`pb`:** a `pb.cmd` shim calling `py -3`. It must work from Git Bash (CC's shell) and from PowerShell/cmd (Codex's shell).
5. **Must-fix before any Windows run:**
   - `os.kill(pid, 0)` **terminates the process** on Windows (`ccpeer.py:75`, `bin/pb:217`). Use `OpenProcess` + `GetExitCodeProcess`.
   - There is no `ps` (`ccpeer.py:65`).
   - `stub.py:59` writes `pidDomain` as `sys.platform`. Mirror CC's format on every OS, which also fixes WSL.
6. **Autostart:**
   - Native Windows: a Scheduled Task "At log on", run as the user, non-elevated. **Not** a service: session 0 has a different `LOCAL\` pipe namespace, and an elevated hub cannot use the daemon.
   - WSL: `.bashrc` or a Codex SessionStart hook running `pb ensure`.
7. **Python:** python.org 3.12+ via `py -3`. The Store `python3` stub exits 49.

## Fit with the agent bridge (the bridge plan)

The p2p tunnel stays the only Mac⇄PC link, and peerbridge stays local to each machine. The win: inbound G1 lines from the remote helper agent can go into the PC's Codex thread through `turn/start`, a real wake. That removes the plan's "Codex has no push" limit and the `recv --wait 60` polling in the agent prompt. All of the plan's rules still apply:
- Windows `join.ps1` only, never `join.sh` in WSL.
- No terminal or exec.
- `.ps1` files ASCII or UTF-8 with BOM.
- Message text goes through `--file`.

## First thing to ask the remote helper agent to run

Use the read-only checklist in `research/lane-C-windows.md` §Q5, steps 1–9 plus W1–W4. Two results decide whether to proceed: step 3 (is the daemon running on Windows?) and step 6 (does CC show a `cc-msg-` pipe?).

## Open questions

1. A live `turn/start` wake on Windows.
2. Whether a byte-mode CC client works against a message-mode Python pipe server.
3. Whether the Codex Windows sandbox allows opening `\\.\pipe\LOCAL\*` and running the proxy.
4. The `daemon_auto_start` default on Windows.
5. Whether CC treats `pidDomain` strictly.
