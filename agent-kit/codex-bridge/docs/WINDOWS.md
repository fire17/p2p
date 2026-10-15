# peerbridge on Windows (draft)

2026-10-15, claude-opus-5-5. Status: **DESIGN DRAFT, nothing verified on Windows.** The evidence and command citations are in `research/lane-C-windows.md`. Tags: [CODE] read from the 0.162.1 `codex.exe` and 2.1.301 `claude.exe` Windows builds; [WEB] public issue or PR; [INFERRED] reasoning only.

Target: Windows 10/11 machines, possibly with WSL.

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

## Fit with a cross-machine tunnel

A p2p tunnel stays the only link between machines, and peerbridge stays local to each machine. The gain: messages arriving over the tunnel can go into a Codex thread through `turn/start`, which is a real wake, instead of being polled.

## First thing to run on a Windows machine

`pb doctor` (non-elevated PowerShell), then `codex app-server daemon start` and `cxsend probe`. Two results decide whether to proceed: is the daemon running, and does Claude Code show a `cc-msg-` pipe?

## Open questions

1. A live `turn/start` wake on Windows.
2. Whether a byte-mode CC client works against a message-mode Python pipe server.
3. Whether the Codex Windows sandbox allows opening `\\.\pipe\LOCAL\*` and running the proxy.
4. The `daemon_auto_start` default on Windows.
5. Whether CC treats `pidDomain` strictly.


## Live result on a Windows 11 test desktop (build 26200, 2026-10-15, run by the remote helper agent)

- PASS: a plain `cmd /k codex` auto-started the shared daemon (`codex app-server daemon version`: running, pid backend, 0.162.1, AF_UNIX `.sock` under `%USERPROFILE%\.codex\app-server-control`).
- PASS: `pb doctor` showed Windows 11 (build 26200), daemon running, the desktop app's private app-server detected as unreachable, transport proxy, `daemon rpc ok`.
- PASS: `cxsend list --cwd <folder>` returned exit 0.
- 0 threads: the unattended TUI sat at Codex's first-run **trust this folder?** screen, so no thread was created yet.
- After that window closed (taskkill /T), the daemon refused connections (10061), as expected: the auto-started daemon lives with its session.

**Unattended tests on Windows.** The machine owner should pre-trust the throwaway folder once, so the TUI does not stop at the trust screen:

```
[projects.'C:\Users\<you>\AppData\Local\Temp\cxtest']
trust_level = "trusted"
```

(in `%USERPROFILE%\.codex\config.toml`). peerbridge and its selftest never edit `config.toml` themselves.


## Headless proof (v0.2.6): no TUI needed

On the Windows 11 test desktop an unattended Windows TUI never created a thread (3 tries: plain; read-only + on-request). Likely causes are a first-run screen or the Windows sandbox setup. `-a untrusted` does not exist in 0.162.1; the only values are `on-request` and `never`. Do not test the TUI path unattended. Instead:

```
codex app-server daemon start                 # shared daemon, no TUI
py bin\cxsend probe --cwd %TEMP%\cxtest        # thread/start (ephemeral, read-only, no approvals) + turn/start + wait for reply
codex app-server daemon stop                  # if you started it only for the test
```

PASS means the daemon accepted a thread, an injected turn ran, and the model replied. That is the whole Codex-side path peerbridge uses. On macOS: thread 103 ms, inject 3 ms, reply +4.1 s.

The questions from that run, answered:
- `codex "hello"` (initial prompt argument) starts a turn at once, which creates the thread.
- `codex resume <id>` attaches a TUI to an existing thread, including one made by `thread/start`. (A TUI attaching is a subscriber, so the thread then stays loaded while it is open.)
- `thread/start` over RPC creates a thread with no TUI at all. That is what `cxsend probe` does.
