# peerbridge v0.1: cxsend (STABLE on macOS; Windows/WSL UNTESTED)

`cxsend` injects a message into a **live** Codex session through Codex's own shared app-server daemon. Every `codex` 0.162+ TUI attaches to this daemon (feature `daemon_auto_start`). There is no tmux typing and no polling.
- **Idle** session: the message starts a new turn (it wakes).
- **Busy** session: the message is folded into the running turn (steer).
- The text shows in the target's TUI as a user turn wrapped in `<cross-session-message from-name=…>`, so the target can tell it came from an agent.

    python3 bin/cxsend list                         # live Codex threads: id, status, cwd, name
    python3 bin/cxsend send <thread-id|name|cwd-basename> "text" --from my-agent
    python3 bin/cxsend send <id> --file msg.txt     # multi-line

Requirements: Python 3.9+ (stdlib only) and `codex` ≥ 0.162 on PATH with at least one Codex session open (the session starts the daemon).

Transport:
- Direct: `$CODEX_HOME/app-server-control/app-server-control.sock` (WebSocket JSON-RPC over a Unix socket).
- Proxy: `codex app-server proxy`, where Codex chooses the OS transport. This is the default when the socket file is missing (as on Windows). `PEERBRIDGE_CODEX_TRANSPORT=proxy` forces it.

Not in v0.1: Codex sessions do not yet appear in Claude's ListAgents/SendMessage, and Codex→Claude replies are not wired yet. Both come in v0.2 (hub + pb).

## Status in agent-kit
- v0.1 — **experimental on Windows/WSL** (stable on macOS). First Windows test: open one `codex` session, then in PowerShell `py codex-bridge\bin\cxsend list` and `py codex-bridge\bin\cxsend send <id> "reply OK" --from <you>`; repeat inside WSL. Report the result to Shai as LOG/ERROR.
