# peerbridge: Claude Code ⇄ Codex native peer messaging

peerbridge makes every live **Codex** session a native **Claude Code** peer:
- it appears in Claude's `ListAgents`;
- Claude's `SendMessage` wakes it (idle) or steers it (busy);
- it answers through `pb send`, which lands in Claude as a real `<cross-session-message>` turn.

Codex⇄Codex works through the same path.

It is built on two native mechanisms and adds no tmux typing and no polling leases:
- **Claude Code's peer mesh**: `~/.claude/sessions/<pid>.json`, plus a Unix socket and key per session.
- **Codex's shared app-server daemon**: every `codex` ≥0.162 TUI attaches to it. Its JSON-RPC `turn/start` starts a turn on an idle thread and folds into the running turn on a busy one.

```
Claude session ──SendMessage──► stub (CC peer row + socket, one per Codex thread)
                                   └─► hub ──turn/start──► Codex app-server daemon ──► live Codex TUI
Codex shell: pb send <claude-or-codex-peer> "text" ──► target's CC socket (native envelope, from = the stub)
```

## Versions

| | What | Status |
|---|---|---|
| v0.1 | `cxsend`: inject a message into a live Codex thread via the daemon | STABLE (macOS). Windows untested. Shipped to Shai 22:28. |
| v0.2 | hub + per-thread stubs + `pb`: Codex in ListAgents, native SendMessage both ways, CC-convention receipts, opt-in policy + kill switch | EXPERIMENTAL→verifying: live on macOS (evidence/acceptance-manual.md); installer + selftest gate pending |

## Commands

| Command | What it does |
|---|---|
| `pb list` | List all peers: Claude sessions and bridged Codex threads |
| `pb send <name\|uds:addr\|ref> "text"` | Send a message from inside Codex. Options: `--file F`, `--notify-idle` |
| `pb whoami`, `pb name <new>` | Show or set this Codex thread's peer identity |
| `pb policy` | Show what is exposed |
| `pb expose [--thread ID\|--cwd P\|--all]`, `pb hide …` | Opt in or out. Only the local CLI can change exposure |
| `pb off`, `pb on` | Kill switch: withdraws every Codex peer within about 1 s and refuses injection |
| `pb ensure`, `pb status`, `pb stop` | Hub lifecycle |
| `cxsend list [--cwd P] [--all]`, `cxsend send <id> "text" --from me` | Raw inject, no hub needed (v0.1) |

## Receipts (Claude Code's own convention)

- **Accepted is silent.** That matches Claude Code: it uses `delivered` only for "released after a hold".
- **Refused** (Codex rejected the message, or the target is not exposed) is sent back as `expired/refused`.
- **Dropped** (the Codex daemon is unreachable) is sent back as `dropped`.
- **Claude-side holds**: when a Claude peer holds, refuses or expires a message that Codex sent, the notice is printed by `pb send` if it arrives within 1.5 s. After that it is injected into the Codex thread as `[Cross-session delivery notice]`.
- **Injection detail**: `~/.peerbridge/events.jsonl` records each injection as "started a new Codex turn" or "steered into the running Codex turn".

## Honest limits

- A Codex thread stays listed for about 60 s after its TUI exits, until the daemon unloads it.
- Desktop-app threads are covered only if the app shares the daemon. Not verified.
- Windows: see docs/WINDOWS.md.
- Design and dead ends: docs/DESIGN.md.

## Status in agent-kit (v0.2)
- macOS: stable. Linux/WSL: experimental. Native Windows: `cxsend` only (proxy transport); Claude<->Codex on native Windows needs v0.3 (named pipes).
- Default policy is **optin**: no Codex session is reachable until the machine's owner runs `pb expose ...` locally. `pb off` is the kill switch.
- Windows: never run codex or cxsend from an Administrator terminal; launch codex without -c/--enable/--disable flags. See docs/WINDOWS.md.
