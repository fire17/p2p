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
| v0.2 | hub + per-thread stubs + `pb`: Codex in ListAgents, native SendMessage both ways, CC-convention receipts, opt-in policy + kill switch | Claude→Codex STABLE. Codex→Claude only in unsandboxed Codex. |
| v0.2.1 | sandbox-proof `pb send` (rollout channel, HMAC + dedupe), `codex-unsandboxed` opt-in launcher, default-sandbox selftest leg | macOS: 29/29 PASS (evidence/selftest-20261015-225433.json) |
| v0.2.2 | `pb doctor`, `codex-unsandboxed.cmd` | macOS doctor verified; .cmd untested |
| v0.2.3 | no-daemon diagnosis (desktop-app-only machines), clean cxsend errors | macOS verified |
| v0.2.4 | docs: the three hold options with exact apply/revert commands | docs only |
| v0.2.5 | doctor hint for 0 threads (trust screen); Windows live result + pre-trust note in docs/WINDOWS.md | Windows daemon + proxy PASS live (the remote helper agent) |
| v0.3 (planned) | native-Windows Claude⇄Codex via named pipes | not started |

## Two modes (both validated by selftest, 29/29 PASS)

| Mode | Launch | Codex to Claude path | Declared from-mode | Bypass-mode Claude receiver |
|---|---|---|---|---|
| **(a) default, sandboxed** | plain `codex` | The sandbox blocks sockets. `pb` prints one signed `@@PBSEND1…@@` line, and the hub reads it from the thread's rollout. No escalation, no config change. | `prompting` (honest) | **Holds the message until its user approves.** This is Claude Code's anti-permission-laundering rule; Codex gets a `[Cross-session delivery notice] … HELD` turn. A prompting-mode Claude receives it immediately. |
| **(b) opt-in, unsandboxed** | `codex-unsandboxed` (= `codex -a never -s danger-full-access`) | Direct hub socket | `bypass` | Delivered immediately |

Claude to Codex works the same in both modes: it wakes an idle session or steers a busy one.

For a held reply, there are three ways through: manual approval, `codex-unsandboxed`, or Claude's `crossSessionInbound` setting (per session via `--settings`, or global). See docs/HOLD-OPTIONS.md. The machine owner chooses; peerbridge never changes that setting.

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

## Status in agent-kit (v0.2.5)
- Claude->Codex: stable (both modes). Codex->Claude: stable from an unsandboxed Codex (mode b); stable from a default-sandbox Codex (mode a) to prompting-mode Claude receivers; HELD for the human's approval when the receiving Claude runs in bypass mode (Claude Code's permission-parity rule). macOS stable; Linux/WSL experimental; native Windows = cxsend + `pb doctor` (v0.3 for named pipes). Diagnose any machine with `python bin/pb doctor` (read-only).
- Default policy is **optin**: no Codex session is reachable until the machine's owner runs `pb expose ...` locally. `pb off` is the kill switch.
- Mode (b) `bin/codex-unsandboxed` (`bin\codex-unsandboxed.cmd` on native Windows, untested live) runs Codex with NO sandbox and NO approvals. It is an explicit opt-in the machine's owner chooses per machine; never the default, never enabled silently.
- Windows: never run codex or cxsend from an Administrator terminal; launch codex without -c/--enable/--disable flags. See docs/WINDOWS.md.
- Windows: the Codex DESKTOP APP uses a private app-server that cannot be bridged on Windows today; only CLI `codex` sessions are bridgeable. `pb doctor` prints a FIX line when no shared daemon runs.
