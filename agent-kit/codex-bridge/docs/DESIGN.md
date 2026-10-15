# peerbridge: design record

2026-10-15, claude-opus-5-5. Ground truth: internal research notes, plus the live probes in `research/` and `evidence/`.

## Decision: new design on Codex's own daemon. The ASTRA sidecar is not revived.

The ASTRA bridge (`astra-mind/peer.ts`) existed because in Sept 2026 the only way into a Codex turn was a `functions.exec` lease pump or a 1-minute heartbeat. **Codex 0.162.1 has a native mechanism that removes that problem.**

**What Codex has natively (all verified live on this Mac, 2026-10-15 22:16–22:19):**

| Native Codex feature | What it gives us | Evidence |
|---|---|---|
| Shared local **app-server daemon**. `daemon_auto_start` is stable and on, so every `codex` TUI attaches to it. Socket: `~/.codex/app-server-control/app-server-control.sock`. | One place where every live Codex thread can be seen and driven. | `codex app-server daemon version` → running 0.162.1. A new TUI's thread showed up in `thread/loaded/list`. |
| Wire: JSON-RPC 2.0 in **WebSocket text frames over the UDS**. `codex app-server proxy` relays the same bytes over stdio. | Stdlib client. The proxy keeps the OS transport inside Codex, which is the portable path. | `peerbridge/cxrpc.py`; both transports return `initialize` and `thread/loaded/list`. |
| `thread/started`, `thread/status/changed` (`idle` / `active[waitingOnApproval\|waitingOnUserInput]` / `systemError` / `notLoaded`), `thread/closed`, broadcast to every client **without subscribing**. | Real idle/busy/waiting status for the CC registry, plus join and exit events. | `evidence/listen-1.log` |
| `turn/start {threadId,input}` into a thread owned by **another** client (the TUI). | **True push.** An idle Codex starts a turn that renders in its TUI as a user turn. | Codex answered "PONG-1" in 3 s and it rendered in the pane. |
| `turn/start` on an **active** thread steers into the running turn: same turn id, and the model folds the text in. | The same behaviour as CC's "read at next tool round". | The "ZEBRA" steer test: `DONE ZEBRA`. |
| `CODEX_THREAD_ID` / `CODEX_SESSION_ID` are present in every Codex shell. | Outbound identity for the `pb` command without guessing. | rollout `01a140fe-5c09…` |
| `codex queue --thread <id\|name> --message` | Codex's own built-in way for one session to message another (Codex⇄Codex). | `codex queue --help` |

## Architecture

```
            Claude Code sessions (native mesh)                Codex TUIs / desktop
   ~/.claude/sessions/<pid>.json + /tmp/cc-socks/<pid>.sock       │  (attach to)
                 ▲            │ SendMessage                       ▼
                 │            ▼                          Codex app-server daemon
   pb send ──────┘     [stub pid S1] ── stdio ──┐        (WS JSON-RPC on UDS)
   (from Codex shell,  [stub pid S2] ── stdio ──┤                ▲
    CODEX_THREAD_ID)                            ▼                │ turn/start · status events
                                         peerbridge hub ─────────┘
                                   (one per machine, flock singleton)
```

- **Hub** (`peerbridge/hub.py`): one per machine. It holds one RPC connection to the Codex daemon, tracks every loaded non-ephemeral thread, and spawns or reaps one **stub** per thread.
  - **Inbound:** a CC frame becomes a `<cross-session-message from= from-name= from-mode=>` envelope (the same provenance Claude gets), which the hub sends with `turn/start`.
- **Stub** (`peerbridge/stub.py`): one small process per Codex thread. It has to be its own process because CC's sender checks `LOCAL_PEERPID` == the record's pid, and the registry file is `<pid>.json`.
  - It binds `/tmp/cc-socks/<pid>.sock` and writes `~/.claude/sessions/<pid>.json` (`entrypoint:"codex"`, `harness:"codex"`) plus a `<pid>.<sha256(sock)>.key` peer key.
  - It verifies inbound auth tokens (fixes ASTRA gap 5) and relays frames to the hub over stdio.
- **`pb`** (`bin/pb`): the Codex-side command (`pb list`, `pb send <to> <text>`, `pb name <new>`, `pb whoami`). It finds its own stub from `CODEX_THREAD_ID` and writes a CC user frame directly to the target socket, using the stub's address as `from`, so replies route back into the Codex thread. A Codex target is just another stub, so Codex⇄Codex uses the same path. It waits briefly for the receipt.
- **Codex skill** `~/.codex/skills/peerbridge/SKILL.md` teaches every Codex session `pb`.
- **Autostart:** a Codex `hooks.json` SessionStart entry runs `pb ensure`, which starts the hub if it is not running (idempotent). On macOS a launchd agent lives in `~/Library/LaunchAgents`, with code in `~/.peerbridge`, never `~/Documents` (TCC trap).

### Receipts: CC's own convention (corrected after lane B, research/lane-B-cc-protocol.md §4)

CC 2.1.281 sends **no receipt for an accepted message**. It shows `delivered` to the sending model as "approved and released after hold". peerbridge does the same:

| Event | Wire frame to the CC sender |
|---|---|
| `turn/start` accepted (idle: new turn; busy: steered) | **none**. The local event `~/.peerbridge/events.jsonl` records `inbound … injected: started a new Codex turn \| steered into the running Codex turn` |
| Codex refused the input (RPC error, or target not exposed by policy) | `peer_message_status` `status:"expired", status_detail:"refused"`. This is how CC sends refused. |
| Codex daemon unreachable | `status:"dropped", drop_reason:"queue-full", dropped_msg_ids:[id]` |
| Held/denied/expired/dropped notice for a message *Codex* sent | `pb send` prints it if it arrives within 1.5 s. Otherwise the hub injects `[Cross-session delivery notice] …` into the Codex thread. |

**Every outbound frame (pb sends, receipts, idle notices) is written by the stub's own pid.** CC pins its receipts and idle notices to the pid that connected (`expectPeerPid`). If anything else wrote them, CC's replies to the stub would be refused as `wrong-endpoint`.

**Approvals (review #2, refuted live 22:37).** A turn injected on an `on-request` thread raised its approval prompt in the owning TUI, not in the hub. The peer row showed `waiting`, and approving in the TUI finished the command.

### from-mode (the hold problem)

The CC receiver HOLDS a message whose declared mode differs from its own. Our agents run in bypass mode. The stub declares `bypass` only when the Codex thread really runs without approvals (`approvalPolicy: never`). Otherwise it declares `prompting`, which is honest: the receiver holds the message for its user.

### Status mapping

`idle`→idle · `active[]`→busy · `active[waitingOn*]`→waiting · `systemError`→idle · `notLoaded`/`thread/closed`→unregister. `notify_when_idle` is answered with a `peer_idle_notice` when the thread next turns idle.

## Dead ends and why

| Option | Why not |
|---|---|
| Revive ASTRA `peer.ts` | Single-tenant, delivery by lease pump or heartbeat, status stuck on `busy`, code under `~/Documents` (TCC). The daemon makes all of that unnecessary. |
| tmux typing | No provenance, `rc=0` does not mean submitted, needs a terminal. |
| One process that binds every socket | CC's sender checks `LOCAL_PEERPID` against the record's pid, and the record is named `<pid>.json`. So one pid can carry one peer row only. |
| `codex-app-tools send_message_to_thread` | Host-only (ChatGPT.app executor). |
| `thread/inject_items` | Adds to history without starting a turn: no wake. |

## Known limits (honest)

- **Exit lag.** A thread is unloaded about 60 s after its TUI exits. Until then its row stays listed and status stays real; a message in that window would run a headless turn. Observed: TUI killed 22:18, `thread/closed` at 22:19:25.
- **Desktop app.** Codex desktop (ChatGPT.app) threads are covered only if the app uses the same daemon. NOT verified; the app is not running.
- **Windows.** See `docs/WINDOWS.md`.

## Lane A additions (research/lane-A-codex-native.md, all live-tested)

- **Invisible sessions.** A `codex` launched with any `-c`, `--enable`, `--disable` or `--search` flag skips the shared daemon, as the TUI warns. Such a session is not bridged. Launch agents without those flags, or put the settings in `config.toml` or a profile.
- **Desktop app (ChatGPT.app, bundled codex 0.154-alpha).** It runs a private app-server by default. Only with `CODEX_APP_SERVER_USE_LOCAL_DAEMON=1` does it use the shared daemon. NOT covered by default.
- **Unload timing.** A thread is unloaded exactly 60 s after it is idle with no subscribers (`thread_unload_delay_secs`, set in the daemon config). Nothing is emitted when the TUI disconnects.
  - `turn/start` does not subscribe the caller. `thread/resume` does subscribe, which would pin dead threads. **The hub never calls `thread/resume`.**
- **Native durable mailbox.** `thread/queue/add` (what `codex queue` uses) waits for idle and never steers. It also works for unloaded threads and runs when they load again. Candidate v0.3 mode: deliver to a thread whose TUI is gone.
- **Hooks** run as children of the daemon, with the daemon's env (not the TUI's). `SessionStart` fires at the first turn. The thread id comes only from the hook's stdin `session_id`. Our SessionStart hook is therefore only a hub-liveness kick (`pb ensure`). Discovery comes from daemon broadcasts.
- **Provenance.** The hub sets `clientUserMessageId` = the CC `msg_id`. It comes back as `userMessage.clientId` in item events, which is a hook for a future read receipt.
