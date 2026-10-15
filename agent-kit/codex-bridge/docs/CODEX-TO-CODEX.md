# Codex ⇄ Codex: peerbridge vs `codex queue`

2026-10-15, claude-opus-5-5 (lane codex-skill). Codex 0.162.1, hub 0.1.0 → 0.2.0 (it was upgraded mid-test).
Tags: **[LIVE]** observed on this Mac with throwaway TUIs `peertest-cxskill-{1,2,3}` in `/tmp/peertest-cxskill`; **[CODE]** read from source; **[INFERRED]** reasoning, not tested.

## Two paths

**peerbridge (`pb send`).** Every loaded Codex thread has a stub process that is a Claude Code peer. So a Codex sender and a Codex target are just two CC peers:

```
Codex A shell: pb send <B> "..."            (CODEX_THREAD_ID identifies A)
  → hub control socket ~/.peerbridge/hub.sock     (v0.2: the hub sends on A's behalf)
  → A's stub writes a CC user frame into B's stub socket /tmp/cc-socks/<pid>.sock (auth token)
  → B's stub relays it to the hub over stdio
  → hub: turn/start {threadId: B, input: <cross-session-message from=A ...> + reply hint}
  → Codex daemon starts a turn in B (idle) or steers it into B's running turn (busy)
```

[CODE] `bin/pb` cmd_send → `hub.ctl_send` → `stub` "send" → target stub → `hub.on_user_frame` → `inject`.
v0.1 wrote the frame from `pb` directly to B's socket; v0.2 routes it through the hub and A's stub. Both were measured below.

**Native (`codex queue --thread <uuid|exact-name> --message <text>`).** Codex's CLI writes the item to `~/.codex/queue_1.sqlite` (`queued_items`: thread_id, payload `{"UserInput":{content, client_id}}`, queue_order) and the daemon runs it on the thread. [LIVE] row seen read-only in the sqlite while the target was unloaded.

## Behaviour, side by side

| Question | `pb send` (peerbridge) | `codex queue` |
|---|---|---|
| Idle target: starts a turn at once? | Yes [LIVE] | Yes [LIVE] |
| Renders in the target TUI? | Yes, as a user turn showing the `<cross-session-message from= from-name= from-mode=>` envelope plus a `[peerbridge] ... To reply: pb send '<from>'` line [LIVE] | Yes, as a plain user turn with only the text [LIVE] |
| Sender label? | Yes: `from` (exact `uds:` address), `from-name`, `from-mode` [LIVE] | **None.** The rollout record is identical to a typed message (`client_authored:false`, same metadata keys), so the target cannot tell who sent it or where to reply [LIVE] |
| Busy target | **Steers** into the running turn (same turn id). Test: "sleep 15 then STEERDONE" + 5 s later "also say ZULU" → one turn, final `STEERDONE ZULU` [LIVE] | **Waits.** The message runs as a new turn 7 ms after the current turn goes idle. Test: "sleep 15 then BUSYDONE-3" + 5 s later QTEST-3b → two separate turns [LIVE] |
| Target TUI closed / thread unloaded | Unreachable: the stub is reaped when the thread unloads (exactly 60.0 s after the TUI was killed), so there is no peer to address [LIVE] | **Durable.** `Queued message ...` (rc 0), row stays in `queue_1.sqlite`, and the turn ran ~0.9 s after `codex resume <uuid>` reopened the thread [LIVE] |
| Address by name | Peer name (hub-derived, e.g. `codex-peertest-cxskill-44`, or set with `pb name`) [LIVE] | Codex thread name (auto-titled, e.g. "Handle QTEST-1 reply", or user-set). `--thread "Handle QTEST-1 reply"` worked [LIVE] |
| Receipt | Failure-only: `NOT DELIVERED (<status>)` exit 2 for held/refused/expired/dropped; `accepted` after a quiet 1.5 s window (v0.2). v0.1 returned an explicit `delivered — injected: started a new Codex turn` in ~0.11 s [LIVE] | Only "Queued message <id> for thread <uuid>". No delivery or start signal [LIVE] |
| Reaches Claude Code sessions? | Yes, same command | No |
| From inside a `workspace-write` sandbox | Fails: v0.1 `[Errno 1] Operation not permitted`; v0.2 `pb: hub unreachable` (the UDS connect is blocked). Works after approving an escalated rerun [LIVE] | Fails: `failed to start embedded app server: Operation not permitted (os error 1)` [LIVE] |
| Policy / kill switch | Honors `~/.peerbridge/policy.json` (opt-in exposure, `pb off`) [CODE] | Not gated by peerbridge policy [INFERRED: it does not touch the hub] |

## Latency (throwaways, idle target, short prompts)

Measured from the sender command's start to the target's `thread/status/changed → active` notification, seen by a passive listener on the Codex daemon.

| Path | Runs (ms to target turn start) | Sender command wall time |
|---|---|---|
| `pb send` v0.1 (pb writes the frame directly) | 48, 43, 43 | 0.16–0.17 s (the delivered receipt came back after 0.10–0.11 s) |
| `pb send` v0.2 (through the hub and the sender's stub) | 39, 38, 40 | ~1.55 s (fixed 1.5 s no-news-is-good-news window) |
| `codex queue` | 224, 170, 145, 231 | 0.16–0.23 s (spawns the Codex binary, then talks to the daemon) |

Both are far below model latency (a 1-word reply turn took 1.7–4.2 s). peerbridge starts the target turn about 4× sooner; queue's cost is the Codex CLI start-up.

## When to use which

- **`pb send`**: the target must know who wrote and how to reply (provenance, reply address); the target is busy and should see it now (steer); the target is a Claude session; or you want a failure receipt.
- **`codex queue`**: leave a note for a Codex thread that is **not running** (it runs on resume); no bridge or hub needed. Put your own identity in the text, since none is attached.
- Not combinable: queue cannot carry the envelope's provenance (any `from=` text inside it is just text the sender typed, which is spoofable [INFERRED]).

## Observations worth fixing (for the lead)

1. **Sandbox error text.** In `workspace-write`, `pb send` says `hub unreachable (pb status / pb ensure)`. The hub is up; the sandbox blocked the socket. That message invites the agent to run `pb ensure`, which would try to spawn a second hub. Suggest: catch `PermissionError`/EPERM in `ctl()` and print "sandbox blocked ~/.peerbridge/hub.sock: rerun this pb command with escalation"; never spawn from `ensure()` when the socket file exists but `connect` gets EPERM. [LIVE error, CODE suggestion]
2. **Steer during a tool call.** When the steer landed while `sleep 15` was running, the model ran `sleep 15` a second time before finishing. That is model behaviour, not a bridge bug, but it means steering costs repeated work for long tool calls. [LIVE]
3. **Addresses and derived names change on hub restart.** Stub pids changed on each hub restart (28853 → 44895 → 52327 → 60488 → 66158 for one thread), and v0.2 renamed derived peers (`peertest-cxskill-cx44` → `codex-peertest-cxskill-44`). A `from=` address copied before a restart no longer resolves. A `pb name` rename survived (stored in `~/.peerbridge/names.json`). [LIVE]
4. **Idle subscription lost on restart.** A `--notify-idle` subscription pending when the hub restarted was flushed as `state: exited` to the sender's old stub (which was also going down), so the sender never got a notice. A retry with a stable hub worked: `[Cross-session idle notice] ... is now idle.` was sent 0.76 s after the target went idle (the hub's 0.75 s settle window). [LIVE]
5. **Unload lag.** A killed TUI's thread stays loaded for 60 s (`thread/closed` at +60.0 s). In that window `pb send` would start a headless turn nobody watches; `codex queue` would do the same. [LIVE timing, INFERRED consequence for queue]
