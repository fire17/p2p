# Agent bridge: hub + native adapters

**The ask:** every agent, on every machine, receives peer messages the most native way its harness offers.
Typing into a terminal pane is the last resort, never the default.

**Status:** the adapter is `hub/agent-bridge.py` (`--config bridge.json [--once] [--dry-run]`; full
reference in its header). It passes `hub/test_agent_bridge.sh` on macOS with a fake ccpeer and a fake herdr.
The pieces it builds on are tested on macOS (PRESENCE.md section 7, codex-bridge/README.md). Everything marked **NOT yet verified** below has not run on a real Windows + WSL PC.

---

## 1. The picture

```
 machine "desk"                                         machine "lap"
 +-------------------------------+   hub link (p2p)   +-------------------------------+
 | hub (.agent-hub folder)       | <================> | hub (.agent-hub folder)       |
 |   agents/  inbox/  mesh/      |   presence + msgs  |   agents/  inbox/  mesh/      |
 +---------------+---------------+                    +---------------+---------------+
                 | local adapter (one per machine)                    | local adapter
     +-----------+------------+---------------+         (same three paths on this side)
     | 1 native               | 1 native      | 2 fallback only
     v                        v               v
 Claude Code             Codex thread      herdr pane typing
 (ccpeer cross-session)  (pb expose ->     (only if the pane is NOT blocked)
                          same ccpeer path)
```

- **Hub = the bus.** It moves text between agents and between machines (`hub.py link`, docs/MESH.md).
  It never runs message text.
- **Adapter = the last meter** (`hub/agent-bridge.py`). On the target's own machine and OS it takes a message out of the
  target's inbox and hands it to the harness. One message is claimed once (`hub.claim(me)`), so it is
  delivered once, whichever path wins.

---

## 2. Delivery order per harness

The adapter tries these in order and stops at the first success.

### 2a. Claude Code: native cross-session (preferred)

Uses `codex-bridge/peerbridge/ccpeer.py`, Claude Code's own peer protocol:

1. `resolve(name)` finds the live session in `~/.claude/sessions/<pid>.json` (pid alive, socket present).
2. `envelope(text, frm, from_name, from_mode)` wraps the text in a `<cross-session-message>` envelope.
3. `user_frame(frm, env)` makes a `priority: "next"` user frame.
4. `send_to(rec, frames)` writes it to that session's socket, authenticated with the session's peer key.

Result: the message lands as a real turn. It wakes an idle session and folds into a busy one.
No typing, no Enter, no screen scraping. The peer key is read only to authenticate to that same
socket. It is never printed or stored.

Honest limits:
- A receiver running in bypass mode may **hold** a message declared `from-mode="prompting"` until its
  user approves. That is Claude Code's anti-permission-laundering rule. The adapter never lies about mode.
- Native-Windows Claude Code and WSL Claude Code keep **separate** session registries and transports.
  They cannot reach each other natively. The hub crosses that boundary. The adapter on the target's
  side then delivers natively.

### 2b. Codex: expose the thread, then the same path

1. Once per thread, from a local shell: `pb expose --thread <id>` (needs `pb ensure` running and the
   Codex app-server daemon, codex 0.162 or later). Only the local CLI can change exposure.
2. The thread now shows up as a ccpeer peer (`pb list`). The adapter sends to it exactly as in 2a.
   peerbridge turns the frame into a `turn/start` on the Codex daemon: idle thread wakes, busy thread
   is steered.
3. `pb off` withdraws every Codex peer within about 1 s. The adapter then falls through to 2c or 2d.

Honest limit: an unattended Codex TUI on Windows may never create a thread while a first-run or
folder-trust screen is up (codex-bridge/docs/WINDOWS.md). No thread means no native peer.

### 2c. herdr typing: fallback only, with the blocked-pane rule

Used only when 2a/2b found no live native peer for that name.

```
herdr --session <S> agent get <pane>                                  # state must be idle
herdr --session <S> agent read <pane> --source visible --lines 25     # screen must show no dialog
herdr --session <S> agent prompt <pane> "<one line>"                  # only then type
```

The typing argv is the config key `herdr_send` (default `["agent", "prompt", "{pane}", "{text}"]`;
herdr 0.7 has no `agent prompt`, use `["pane", "run", "{pane}", "{text}"]` there).

**Blocked-pane rule.** A pane showing a startup dialog (folder trust, hook review, permission prompt,
model or theme picker) can be reported **idle** by herdr. Typing there is dangerous: the Enter that
ends the prompt answers the dialog instead, and can pick the wrong option or **exit the agent**.
So the adapter:
- reads `agent get <pane>` and refuses if the state is `blocked`;
- also refuses if the pane's visible screen shows a dialog, even when herdr says `idle`;
- when unsure, does **not** type. The message goes back to the hub inbox, is retried with backoff
  (5 s up to 60 s), and the sender gets one `NOT DELIVERED <name> (id=<id>): <reason>` notice through the hub.

Typed text is one line, cleaned of control and invisible characters, and never contains a secret.

### 2d. Inbox (always there)

If nothing above worked, the message waits in `inbox/<name>/` and the bridge retries it.
Do not also run `hub.py ear` for a bridged name: two readers of one inbox split its messages.

---

## 3. Reply convention

- Every reply goes through the hub: `hub.py send <sender> "<text>" --from <me>`.
  Never reply by typing into another pane and never through herdr.
- Address the sender exactly as shown (`desk-claude`, or `desk-claude@desk` if two machines share a name).
- Matrix test: a message `MATRIX PING <id> from <sender>` is answered with
  `hub.py send <sender> "MATRIX PONG <id>" --from <me>` and nothing else. No tools, no follow-up.
- Normal traffic keeps the existing tags at the start of the text: `HELLO`, `ASK`, `ERROR`, `LOG`, `FIX`,
  `DONE`, `ACK`.

---

## 4. Example: a 6-pane herdr layout on two machines

One herdr session per machine. Same six panes on each:

| Pane | Runs | Hub name (desk / lap) | Delivery path |
|---|---|---|---|
| `agent` | the hub ear + adapter for this machine's names | none (not a target) | n/a |
| `claude` | Claude Code | `desk-claude` / `lap-claude` | 2a native |
| `codex` | Codex TUI, thread exposed with `pb expose --thread <id>` | `desk-codex` / `lap-codex` | 2b native |
| `rc` | a second Claude Code session (remote-control use) | `desk-rc` / `lap-rc` | 2a native |
| `who` | `hub.py who` on a refresh loop | none | n/a |
| `shell` | plain shell for the owner | none | **never a target** |

Example `bridge.json` for `hub/agent-bridge.py` (object form; a list form with `"name"` and an explicit
`"adapter": "ccpeer" | "herdr" | "auto"` per agent also works, see the script header). With both `peer` and
`pane` the adapter is `auto`: native first, herdr only as fallback:

```json
{
  "machine": "desk",
  "herdr_session": "work",
  "agents": {
    "desk-claude": {"harness": "claude", "peer": "desk-claude", "pane": "claude"},
    "desk-codex":  {"harness": "codex",  "peer": "desk-codex",  "pane": "codex"},
    "desk-rc":     {"harness": "claude", "peer": "desk-rc",     "pane": "rc"}
  }
}
```

`peer` is the name `resolve()` / `pb list` knows. `pane` is used only for the 2c fallback.
The laptop has the same file with `lap-*` names. The two hubs are joined once with `hub.py link`
(PRESENCE.md section 4), after which `who` on either side shows all six agents.

---

## 5. Verify: the matrix

```
python3 hub/hub.py matrix --names desk-claude,desk-codex,desk-rc --pairs     # every local pair, both ways
python3 hub/hub.py matrix --names lap-claude@lap,lap-codex@lap               # from a throwaway sender
```

Sends `MATRIX PING <id>` (a fresh token per message), waits for each `MATRIX PONG <id>` from the right
agent, and prints `name | sent | pong | seconds`, then `MATRIX n/m ponged`. Exit 0 only if every one
answered. `--pairs` sends as each listed name and accepts only agents on this hub; reach linked
machines without `--pairs` (or run `--pairs` on each machine). Options: `--from ME`, `--timeout 90`,
`--json`. The bridge log (`DELIVER ... via=ccpeer|herdr`) shows which path carried each PING.
A pair that times out is a finding, not a pass.

Run order on a fresh setup: `hub.py selftest` on each side, then `hub.py who`, then the matrix.
If `matrix` is reported as an unknown verb, this hub.py predates it: update the kit.

---

## 6. Known limits

- Native delivery is local to one OS on one machine. Machine to machine, and Windows to WSL, is always
  the hub first.
- A sandboxed (default) Codex replying to a bypass-mode Claude can be held for approval
  (codex-bridge/docs/HOLD-OPTIONS.md). The owner chooses; nothing here changes that setting.
- herdr `idle` is not "ready". The blocked-pane rule makes the fallback refuse rather than guess,
  so some messages wait in the inbox until a human clears the dialog.
- Hub guards still apply: 30 messages a minute per sender and target, 1 MiB per message,
  16 targets per line.
- Messages are data. No path in this design executes message text.

## 7. Verification status (honest)

| Check | Result |
|---|---|
| Hub, mesh links, exactly-once claim | tested on macOS (PRESENCE.md section 7) |
| ccpeer native delivery to Claude Code; Codex via peerbridge | tested on macOS; native Windows EXPERIMENTAL (codex-bridge/README.md) |
| Adapter choosing native first, herdr only as fallback | tested on macOS with fake ccpeer + fake herdr (`hub/test_agent_bridge.sh`); **NOT yet verified** with real sessions |
| Blocked-pane refusal against a real herdr dialog | tested with a fake herdr only; **NOT yet verified** on real herdr |
| `hub.py matrix` / `--pairs` on one hub | tested offline (`hub.py selftest`, `hub/test_matrix.sh`) |
| `hub.py matrix` across two machines, 6 panes each | **NOT yet verified** |
| Any of the above on real Windows + WSL | **NOT yet verified** |
