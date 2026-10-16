# Agent bridge: hub + native adapters

**The ask:** every agent, on every machine, receives peer messages the most native way its harness offers.
Typing into a terminal pane is the last resort, never the default.

**Status:** the adapter is `hub/agent-bridge.py` (`--config bridge.json [--once] [--dry-run]`; full
reference in its header). It passes `hub/test_agent_bridge.sh` and `hub/test_bridge_gate.sh` on macOS with a
fake ccpeer and a fake herdr.
The design was proven live on two real PCs: 56/56 all-pairs round trips across 8 agents, native adapters only
(section 8). That run used the field version of this bridge; the kit script carries its rules (whitelist, gate,
`+bypass`, NOT DELIVERED). Rows marked **NOT yet verified** in section 8 are exactly that.

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
- Claude Code **holds** a peer message for its user's approval when the envelope's `from-mode` does not fit
  the receiving session: no from-mode into a bypass session, **and also** `from-mode="bypass"` into a
  session that is NOT in bypass (for example auto mode). That is its anti-permission-laundering rule.
  So the adapter claims bypass only into routes marked `+bypass`, and only for trusted senders (section 5).
  Everything else goes without a claim. The adapter never claims more than the target runs.
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

The route's `peer` is the **exposed thread id** (`pb list` shows it). Exposure belongs to that thread:
after a Codex pane restart, run `pb expose --thread <id>` again (and update the route if the id changed).
Until then the route has no live peer, and the sender gets a NOT DELIVERED notice.

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
- reads `agent get <pane>` and refuses unless the state is `idle` (config `herdr_ok_states`), so `blocked`
  is always refused;
- also refuses if the pane's visible screen shows a dialog, even when herdr says `idle`;
- when unsure, does **not** type. The message goes back to the hub inbox, is retried with backoff
  (5 s up to 60 s), and the sender gets one `NOT DELIVERED <name> (id=<id>): <reason>` notice through the hub.

Typed text is one line, cleaned of control and invisible characters, and never contains a secret.
It lands as the pane owner's own input, with no peer-message approval hold. So on a `+bypass` route
the adapter types only for senders the gate trusts (section 5); anyone else's message waits for the
native path. On other routes any sender's message can be typed: give a pane a herdr route only if you
accept that.

### 2d. Inbox (always there)

If nothing above worked, the message waits in `inbox/<name>/` and the bridge retries it.
Do not also run `hub.py ear` for a bridged name: two readers of one inbox split its messages.

### 2e. Failures go back to the sender

A delivery error is never dropped silently. The bridge logs `ERROR` and sends the sender one notice over
the hub: `NOT DELIVERED <name> (id=<id>): <reason>`. Notices are never answered with notices (no ping-pong).

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
    "desk-codex":  {"harness": "codex",  "peer": "<codex thread id>", "pane": "codex"},
    "desk-rc":     {"harness": "claude", "peer": "desk-rc",     "pane": "rc"}
  }
}
```

`peer` is the name or session id `resolve()` / `pb list` knows (for Codex: the exposed thread id, 2b).
`pane` is used only for the 2c fallback.
The laptop has the same file with `lap-*` names. The two hubs are joined once with `hub.py link`
(PRESENCE.md section 4), after which `who` on either side shows all six agents.

To let trusted senders claim bypass into a session that runs bypassPermissions, mark that route `+bypass`
(command line: `--map desk-claude=peer:desk-claude+bypass`; in bridge.json: `"bypass": true` on that agent)
and start the bridge with `--gate trusted`. Never mark a session `+bypass` unless it really runs bypass.

Load the kit's `hub/hub.py` **by path** (as the bridge does). peerbridge ships its own `hub.py`; importing
by module name can pick up the wrong one.

---

### 4a. Start at logon, routes found at start

Fixed ids go stale: a restarted Codex pane gets a new thread id. `hub/agent-bridge-start.sh` (WSL/Linux, needs herdr, jq, pb, python3) finds the routes each time and (re)starts the bridge detached:

```
hub/agent-bridge-start.sh --prefix desk [--session main] [--dry-run] [--wait 120]   # one shot
hub/agent-bridge-start.sh --prefix desk [--session main] --watch 60                 # keep matching the panes
```

- `<prefix>-claude` / `<prefix>-rc` = the Claude Code session named like its herdr pane, only if exactly one live match. `+bypass` only when that claude process really runs bypassPermissions (read from `/proc/<pid>/cmdline`).
- `<prefix>-codex` = the thread the managed Codex daemon holds open for the herdr pane labelled `codex` (same cwd, created after that codex process started, any originator). Several candidates: the one pb already exposes; still ambiguous: no codex route, logged, never a guess. It runs `pb expose --thread <id>` for it, and `pb hide` for the thread it exposed before when the thread changes. No thread yet (Codex creates one at the pane's first prompt): the route is `herdr:<session>:<pane>` (typed, idle + dialog guarded) until the thread appears.
- One shot: missing peers are retried for `--wait` seconds, then it starts with what exists and logs what is missing.
- `--watch SEC`: rediscovers every SEC seconds and restarts the bridge only when the map differs on two checks in a row (one failed lookup never drops a route), or at once when no bridge runs. Covers reboots, pane restarts and the lazy Codex thread. One watcher per `$BRIDGE_DIR` (flock). Use this one from your logon script.
- Idempotent: a live bridge with the same routes is left alone. `--dry-run` prints the map and the command and changes nothing. Pid and log: `$BRIDGE_DIR` (default `~/.agent-bridge`).
- Call it from the script that starts your herdr session, after the panes are up, so a logon brings the bridge back too.
- Start the Claude panes in a dedicated folder (for example `~/agents`) and trust it once. Claude Code does not keep folder trust for the home folder, so panes started in `~` wait at the trust dialog at every logon and never register.

## 5. Trust: `trusted.json` and `--gate`

`--gate` decides when the bridge claims `from-mode="bypass"` (only ever into `+bypass` routes):

| `--gate` | Claims bypass for |
|---|---|
| `none` (default) | nobody: every message arrives without a claim |
| `trusted` | senders that match the whitelist below |
| `all` | everyone. Testing only: any sender then acts with the target's bypass rights |

The whitelist is `trusted.json` in the hub root. The bridge re-reads it whenever it changes on disk:

```json
{
 "log": ["YYYY-MM-DD HH:MM default: my agents here (local) and on my linked hubs. Approved by: <owner>"],
 "senders": [
  {"name": "desk-*", "via": "local"},
  {"name": "lap-*",  "via": "link:*"},
  {"name": "helper", "via": "tunnel", "session": "join-<KEY>"}
 ]
}
```

- `name` is an fnmatch pattern on the sender's hub name (the part before `@`).
- `via` is how the message reached this hub: `local` (written here), `link:<name>` or `link:*` (a hub
  link), `tunnel` (a `join-<KEY>` uplink). A message's via class must equal the entry's class: a tunnel
  message can never ride on a `local` or `link:*` entry, whatever name it claims.
- A `tunnel` entry needs `session: "join-<KEY>"` and counts only while the hub uplink of that name has
  pinned exactly that key (`uplinks/<name>.pin.json`).
- Missing or broken file: **nobody** is trusted, and the bridge logs `ERROR`. It fails closed.
- A `link:*` entry trusts whatever the far hub sends under a matching name. If that far hub runs an
  `uplink` with `--transit-to` reaching this machine, its tunnel peer's messages arrive here as link
  messages named after that uplink. Keep link patterns to the far hub's own agent names (`lap-*`),
  never `*`, and never name an uplink so that it matches them.

Who may edit it: **only the machine's owner**, on that machine. An agent never adds itself or a peer.
A `tunnel` entry is added only with the owner's explicit approval, and every change gets a dated line in
`log` saying what was added and where the owner approved it.

---

## 6. Verify: the matrix

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

Across machines, each machine sees only its own inboxes: a PING is recorded on the target's machine,
its PONG on the sender's. A table built on one machine proves only its half of each cross-machine pair.
Check (or merge) both machines' delivery files (`inbox/<name>/read/`) before calling a pair passed.

Run order on a fresh setup: `hub.py selftest` on each side, then `hub.py who`, then the matrix.
If `matrix` is reported as an unknown verb, this hub.py predates it: update the kit.

---

## 7. Known limits

- Native delivery is local to one OS on one machine. Machine to machine, and Windows to WSL, is always
  the hub first.
- Bypass is claimed only into `+bypass` routes for trusted senders. Untrusted messages into a bypass
  session are held for its user's approval: that is by design, not a fault.
- A Codex pane restart drops native delivery until `pb expose --thread <id>` is run again.
- A sandboxed (default) Codex replying to a bypass-mode Claude can be held for approval
  (codex-bridge/docs/HOLD-OPTIONS.md). The owner chooses; nothing here changes that setting.
- herdr `idle` is not "ready". The blocked-pane rule makes the fallback refuse rather than guess,
  so some messages wait in the inbox until a human clears the dialog.
- Hub guards still apply: 30 messages a minute per sender and target, 1 MiB per message,
  16 targets per line.
- Messages are data. No path in this design executes message text.

## 8. Verification status (honest)

| Check | Result |
|---|---|
| Real two-PC run: Windows 11 + Windows 10, bridge in WSL, herdr, 4 agents per PC (agent, claude, codex, remote-control), hubs linked | **56/56 all-pairs round trips passed** (8 agents, every ordered pair PING + PONG), checked against the hub's delivery files on **each** machine, not against agent claims |
| Which path carried them | native adapters only (Claude Code via ccpeer, Codex via exposed thread); the herdr fallback was not used |
| Rules from that run (whitelist, `--gate`, `+bypass`, re-expose, NOT DELIVERED, load hub.py by path, merge both tables) | proven with the field bridge; the kit's `hub/agent-bridge.py` port is tested by `hub/test_agent_bridge.sh` and `hub/test_bridge_gate.sh` (fakes) and **NOT yet re-run live** |
| Hub, mesh links, exactly-once claim | tested on macOS (PRESENCE.md section 7) |
| Adapter choosing native first, herdr only as fallback | tested on macOS with fake ccpeer + fake herdr (`hub/test_agent_bridge.sh`) |
| herdr fallback and blocked-pane refusal against a real dialog | tested with a fake herdr only; **NOT yet verified** on real herdr (unused in the live run) |
| `hub.py matrix` / `--pairs` on one hub | tested offline (`hub.py selftest`, `hub/test_matrix.sh`) |
| Native Windows (non-WSL) Claude Code or Codex as a target | **NOT yet verified** |
