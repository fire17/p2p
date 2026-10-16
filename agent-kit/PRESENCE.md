# Presence: Windows, WSL and other computers

**The ask:** agents on this PC should be able to talk to each other (Windows ⇄ WSL), to agents on other computers, and always **know who is there**.

**The answer:** a small local hub on this PC (`hub/`). Every agent on the PC, on Windows or inside WSL, shares one folder. They leave heartbeats there and drop messages into each other's inboxes. One **uplink** process joins that folder to the Agent Tunnel, so Shai sees the whole PC as one link: who is up, and what each agent says.

- **What crosses:** text only.
- **What never crosses:** commands. Nothing in the hub runs what it receives. Each agent decides for itself.

---

## 1. Facts this design rests on

| Fact | Source (p2p v0.3.8) |
|---|---|
| One tunnel listener talks to exactly **one** peer. It pins the first peer that connects and closes any other. | `bin/p2p-tunnel.js:196-198` |
| The Windows join line creates the mailbox `join-<KEY>`. The CLI's default mailbox is `default`, so every command needs `--name join-<KEY>`. | `tools/join-client.mjs:27`, `bin/p2p-tunnel.js:285` |
| A mailbox is plain files: `<P2P_HOME>/tunnel/<name>/current.json` points to `<id>/`, which holds `state.json` and `inbox.jsonl`. `P2P_HOME` defaults to `%USERPROFILE%\.p2p` on Windows. | `bin/p2p-tunnel.js:74-82`, `src/tunnel.js:259-268` |
| `tunnel recv` moves a cursor, so two readers using `recv` rob each other. Reading `inbox.jsonl` by byte offset robs nobody. The uplink reads by byte offset. | `bin/p2p-tunnel.js:424-436` |
| `send --file` takes UTF-8 text up to 1 MiB. `send` exits 0 delivered, 3 failed, 4 no ack yet, 5 daemon down. | `bin/p2p-tunnel.js:380-406`, help text `:280` |
| A listener started with a fixed `--profile` keeps its key across restarts. | `bin/p2p-tunnel.js:306` |
| The Linux join script switches to **server mode** (keeper plus remote-terminal grant) on Linux with systemd and sudo. Inside WSL, always add `--chat-only`. | served `join.sh:5-6, 270-276` |

Windows and WSL are two separate operating systems on one PC. They share no process list, no sockets and no home folder. What they do share is the Windows disk: WSL sees `C:\Users\<you>` as `/mnt/c/Users/<you>`. That shared disk is the hub.

---

## 2. Three options

| | (a) One tunnel per machine | (b) Local hub + one uplink | (c) Your own network |
|---|---|---|---|
| **Shape** | Shai's side runs one listener for each of your machines (Windows, WSL, laptop…). Each one joins separately. | Every agent on this PC shares `%USERPROFILE%\.agent-hub`. One uplink connects that folder to Shai's existing tunnel. | Your main PC runs its own listeners, one per machine of yours. Every machine runs a hub, and uplinks join them. Shai is just one more link. |
| **Windows ⇄ WSL talk** | Only by bouncing through Shai's computer. | **Local, instant, no internet.** | Local. |
| **Who is there** | Shai sees one connected/waiting line per machine. Your agents see nothing. | Everyone runs `who`. Shai gets a `PRESENCE` line on every change, plus on demand with `WHO?`. | Everyone, on every machine, through `who` and `PRESENCE`. |
| **New keys** | Yes, one per machine, and every reinstall needs Shai's owner. | **None.** It uses the link you already have. | Only your own keys. You mint them, you control them. |
| **Depends on Shai** | Completely. | Only for the link to Shai. | Not at all. Shai is optional. |
| **Cost to start** | A key exchange per machine. | Copy one folder. Run one command per agent. | A listener plus a join per extra machine. |

**Tonight: (b).** It needs no new keys and no change on Shai's side. Windows and WSL talk locally, and presence works in both directions.

**Later: (c).** It is the same hub with more uplinks. Your machines form your own network, which works whether or not Shai is around. Shai's link stays one uplink among several.

**(a)** is the fallback, for one case: WSL needs its own direct link to Shai while Windows is off. Even then, (b) still covers local talk.

---

## 3. Tonight: the local hub (option b)

Put this kit folder at `%USERPROFILE%\shai-kit`. WSL sees the same folder as `/mnt/c/Users/<you>/shai-kit`.

**Python.**
- Inside WSL, `python3` is usually already there.
- On Windows, check with `py -3 --version`. Plain `python` can be the Store stub that only opens a store page.
- If Windows has no Python, Windows agents use `hub.ps1`, the PowerShell twin. It works on the same folder and has the same verbs, except `uplink`. The uplink then runs from WSL (step 1, WSL variant).

**Names.** Pick one name per agent: `<where>-<harness>`, for example `win-claude`, `win-codex`, `wsl-claude`, `wsl-codex`.

### Step 1: start the uplink, once per PC

This is the only process that reads the tunnel. While it runs, agents stop calling `tunnel recv` and talk only through the hub.

Windows PowerShell. Keep this window open; Ctrl+C stops it.
```powershell
$N = (Get-ChildItem "$env:USERPROFILE\.p2p\tunnel" -Directory | Where-Object Name -like 'join-*' | Select-Object -First 1).Name
py -3 "$env:USERPROFILE\shai-kit\hub\hub.py" uplink --session $N --as shai
```

WSL variant: use this when Windows has no Python. It drives the Windows p2p install through interop.
```bash
python3 /mnt/c/Users/<you>/shai-kit/hub/hub.py uplink --session join-<KEY> --as shai --wsl-interop
```

The uplink prints `LINK shai UP`. It then sends Shai a roster line like `PRESENCE win-claude(PC/claude) wsl-codex(PC-wsl/codex)`. It sends that line again whenever the roster changes, at most once every 20 s.

### Step 2: give each agent an ear

**Claude Code** (has Monitor; every message and JOIN/LEAVE line wakes it):
```
Windows:  Monitor({ command: "py -3 \"$USERPROFILE/shai-kit/hub/hub.py\" ear win-claude --harness claude", persistent: true })
  (no Python: Monitor({ command: "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"$USERPROFILE\\shai-kit\\hub\\hub.ps1\" ear win-claude -Harness claude", persistent: true }))
WSL:      Monitor({ command: "python3 /mnt/c/Users/<you>/shai-kit/hub/hub.py ear wsl-claude --harness claude", persistent: true })
```

**Codex**, or any agent without Monitor: at the start of every turn, run
```
python3 /mnt/c/Users/<you>/shai-kit/hub/hub.py ear wsl-codex --harness codex --once
```
That one call marks the agent present, prints its waiting messages and shows who is here. Between turns it shows as `stale`. That is honest: it is not listening right then, and its messages wait in its inbox.

### Step 3: talk

| Want | Command (`hub` = `py -3 …\hub.py` on Windows, `python3 …/hub.py` in WSL) |
|---|---|
| Who is here? | `hub who` gives `up` / `stale`, age, machine, harness. Shai's row shows `link-down` when the tunnel is down. |
| Message one agent | `hub send wsl-codex "run the tests" --from win-claude` |
| Message several | `hub send wsl-codex,wsl-claude "…" --from win-claude` |
| Message everyone on this PC | `hub send all "…" --from win-claude` (stays local and never goes to Shai) |
| Message Shai | `hub send shai "ERROR npm test \| 3 failing" --from wsl-codex` (Shai sees `[wsl-codex] ERROR npm test \| 3 failing`) |
| Multi-line | `--file report.txt` instead of the text |
| Read without staying present | `hub read <me>` |
| Leave | `hub bye <me>`. The ear does this itself when it stops. |

A message to an agent that is not up still waits in its inbox, and the sender is told `NOT UP`. A message to a name that has never been here is refused unless `--queue` is added.

### What Shai sees and sends

- **Sees:** `[<agent>] <text>` for every message an agent sends to `shai`. It also sees `PRESENCE …` lines.
- **Sends:**
  - `@wsl-codex <text>` reaches one agent. `@a,b <text>` reaches several, and `@all <text>` reaches everyone up.
  - A line with no `@` goes to every local agent that is up.
  - `WHO?` is answered automatically with the roster, and no agent is disturbed (at most once every 20 s).
- **Limits:** Shai reaches only agents on this PC that have been here before: never another machine, never another tunnel link, never a name that was never here (those lines wait in `inbox/shai-unrouted`). At most 16 names per line, and at most 30 messages a minute to any one agent (the rest wait in `inbox/<agent>/throttled/`). Shai's `WHO?` shows this PC only. The owner can widen this with `uplink --transit-to <machine> --share-mesh`.
- **Pinned:** the uplink trusts the tunnel key it meets first. If another key shows up later, it holds (`who` shows `peer-changed`) until the owner runs `hub unpin shai`.

The message tags from the agent prompt (`HELLO`, `ASK`, `ERROR`, `LOG`, `FIX`, `DONE`, `ACK`) still start the text.

---

## 4. Later: your own network (option c)

**Easiest:** `windows/mesh-setup.ps1` does all of this, plus autostart at logon. Step-by-step guide: [docs/MESH.md](docs/MESH.md).
By hand: same hub, one `link` per extra machine. Example: your main PC (`main`) and a laptop.

1. On `main`, open a listener **for the laptop**. One listener serves one machine, so add one per extra machine:
   ```powershell
   $P2P = "$env:USERPROFILE\.local\bin\p2p.cmd"
   & $P2P tunnel listen --name laptop --profile tunnel-laptop
   ```
   It prints a key. The fixed `--profile` keeps the key the same when you restart it.
2. Join from the laptop.
   - Windows laptop: `& ([scriptblock]::Create((irm https://p2p.akeyo.io/join.ps1))) <KEY>`
   - Linux or WSL laptop: `curl -fsSL https://p2p.akeyo.io/join.sh | sh -s -- <KEY> --chat-only`
3. Run one hub link on each end (`--as` = the OTHER machine's name, `--label` = this machine's name):
   - on `main`: `hub.py link --session laptop --as laptop --label main`
   - on the laptop: `hub.py link --session join-<KEY> --as main --label laptop`
4. Each side's `who` now shows the other machine's agents as `name@machine`, with the route:
   ```
   up  lap-claude@laptop  lap-host  claude  age 3s  via laptop, 1 hop
   ```
   Address them by name: `hub send lap-claude "<text>" --from win-claude`, or `lap-claude@laptop` when two machines share a name. The old form `hub send laptop "@lap-claude <text>"` still works. With more machines, each one sees all the others through `main`.
5. The Shai link is just the uplink from tonight, still running beside these. It does not see or reach your other machines (section 3, Limits).
6. Each link pins the tunnel key and hub id it meets first (`uplinks/<link>.pin.json`). If another machine shows up on that tunnel, the link holds until you run `hub unpin <link>`.

**Caveats:**
- **Restarts.** A listener on Windows does not restart after a reboot. Rerun step 1's `listen` line on `main` and each laptop's join line, then the uplinks.
- **Fresh identity.** If a laptop is reinstalled, its identity changes. Restart that listener first (`tunnel stop --name laptop`, then `listen` again) so it can accept the new identity (`bin/p2p-tunnel.js:196-198`), then `hub unpin laptop` on `main` so its link accepts the new key and hub id.
- **Names.** A machine name must differ from every agent name: a link refuses to start with a local agent's name, and an agent cannot take a link's name.
- **Unverified.** p2p `tunnel listen` on Windows is untested by this kit (see §7).

---

## 5. Option (a), for completeness

Shai's side runs one more listener in its own separate tunnel home. Shai's side runs:
```sh
P2P_HOME=<shai's tunnel home for you> p2p tunnel listen --name <you>-wsl --profile tunnel-<you>-wsl
```
Then WSL joins chat-only with the printed key:
```bash
curl -fsSL https://p2p.akeyo.io/join.sh | sh -s -- <KEY> --chat-only
```
The WSL mailbox is then `join-<KEY>` under `~/.p2p` inside WSL.

**Never leave out `--chat-only` inside WSL.** If systemd and sudo are present, the default becomes server mode (`join.sh:275-276`).

---

## 6. The hub on disk (any language can join)

```
.agent-hub/
  agents/<name>.json             {"name","machine","os","harness","note","pid","started","beat","remote"}
                                 beat = Unix seconds; up = younger than 45 s; hidden after 24 h of silence
  inbox/<name>/<ns>-<id>.json    {"v":1,"id","from","to","t","ts","text","via"}
  inbox/<name>/read/             claimed messages (gc after 7 days: hub.py gc)
  inbox/<name>/failed/           messages a link could never send (the sender got UNDELIVERABLE)
  inbox/<name>/throttled/        messages over 30 a minute from one sender (a reply loop?)
  uplinks/<as>.offset.json       the uplink's byte offset into the tunnel inbox + recent row ids (per generation)
  uplinks/<as>.pin.json          the far end trusted on first use: {"peer": tunnel key, "hub": hub id}
  mesh/hub.json                  this hub's id and machine label (Windows and WSL share it)
  mesh/peers/<id>.json           another machine's presence, as heard through a link
  mesh/seen/<msg id>             message ids already handled (each message at most once per hub)
```
On macOS/Linux/WSL-native paths the hub folder is `0700` and its files `0600`.

**Writing.** Every file is written as `.tmp-*` and then renamed, so a reader never sees half a message.

**Reading.** A reader **claims** a message by renaming it into `read/`. It prints the message only if that rename succeeded, so a message is printed exactly once even with two readers.

**Clock skew.** WSL2's clock can lag Windows after sleep. Ages in `who` then look wrong. Inside WSL, `sudo hwclock -s` (or `wsl --shutdown` from Windows) resyncs it.

**Safety:**
- No verb executes message text.
- The uplink skips terminal frames (`channel: "term"`).
- Broadcasts never leave the PC.
- Messages over 1 MiB are refused, the tunnel's own limit. An oversized or undeliverable message never stalls or stops a link.
- Printed fields are one clean line: control, bidi and invisible characters (zero-width, TAG block) are removed, and the reader is told how many.
- Never put secrets in a message. Mask tokens and passwords as `***`.

---

## 7. Verification status (honest)

| Check | Result |
|---|---|
| `python3 hub/hub.py selftest`: offline; presence, direct, broadcast, exactly-once claim, Hebrew/emoji, fake tunnel routing; the 3-hub mesh over fake links (relay, hop counts, loops, ttl, duplicates, hostile presence, forget, link down, late start); and one guard per docs/MESH-THREATS.md fix (transit, fan-out, name collisions, oversized and replayed rows, undeliverable, invisible characters, printed fields, peer pin, `WHO?` flood, inbox planting, file modes, rate limit, route hijack) | **67/67 pass** (macOS, Python 3.12 and 3.9) |
| `sh hub/test_e2e_p2p.sh`: the **real** p2p v0.3.8 CLI. Two throwaway tunnel homes meet over p2p's offline `--rendezvous-dir` loopback. The uplink pushes `PRESENCE`, routes `@wsl-codex`, forwards `[wsl-codex] ERROR...` back, and answers `WHO?`. All daemons are stopped afterwards. | **9/9 pass** (macOS, node) |
| `sh hub/test_e2e_mesh.sh`: the real p2p CLI, four throwaway homes: laptop -> main <- second plus a helper uplink. Presence relayed both ways, messages by name, name@machine and `@name`, no duplicates, idle traffic, leave propagation; the helper sees and reaches main only until `--transit-to`/`--share-mesh`; a thief who wins a restarted listener's key race is held (`PEER-CHANGED`) | **26/26 pass**, run 3 times (macOS, node) |
| `sh hub/test_interop.sh`: `hub.py` and `hub.ps1` (PowerShell 7) share one folder and see and message each other both ways, including Hebrew, multi-line and broadcast; both twins strip control/invisible characters and refuse a link's name | **16/16 pass** (macOS, pwsh 7) |
| `ear` live: JOIN, MSG and LEAVE lines; presence removed on SIGTERM and SIGINT | observed (macOS) |
| On real Windows: `hub.ps1` under Windows PowerShell 5.1; `hub.py` with `p2p.cmd`; Monitor command quoting in Claude Code for Windows | **NOT yet verified** |
| Inside real WSL: hub root auto-detection via `cmd.exe` and `wslpath`; `--wsl-interop` uplink; rename semantics on `/mnt/c` | **NOT yet verified**. If auto-detection fails, set `AGENT_HUB=/mnt/c/Users/<you>/.agent-hub`. |
| `p2p tunnel listen` on Windows (option c) | **NOT yet verified** |

The first real run on this PC should be:
1. `hub.py selftest` on Windows and inside WSL;
2. then `who` from both sides;
3. then `WHO?` from Shai.

---

## Agent bridge and matrix test

The hub is the bus. Delivery into each harness is native first, typing last. Full design: [docs/AGENT-BRIDGE.md](docs/AGENT-BRIDGE.md).

| Harness | How a message arrives |
|---|---|
| Claude Code | Native cross-session message through `codex-bridge/peerbridge/ccpeer.py`. It lands as a real turn, with no typing. |
| Codex | Run `pb expose --thread <id>` once. The thread then shows up as a ccpeer peer and gets the same native path. |
| Anything else, or no live peer | herdr typing, **only** if the pane is not blocked. A startup dialog (folder trust, hook review) can look idle, and an Enter there can exit the agent. If unsure, the message waits in the inbox. |

- **Replies** always go through `hub.py send <sender> "<text>" --from <me>`. Answer `MATRIX PING <id>` with `MATRIX PONG <id>` and nothing else.
- **Run the adapter:** `python3 hub/agent-bridge.py --config bridge.json` (try `--once --dry-run` first). Config format: docs/AGENT-BRIDGE.md section 4.
- **Check every path at once:** run `python3 hub/hub.py matrix --names a,b,c --pairs` (agents on this hub). Start with `selftest` and `who`.
- **Status:** **NOT yet verified** on real Windows + WSL, or across two machines with herdr.
