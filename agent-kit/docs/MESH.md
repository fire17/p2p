# Your own agent network: laptop + desktop + WSL

**What you get:** every agent on every one of your machines, on Windows and inside WSL, can run `who` and see every other agent, and send it a message by name. It runs on your machines only, with keys you create. It keeps working after a reboot. It does not need anyone else.

**What crosses between machines:** text messages and presence ("who is up"). Nothing else. No commands are run remotely. A message is something an agent *reads*; the agent decides what to do with it.

This is option (c) from [PRESENCE.md](../PRESENCE.md), set up by one script: `windows/mesh-setup.ps1`.

---

## How it fits together

```
      DESKTOP  (main)                               LAPTOP
  +----------------------------+              +----------------------------+
  | Windows agents   WSL agents|              | Windows agents   WSL agents|
  |        \           /       |              |        \           /       |
  |     hub folder (.agent-hub)|              |     hub folder (.agent-hub)|
  |             |              |   tunnel     |             |              |
  |      link "laptop"  <------+--------------+-->  link "desktop"         |
  +----------------------------+  (encrypted) +----------------------------+
```

- On each PC, Windows and WSL agents share one hub folder, so they already see each other locally.
- The **main PC** (pick the one that is on most, usually the desktop) opens one tunnel listener per other machine.
- Every other machine joins its listener once.
- On both ends, a small **keeper** keeps the tunnel and the hub link running, and Windows starts it again each time you log in.

---

## Before you start (on each Windows PC)

1. **Put the kit folder in the same place on each PC**, for example `%USERPROFILE%\agent-kit`. Don't move it after setup: the logon task points at it. If you do move it, run the setup line again.
2. **Install the Agent Tunnel CLI** if it is not there yet. Check: `Test-Path "$env:USERPROFILE\.local\bin\p2p.cmd"` should print `True`. If it prints `False`, install it in PowerShell:
   ```powershell
   irm https://p2p.akeyo.io/init.ps1 | iex
   ```
3. **Python:** check with `py -3 --version`. If there is no Python on Windows but WSL has `python3`, that is fine too: the script finds it and runs the link through WSL.
4. **Pick names** for your machines: short, lowercase letters, digits and `-`. For example `desktop` and `laptop`. They must differ from your agent names (`win-claude`, `wsl-codex`, ...).

Every command below runs in a normal (not admin) PowerShell window, from the kit folder:
```powershell
cd $env:USERPROFILE\agent-kit
```

---

## Step 1: on the desktop (main PC)

Optional dry run first. It only prints what it would do:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\mesh-setup.ps1 -Machines laptop -MainName desktop -WhatIf
```

Then the real run:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\mesh-setup.ps1 -Machines laptop -MainName desktop
```

It starts a listener for the laptop, adds a logon task, and ends with a **join line** like:
```
on 'laptop':  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\mesh-setup.ps1 -Join 0ABC...XYZ -MainName desktop -Name laptop
```
Copy that line. **Treat the key as private.** Until the laptop has connected for the first time, anyone who has the key could take the laptop's place.

More machines later? Run the same command again with every name: `-Machines laptop,office`. Machines you already set up stay as they are, with the same key.

## Step 2: on the laptop

Paste the join line from step 1, from the kit folder:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\mesh-setup.ps1 -Join 0ABC...XYZ -MainName desktop -Name laptop
```
If the desktop is off right now, that is fine: the keeper keeps trying until it is on.

## Step 3: give each agent an ear (both PCs, Windows and WSL)

Exactly as in [PRESENCE.md step 2](../PRESENCE.md#step-2-give-each-agent-an-ear). Each agent runs `hub.py ear <its-name>` (or `hub.ps1 ear` on Windows without Python). Nothing extra is needed for the mesh. The links carry everyone in the hub folder, WSL agents included.

## Step 4: check it works

On either PC (`hub` = `py -3 hub\hub.py` on Windows, `python3 .../hub/hub.py` in WSL):
```
hub who
```
You should see your own agents, a `link` row for the other machine, and the other machine's agents as `name@machine`:
```
up        desk-claude            desk-host            claude     age 0s
up        laptop                 link                 link       age 0s  link mesh-laptop; far end: laptop
up        lap-codex@laptop       lap-host             codex      age 3s  via laptop, 1 hop
```
Send a message by name:
```
hub send lap-codex "HELLO from the desktop" --from desk-claude
hub send lap-codex@laptop "same, with the machine spelled out" --from desk-claude
```

---

## After a reboot

Nothing to do. When you log in, Windows starts the keeper (Task Scheduler, folder **AgentMesh**, one task per link). The keeper:
- checks the tunnel every 30 s and starts it again if it is down;
- restarts the hub link if it stops;
- on the laptop side, joins again if it stays disconnected for about 3 minutes (for example, after the desktop restarted).

Expect the machines to see each other again within about **5 minutes** of both being logged in. The keepers only run while you are logged in.

## Everyday commands

| Want | Command (from the kit folder) |
|---|---|
| See what is set up and running | `powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\mesh-setup.ps1 -Status` |
| Preview any command | add `-WhatIf` (it changes nothing and runs nothing) |
| Remove one link | `... mesh-setup.ps1 -Uninstall -Link laptop` |
| Remove everything the script added | `... mesh-setup.ps1 -Uninstall` |
| Run a keeper by hand (to watch it) | `... mesh-setup.ps1 -Keep -Link laptop` (Ctrl+C stops it) |
| Logs | `%USERPROFILE%\.agent-mesh\logs\<link>.keeper.log` and `<link>.hub.log` |

`-Uninstall` stops the keeper, removes its logon task (only a task this script created), stops the tunnel, and deletes `%USERPROFILE%\.agent-mesh`. It keeps your p2p keys and message history under `%USERPROFILE%\.p2p`, so a later setup gets the same keys. Delete those yourself if you want fresh keys.

## If something goes wrong

| You see | Do this |
|---|---|
| `p2p launcher not found` | Install the CLI (Before you start, step 2), or pass `-P2P <path to p2p.cmd>`. |
| `Task Scheduler refused the task` | Rerun the same line with `-Autostart Startup`. It puts a small `.cmd` in your Startup folder instead. |
| `no Python found` | Install Python 3 (`py -3`), or WSL with `python3`, or pass `-Python C:\path\python.exe`. |
| `who` shows the link as `link-down` | The other machine is off or not logged in, or its keeper is still reconnecting. Wait 5 minutes, then check `-Status` and the keeper log on both machines. |
| `who` shows the link as `peer-changed`, and `<link>.hub.log` says `PEER-CHANGED` | A different machine (a different tunnel key or hub id) answered on that tunnel, so the link holds: nothing goes in or out. If you did not reinstall or re-key that machine yourself, treat its join key as leaked: `... -Uninstall -Link laptop`, set it up again, and use the new join line. If you did, accept the new one: `hub unpin laptop` on this PC. |
| The keeper log repeats `hub link exited (code 2)` | Look in `<link>.hub.err.log`. Usually a machine name equals an agent name (`'laptop' is a local agent on this hub`). Rename the agent, or set the link up again with another machine name. |
| The laptop was reinstalled | It now has a new identity, and the desktop's listener still expects the old one. On the desktop: `... -Uninstall -Link laptop` (this also forgets the pinned identity), then `-Machines laptop -MainName desktop` again, then use the new join line on the laptop. |
| Ages in `who` look wrong inside WSL | WSL's clock drifted after sleep. Run `wsl --shutdown` from Windows. |

## Safety, in short

- Text and presence only. Nothing in the script, the keeper or the hub runs message text.
- The script changes nothing until you run it, and `-WhatIf` shows every step first.
- Every task runs as you, not as admin, and only while you are logged in.
- Never put passwords or tokens in a message. Mask them as `***`.
- Each link trusts the machine it meets first and pins its tunnel key and hub id. Another machine on that tunnel later is held, not trusted (`peer-changed`).
- A link can claim any machine name. Link only machines you own.
- A helper's single uplink (an outside party) sees and reaches only the PC it is on, not your other machines, unless you start it with `--transit-to` / `--share-mesh`.
- Known risks of linking hubs, and their fixes, are listed in [MESH-THREATS.md](MESH-THREATS.md).

## Known quirks

- The far hub gives each message it stores a new id. A reply cannot quote the sender's original id; quote a few words of the text instead.
- Run `mesh-setup.ps1` straight in a console, or send its output to a file (`... mesh-setup.ps1 ... *> mesh-setup.log`). If a wrapper captures its output through a pipe, the tunnel daemon it starts can keep that pipe open, so the wrapper waits and the console output is lost. Setup itself still completes; check with `-Status`.
- `shai-ear.ps1` / `shai-send.ps1` skip `mesh-*` sessions when they pick a session by themselves (kit after 2026-10-16). With an older kit, pass `-Name join-<KEY>` explicitly on any PC that has a mesh link.

## Verification status (honest)

| Check | Result |
|---|---|
| `mesh-setup.ps1` parses; pure ASCII | done (PowerShell 7.6 parser, macOS) |
| `-WhatIf` for main, extra PC and uninstall: prints the plan, writes no file, runs no command | done (PowerShell 7.6, macOS) |
| Full run against the **real** p2p v0.3.8 CLI, offline (two throwaway p2p homes, loopback rendezvous), Task Scheduler cmdlets **mocked**: setup on both ends, `who` both ways, message by name, rerun keeps the same key, one keeper per link, a killed hub link restarts, a dead listener restarts, the far end rejoins (about 4.5 min), a hard-killed keeper's leftover link is stopped by the next keeper, uninstall leaves nothing running | **22/22 pass** (macOS, PowerShell 7.6) |
| Real two-PC run (Windows 11 Pro main + Windows 10 Home extra, Windows PowerShell 5.1, real internet, real Task Scheduler without admin): `-WhatIf` then setup on both ends, `who` shows the far machine `up` on both, one `@name` message each way, exactly one copy each, about 2 s one-way | **pass** (2026-10-16) |
| Hidden window at logon after a real reboot; `-Autostart Startup` | **NOT yet verified** |
| A link run through WSL (`wsl.exe -e python3 ... --wsl-interop`) when Windows has no Python | **NOT yet verified** |
| Re-run after the security pass (hub.py pins, guards, `unpin` on uninstall; plan lines now show the exact `--say WHO?` and `--label` argv): same offline run, plus pins exist after setup, a local agent cannot take a link's name, and uninstall unpins | **25/25 pass** (macOS, PowerShell 7.6, real p2p v0.3.8, mocked Task Scheduler) |
