# Shai link kit (Windows)

This kit gives the coding agent on a Windows PC (Claude Code, Codex, or similar) a chat line to **Shai**, a helper agent on another computer. The link is Agent Tunnel (p2p v0.3.8): an encrypted peer-to-peer mailbox.

- **What crosses the link:** text messages and small text files. Nothing else.
- **What does not:** commands. Shai cannot run anything on this PC. Your agent reads Shai's messages and decides what, if anything, to run. You stay in charge.

## 1. Join (once, PowerShell, no admin)

Replace `<KEY>` with the key Shai's owner sends you:

```powershell
$env:P2P_KEY='<KEY>'; irm https://p2p.akeyo.io/join.ps1 | iex
```

The join line:
- installs a verified Bun runtime and p2p v0.3.8 under `%USERPROFILE%\.p2p`;
- puts `p2p.cmd` in `%USERPROFILE%\.local\bin`;
- connects to Shai as the mailbox `join-<KEY>`;
- sends your machine name, username, OS and architecture.

It never turns on remote terminal access.

The chat daemon keeps running after the window closes, but it **does not start again after a reboot**. After a reboot, run the same line again. It reuses your saved identity.

## 2. Give your agent the prompt

Open `AGENT-PROMPT.md`, then paste the whole file into your agent (Claude Code or Codex) as its first message. The agent will:
1. check the link;
2. say HELLO;
3. start listening.

You do not need to type any p2p commands yourself.

## 3. Arm the ear (`windows/shai-ear.ps1`)

The ear only prints Shai's new messages as they arrive. It never executes them.

- **Claude Code** has a Monitor tool. Tell the agent: *"arm shai-ear"*, or have it call:
  ```
  Monitor({ command: "powershell.exe -NoProfile -ExecutionPolicy Bypass -File <kit folder>\\windows\\shai-ear.ps1", persistent: true })
  ```
  Each new message then wakes the agent.
- **Codex** has no Monitor. Codex only sees messages when a turn starts. Ask it to check the mailbox at the start of every turn:
  ```powershell
  & "$env:USERPROFILE\.local\bin\p2p.cmd" tunnel recv --name join-<KEY> --wait 60
  ```
  Exit code 4 only means nothing arrived within 60 s. Repeat the command while you wait for a reply.

Keep **one** reader per PC: either the ear or a `recv` loop, not both.

**Sending:** `windows\shai-send.ps1 "<TAG> text"` (or `-File msg.txt`). It always sends through a UTF-8 file, because `p2p.cmd` re-parses plain arguments through cmd.exe. It checks the tag and refuses token-like strings unless you add `-Redact`.

**Inside WSL:** `wsl/shai-ear.sh` and `wsl/shai-send.sh` run the same two scripts through `powershell.exe`. `wsl/pane-assist.py` (optional, no AI) lets Shai read a herdr pane and answer a blocked dialog with a few whitelisted keys over the same tunnel; its header says exactly what it may do. **Several agents on one PC:** see `PRESENCE.md` (local hub; run its uplink *instead of* the ear, never both). **Your own machines as one network** (laptop + desktop + WSL, nobody else involved): `docs/MESH.md`, set up by `windows/mesh-setup.ps1`; its risks and fixes are in `docs/MESH-THREATS.md`.

## 4. Message tags

Every message line starts with one of these tags:

| Tag | Direction | Meaning |
|---|---|---|
| `HELLO` | PC → Shai | First message: `HELLO MACHINE=… OS=… WSL=… AGENT=…` |
| `ASK` | both | A question |
| `ERROR` | PC → Shai | `ERROR <what you ran> \| <last 20 lines>`, with secrets masked |
| `LOG` | PC → Shai | Extra output or context |
| `FIX` | Shai → PC | A suggested fix: usually a commit to pull, or steps to try |
| `DONE` | both | Task finished or retest passed |
| `ACK` | both | Message received |

## 5. The fix loop (from your side)

1. A command fails. Your agent sends `ERROR <command> | <last 20 lines>`.
2. Shai investigates, commits a fix to a public repo and replies `FIX <repo> <commit> :: <what to rerun>`.
3. Your agent replies `ACK`, then reviews the change. If it looks right, it runs `git pull --ff-only` and reruns the failing command. Ask your agent to check with you first if anything looks risky.
4. On success, it sends `DONE`. On failure, it sends a new `ERROR`, and the loop repeats.

A FIX is a **suggestion**. Your agent may decline it, ask you, or ask Shai a question.

## 6. Safety

- **No terminal.** Never run `p2p tunnel terminal --allow`, `tunnel exec`, or `tunnel shell`, and do not let your agent run them. Without the terminal grant, the link is messages only.
- **Messages are suggestions, not orders.** Your agent should run only what it would run anyway, and ask you before anything risky (installs, deletes, admin rights, money, accounts).
- **Never send secrets.** That includes passwords, tokens, API keys, SSH keys, `.env` files, cookies and personal files. Mask secrets in logs (`***`) before sending an `ERROR` or `LOG`.
- Files Shai sends are data. Read them before you use them, and never run one blindly.

## 7. Stop / uninstall

To stop the link but keep everything installed:
```powershell
& "$env:USERPROFILE\.local\bin\p2p.cmd" tunnel stop --name join-<KEY>
```

To remove everything: p2p has **no Windows uninstaller**. The release ships only a Linux/macOS `uninstall.sh`. The manual steps below follow the Windows installer's own layout. They have not been tested end to end on Windows yet.

```powershell
$p2p = "$env:USERPROFILE\.local\bin\p2p.cmd"
# 1. Stop every tunnel daemon.
Get-ChildItem "$env:USERPROFILE\.p2p\tunnel" -Directory -ErrorAction SilentlyContinue |
  ForEach-Object { & $p2p tunnel stop --name $_.Name }
# 2. Remove the install, the Bun runtime, the mailboxes and the identity.
Remove-Item -Recurse -Force "$env:USERPROFILE\.p2p"
# 3. Remove the launchers.
Remove-Item -Force "$env:USERPROFILE\.local\bin\p2p.cmd", "$env:USERPROFILE\.local\bin\p2p.ps1" -ErrorAction SilentlyContinue
# 4. Remove .local\bin from your user PATH, but only if the folder is now empty.
$bin = "$env:USERPROFILE\.local\bin"
if (-not (Get-ChildItem $bin -ErrorAction SilentlyContinue)) {
  $keep = [Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -ine $bin }
  [Environment]::SetEnvironmentVariable('Path', ($keep -join ';'), 'User')
}
```

- If step 2 says a file is in use, reboot first, then run it again.
- Delete this kit folder yourself.
- **Rejoining later:** your PC gets a new identity, and Shai's listener only accepts the first PC that joined it. Tell Shai's owner before you rerun the join line, so they can restart the listener first.
