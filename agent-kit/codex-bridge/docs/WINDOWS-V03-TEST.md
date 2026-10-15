# v0.3.0-rc1 Windows test (native named pipes) - run on the Windows PC, non-elevated PowerShell

EXPERIMENTAL. This is the first build with native-Windows Claude<->Codex. It was validated on macOS (xtest 14/14) and NOT yet on Windows.

What it does: it starts the peerbridge hub from the unpacked folder (no install, no autostart, no config edits) and creates ONE Codex thread on the shared daemon (read-only sandbox, no approvals). The thread is archived afterwards.
- It makes the thread a Claude Code peer on `\\.\pipe\LOCAL\cc-msg-<hex>`, with a record in `%USERPROFILE%\.claude\sessions` (it removes its own record at the end).
- It plays both a Claude sender and a Claude receiver to prove each direction.
- It uses one tiny model turn.

```
cd <unpacked>\peerbridge-v0.3.0-rc1
codex app-server daemon start                 # or have one CLI codex open (non-elevated)
py xtest.py                                   # prints PASS/FAIL per step, exit 0 = all pass
py bin\pb stop                                # stop the hub started by the test
codex app-server daemon stop                  # only if you started it for this test
```

Optional real-Claude check, while a bridged thread exists. Keep `py xtest.py` paused or open a Codex TUI: in a REAL Claude Code session on that PC, ListAgents should list `codex-<folder>-xx`, and SendMessage to it should start a Codex turn.

Report: the full xtest output (it contains no secrets; pidDomain includes the hostname, so mask it if you like) and `py bin\pb doctor`.
