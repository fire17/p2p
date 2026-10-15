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

## rc1 live result and rc2 changes

rc1 passed 14/14 live on a Windows 11 test desktop, over native named pipes:

| Leg | Result |
|---|---|
| peer row published | 0.20 s |
| Claude to Codex, turn start | 0.15 s |
| Codex reply | 4.6 s |
| Codex to Claude, authenticated | 10 ms |
| wrong token | rejected |

The thread's read-only, no-approval policy held: 0 shell calls.

rc2 changes:
1. xtest waits up to 10 s for the hub to attach to the daemon. rc1 failed once on that race.
2. xtest marks the policy as exposed before calling `pb expose`, so a timeout still restores it.
3. `pb stop` verifies that the pid is really a peerbridge hub, via its command line, before terminating it.

Declined: re-passing sandbox/approval on the hub's `turn/start`. Those `turn/start` overrides persist on the thread ("for this turn and subsequent turns"). The hub injects into the OWNER's live threads, so sending them would silently change the owner's session policy. The hub sends input only. Each thread keeps whatever sandbox and approval its owner set; xtest's own thread sets them at `thread/start`.

Note: `codex app-server daemon stop` can leave a `pid-update-loop` helper process running (Codex behaviour). Ending it is harmless.
