# admin-runner: owner-approved elevated commands

A user-level agent can ask for one elevated PowerShell command. It runs only after the machine's owner approves that exact command (its id and sha8). Every decision is logged.

## Flow
1. The agent queues the command: `request.ps1 -Command "<powershell>" -Reason "<why>"`. It prints `id`, `sha8` and the exact command.
2. The owner sees the id, the sha8, the reason and the exact command, and approves (for example with a chat button).
3. The agent records that approval and starts the runner: `approve.ps1 -Id <id> -Sha8 <sha8> -By "<approval reference>"`. This starts the on-demand task `\AgentAdmin\AgentAdmin-Runner`.
4. The runner (elevated, one pass) runs the command only if all of these hold:
   - the approval's sha8 equals sha256 of the command as loaded at run time (a command changed after approval is refused);
   - the approval is at most 10 min old;
   - the request is at most 60 min old;
   - the command is at most 2000 chars;
   - the id was never handled before.

   The command runs in a child PowerShell with a 10-minute limit. The runner writes `results\<id>.json` (stdout, stderr, exit code), appends one line to `audit.log`, and moves the request and approval to `done\`. A refusal is also logged and moved, so nothing is retried or run twice.
5. `status.ps1 -Id <id>` shows the outcome.

Root: `C:\ProgramData\AgentAdmin\` (`queue\ approved\ done\ results\ bin\ audit.log`).

## Install (once per PC, by the owner, elevated)
`powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -WhatIf` shows the plan. Run it again without `-WhatIf` from an elevated PowerShell. It does the following:
- creates the folders;
- sets ACLs: the user may write only `queue\` and `approved\`, and only reads `bin\`, `results\`, `done\` and `audit.log`;
- copies `runner.ps1` + `common.ps1` into `bin\`, so a user-level process cannot edit what runs elevated;
- registers the task (RunLevel Highest, no trigger, run headless via `conhost.exe --headless`).

Uninstall: `install.ps1 -Uninstall` removes the task and `bin\`, and keeps `audit.log`, `results\` and `done\`.

## The risk, honestly
The approval is a human check, not a cryptographic one. `queue\` and `approved\` are writable by the owner's user account. So **any process running as that user** can queue a command and write a matching approval, then start the task, and so get administrator rights without the owner. That covers the agent itself, a compromised agent or tool, or malware running as the user. In effect this is "UAC off for this user", guarded only by the agents' own discipline.

The sha8 (32 bits) shows WHICH command was approved. It is not a secret: anyone who can write `queue\` can also write `approved\`.

The protections that do hold:
- `bin\` (what runs elevated) is admin-write only;
- an approval expires after 10 min and works exactly once;
- every run and refusal is in `audit.log`, which the user can read but not rewrite.

A stronger variant would have the approver sign `(id, sha256)` with a private key the PC never holds, and the runner verify that signature with a public key stored admin-only. That removes the local-forgery path.

## Tests
`tests.ps1` runs request -> approve -> runner against a temp root without elevation (`-TestRoot <dir> -NoElevate`). It checks:
- an approved, matching command runs exactly once;
- a wrong sha8 is refused;
- a stale approval is refused;
- a replay is refused;
- a command over the limit is refused;
- a command swapped after approval is refused;
- the audit lines are written.
