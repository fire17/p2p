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

## Signed mode (recommended)
Install with `install.ps1 -ApproverKey <approver.pub.xml>`. The approver's RSA **public** key goes to `bin\approver.pub.xml`, which is admin-write only. `install.ps1` refuses a private key and keys under 2048 bits. The private key stays with the approver and never touches the PC.

From then on, every approval must be the approver's JSON `{id, sha8, sha256, by, at, sig}`, recorded verbatim with `approve.ps1 -ApprovalJson <file|text>`:
- `sig` is RSA PKCS#1 v1.5 + SHA-256 over the UTF-8 bytes of `agent-admin-v1|<id>|<sha256>|<by>|<at>`, with `at` exactly `yyyy-MM-ddTHH:mm:ssZ`;
- `sha256` must equal the sha256 of the command as loaded at run time;
- all other checks (age, single use, size, lock, audit) still apply;
- there is no unsigned fallback: a sha8-only approval is refused, and `approve.ps1 -Sha8` refuses on a signed install.

## The risk, honestly
**Unsigned mode** (no `-ApproverKey`): the approval is a human check, not a cryptographic one. `queue\` and `approved\` are writable by the owner's user account. So any process running as that user can queue a command and write a matching approval, then start the task, and so get administrator rights without the owner. That covers the agent itself, a compromised tool, or malware running as the user. In effect this is "UAC off for this user". The sha8 only shows WHICH command was approved; it is not a secret.

**Signed mode** closes that local-forgery path. A process on the PC can still queue requests and write files into `approved\`, but it cannot produce a valid signature, so nothing runs without the approver's key. The remaining trust is:
- (a) **the approver's private key.** Whoever holds it can approve anything on this PC, so it must be kept like an admin password and rotated by reinstalling with a new public key;
- (b) **the owner's tap.** The approver should sign only what the owner approved for that exact id + sha256, and show the owner the exact command;
- (c) **availability.** If the approver is offline, nothing elevated runs. That's by design, with no fallback.

**What always holds:**
- `bin\` (the code that runs elevated, and the public key) is admin-write only;
- an approval expires after 10 min and works once;
- every run and every refusal is in `audit.log`, which the user can read but not rewrite.

The runner does not hide the command from the user account: `results\` are user-readable, so do not pass secrets in commands.

## Tests
`tests.ps1` runs request -> approve -> runner against a temp root without elevation (`-TestRoot <dir> -NoElevate`). It checks:
- an approved, matching command runs exactly once;
- a wrong sha8 is refused;
- a stale approval is refused;
- a replay is refused;
- a command over the limit is refused;
- a command swapped after approval is refused;
- the audit lines are written;
- signed mode, with a throwaway RSA-3072 key made in the test:
  - a valid signature runs once;
  - a tampered command, `by`, `at` or `sha256` is refused;
  - a missing signature is refused;
  - a sha8-only approval is refused;
  - a signature from another key is refused;
  - `approve.ps1` stores the JSON verbatim and rejects a sha256 mismatch;
- a cross-platform vector (`test-vector.json`, signed with Python `cryptography`): `VerifyData(payload)` is True, and `VerifyData(payload+"x")` is False.
