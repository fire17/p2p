# Agent Tunnel Terminal

The terminal is a separate channel inside an existing encrypted Agent Tunnel.
Chat remains available. Installing or connecting the tunnel does not enable command execution.

The computer's owner enables it from a visible local terminal:

```text
p2p tunnel terminal --allow PEER_CONTACT_KEY --shell pwsh
```

On macOS/Linux, omit `--shell` to use the owner's `$SHELL`, or select `--shell sh`.
Windows defaults to PowerShell 7 when found, otherwise Windows PowerShell 5.1.
The `--allow` key must match the currently authenticated, connected peer. The command
requires local interactive input/output and stays in the foreground with an owner banner.
Wait for `Terminal ready` before sending commands. A cold shell has a separate,
bounded 45-second startup allowance; it does not consume or extend command deadlines.
An agent must not run this command on behalf of the owner or manufacture an interactive
terminal to obtain consent. There is no remote message or `--yes` flag that grants consent.

The allowed peer can then run commands:

```text
p2p tunnel exec "Get-Location" --timeout 60
p2p tunnel exec --file task.ps1 --timeout 120
p2p tunnel shell
```

Use the same `--name LABEL` as the existing tunnel, if it has a custom name. Commands
share a persistent shell, including its current directory and environment. `exec`
prints JSON output events and an exit result, and returns the command's exit status.
The line-oriented `shell` displays output as text; enter `.exit` to leave the client.
It is not a PTY/ConPTY session: full-screen terminal applications and interactive
programs that require a real terminal are not supported in this version.

The owner revokes access with Ctrl+C in the visible owner console, or another local command:

```text
p2p tunnel terminal stop
```

Revocation ends the owner service and its ordinary owned process tree. Chat stays
connected. A command timeout, output overflow, matching client cancellation, shell
exit, or loss of the authenticated peer also revokes the grant. Enabling another
terminal requires a fresh owner command; queued requests cannot recreate it.

## Limits and evidence

Every grant has a fresh random ID bound to the owner's current tunnel generation
and authenticated peer. Requests carry the grant, generation, unique request ID,
and deadline. A busy shell refuses another command rather than queuing it. Old grants,
expired commands and replayed request IDs do not execute. The service starts reading
at the end of the inbox; historical chat is never interpreted as consent or commands.

The default execution deadline is 60 seconds, with a maximum of 300 seconds.
Commands are limited to 32 KiB and returned output to 1 MiB. Client and owner audits
are append-only JSONL files next to the tunnel inbox: `term-client-audit.jsonl` and
`term-owner-audit.jsonl`. The owner audit contains command text with known values
redacted; the client records command hashes, request IDs and outcomes. Transport
mailboxes retain the actual request envelopes. Never put credentials directly in
commands; use an existing remote environment variable when appropriate.

The implementation reads inherited environment values whose names indicate a
secret, without reading credential files. It rejects known secret literals in
commands and redacts known values from output, including values split across pipe
chunks. This cannot guarantee that unknown, transformed or newly created secrets
will not appear. An unrestricted command runs with the owner's OS-user permissions
and can access that account's files and environment; this feature provides no extra
privileges and no sandbox for commands.

Process groups on POSIX and `taskkill /T` on Windows cover ordinary owned descendants.
Commands that deliberately daemonize or escape that tree are outside this cleanup
guarantee. Failed termination is reported as a failure, not successful cleanup.
Stronger containment requires operating-system facilities such as Windows Job Objects.
Likewise, a TTY cannot cryptographically distinguish a human from another process
running as the same OS account; the owner-command requirement must also be respected
by agents operating that account.

The owner sidecar reads the existing inbox with its own offset and appends to the
existing outbox, so enabling the channel does not require restarting the chat daemon.
Current `recv`, `recv --all` and `--out` omit terminal frames. A custom raw-inbox watcher
must use `row.channel !== 'term'` before treating a row as chat. New daemons also keep
fragment assemblers separate for each authenticated peer and channel.
