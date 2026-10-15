# Installing peerbridge

```sh
./install.sh            # install + start the hub
./install.sh --selftest # same, then run selftest.sh if present
./uninstall.sh          # reverse everything (add --keep-prefix to keep ~/.peerbridge)
```

Needs `python3` (stdlib only), Codex >= 0.162 with its app-server daemon, macOS or Linux/WSL. Re-running `install.sh` is safe: unchanged pieces are reported as up to date.

## What install.sh does

| Step | Result |
|---|---|
| Code | `peerbridge/*.py` → `$PREFIX/lib/peerbridge/`, `bin/pb` → `$PREFIX/bin/pb`, symlink `~/.local/bin/pb`. `$PREFIX` defaults to `~/.peerbridge`; `~/Documents`, `~/Desktop`, `~/Downloads` are refused (macOS TCC blocks launchd there). |
| Codex hook | Appends one SessionStart entry to `$CODEX_HOME/hooks.json` (default `~/.codex`) that runs `pb ensure` silently. Existing hooks are kept, the old file is backed up as `hooks.json.bak.peerbridge.<ts>`, and duplicates are never added. The entry goes last so existing hooks keep their trust state. |
| Codex skill | `codex-skill/SKILL.md` → `$CODEX_HOME/skills/peerbridge/SKILL.md` (skipped with a warning if missing). |
| Autostart | macOS: `~/Library/LaunchAgents/com.peerbridge.hub.plist` (RunAtLoad, KeepAlive on crash only), loaded with `launchctl bootstrap gui/$UID`. Linux: `~/.config/systemd/user/peerbridge-hub.service` if `systemctl --user` works, otherwise the Codex hook starts the hub. Logs: `$PREFIX/hub.out`. |
| Start | `pb ensure`. |

`$PREFIX/install-manifest` records the paths and labels, and `uninstall.sh` reads it.

## After installing

- Codex asks you once to **trust the new hook**. Approve it in Codex. Until you do, the launchd/systemd agent keeps the hub running.
- Codex hooks need `[features] hooks = true` in `~/.codex/config.toml`. The installer warns if it is missing but never edits that file.
- Make sure `~/.local/bin` is on `PATH` for Codex shells.
- Upgrading: re-run `install.sh`, then `pb stop && pb ensure` so a running hub picks up the new code.

## Env knobs

`PEERBRIDGE_PREFIX`, `CODEX_HOME`, `PEERBRIDGE_NO_LAUNCHD=1` (skip autostart), `PEERBRIDGE_NO_START=1` (do not start the hub), `PEERBRIDGE_LAUNCHD_LABEL` / `PEERBRIDGE_SYSTEMD_UNIT` (rename the unit, e.g. for tests).

Test without touching your real config:

```sh
HOME=/tmp/pbtest/home PEERBRIDGE_NO_LAUNCHD=1 PEERBRIDGE_NO_START=1 ./install.sh
HOME=/tmp/pbtest/home ./uninstall.sh
```

## What uninstall.sh removes

1. Unloads the launchd agent or systemd unit and deletes its file.
2. Stops the hub.
3. Removes only the peerbridge entry from `hooks.json` (backup: `hooks.json.bak.peerbridge-uninstall.<ts>`).
4. Deletes `$CODEX_HOME/skills/peerbridge`.
5. Deletes the `~/.local/bin/pb` symlink, but only if it points into the prefix.
6. Saves the prefix to `${TMPDIR:-/tmp}/peerbridge-backup-<ts>.tgz`, then deletes it.
