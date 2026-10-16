# sentinel: passive incident ledger

`ledger.py` follows our own mesh logs and writes one typed line per NEW problem to
`~/.agent-sentinel/incidents.jsonl`. It is read-only: it changes, stops and runs nothing, reads no pane
screens and no project files, and spends no tokens. Repeats of a known problem only bump its counter.

    python3 ledger.py selftest
    python3 ledger.py replay --logs <log dir> --out /tmp/ledger-replay     # what past logs would have raised
    python3 ledger.py watch  --logs <log dir> [--deadline FILE=SEC]       # follow live
    python3 ledger.py show --open

Log dir on Windows: `%USERPROFILE%\.agent-mesh\logs` (keeper + hub link logs). Run it on the side that writes
the logs (Windows python for Windows logs): polling /mnt/c from WSL keeps the VM busy.
Stop: kill its pid (it holds no lock and leaves nothing half-written). Undo: delete `~/.agent-sentinel`.

This is step 1 of the problem-finder design (incident ledger). Detectors, escalation and gates come later.
