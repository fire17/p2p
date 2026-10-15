#!/usr/bin/env bash
# shai-ear.sh - WSL wrapper: runs the Windows ear (../windows/shai-ear.ps1) through
# powershell.exe interop, so it uses the Windows p2p.cmd installed by the join line.
# Arm it with your Monitor tool (persistent). Output = [SHAI] / [SHAI-EAR] lines,
# CRLF stripped, line-buffered. All arguments pass through, e.g.:
#   ./shai-ear.sh -Wait 60 -Name join-XXXX
# Messages only: nothing received is ever executed.
# Env: SHAI_PS (default powershell.exe; pwsh.exe also works),
#      SHAI_EAR_PS1 (Windows path of shai-ear.ps1 if the kit is not next to this file).
set -u
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ps="${SHAI_PS:-powershell.exe}"
command -v "$ps" >/dev/null 2>&1 || { echo "[SHAI-EAR] ERROR $ps not found - is WSL interop enabled?"; exit 2; }
if [ -n "${SHAI_EAR_PS1:-}" ]; then script="$SHAI_EAR_PS1"
else script="$(wslpath -w "$here/../windows/shai-ear.ps1")" || { echo "[SHAI-EAR] ERROR cannot map kit path for Windows"; exit 2; }
fi
"$ps" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$script" "$@" </dev/null | sed -u 's/\r$//'
exit "${PIPESTATUS[0]}"
