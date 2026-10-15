#!/usr/bin/env bash
# shai-send.sh - WSL wrapper for ../windows/shai-send.ps1 (Windows p2p.cmd via interop).
# The text always travels as a UTF-8 file, never as a command-line argument, so quotes,
# &, |, % and newlines survive the WSL -> powershell.exe -> cmd.exe hops unchanged.
# Usage:
#   ./shai-send.sh "ASK which node version should I use?"
#   ./shai-send.sh -f error.txt [--redact]
#   some-command 2>&1 | tail -20 | ./shai-send.sh --redact -        # stdin (must start with a tag)
#   ./shai-send.sh --reply-to 0123456789abcdef "ACK done"
# Options: -f|--file PATH  -r|--redact  --reply-to ID  --name SESSION  --wait N  --dry-run
# Exit codes mirror shai-send.ps1 (0 delivered, 2 refused/usage, 3 failed, 4 no ack, 5 no session).
set -u
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ps="${SHAI_PS:-powershell.exe}"
command -v "$ps" >/dev/null 2>&1 || { echo "[SHAI-SEND] ERROR $ps not found - is WSL interop enabled?" >&2; exit 2; }
if [ -n "${SHAI_SEND_PS1:-}" ]; then script="$SHAI_SEND_PS1"
else script="$(wslpath -w "$here/../windows/shai-send.ps1")" || { echo "[SHAI-SEND] cannot map kit path" >&2; exit 2; }
fi
file=""; text=""; extra=()
while [ $# -gt 0 ]; do
  case "$1" in
    -f|--file) file="${2:?--file needs a path}"; shift 2 ;;
    -r|--redact) extra+=(-Redact); shift ;;
    --dry-run) extra+=(-DryRun); shift ;;
    --reply-to) extra+=(-ReplyTo "${2:?}"); shift 2 ;;
    --name) extra+=(-Name "${2:?}"); shift 2 ;;
    --wait) extra+=(-Wait "${2:?}"); shift 2 ;;
    -) text="$(cat)"; shift ;;
    --) shift; text="$*"; break ;;
    -*) echo "[SHAI-SEND] unknown option: $1" >&2; exit 2 ;;
    *) text="$*"; break ;;
  esac
done
tmp=""
if [ -z "$file" ]; then
  [ -n "$text" ] || { echo "usage: shai-send.sh \"<TAG> text\" | -f FILE | - (stdin)   TAG = HELLO ASK ERROR LOG DONE FIX ACK NOTE FILE RETEST" >&2; exit 2; }
  tmp="$(mktemp "${TMPDIR:-/tmp}/shai-send.XXXXXX")"; trap 'rm -f "$tmp"' EXIT
  printf '%s' "$text" > "$tmp"; file="$tmp"
fi
[ -f "$file" ] || { echo "[SHAI-SEND] file not found: $file" >&2; exit 2; }
winfile="$(wslpath -w "$(readlink -f "$file")")" || exit 2
"$ps" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$script" -File "$winfile" "${extra[@]+"${extra[@]}"}" </dev/null | sed -u 's/\r$//'
exit "${PIPESTATUS[0]}"
