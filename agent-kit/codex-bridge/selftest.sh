#!/bin/sh
# peerbridge acceptance gate wrapper: runs selftest.py with the repo's python3; exit code = gate result.
cd "$(dirname "$0")" && exec python3 ./selftest.py "$@"
