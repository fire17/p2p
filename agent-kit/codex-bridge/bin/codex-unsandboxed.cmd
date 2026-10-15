@echo off
rem peerbridge mode (b) for native Windows: OPT-IN, UNSANDBOXED Codex. Never the default.
rem Runs codex with NO sandbox and NO approval prompts. pb then declares from-mode=bypass.
rem Do not run from an elevated (Administrator) terminal: Codex then skips the shared daemon.
rem Never add -c/--enable/--disable/--search: any of those makes the TUI skip the shared daemon.
echo codex-unsandboxed: starting Codex WITHOUT sandbox and WITHOUT approvals (peerbridge mode b) 1>&2
codex -a never -s danger-full-access %*
