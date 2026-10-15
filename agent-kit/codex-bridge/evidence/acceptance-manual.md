# Manual acceptance (2026-10-15, macOS, CC 2.1.281, codex-cli 0.162.1, hub v0.2.0)
Throwaway Codex TUI tmux `peertest-codex3`, cwd /tmp/peertest, `-a never -s danger-full-access`.

| Leg | Result | Numbers |
|---|---|---|
| Fresh Codex TUI → bridged CC peer row | PASS | stub row written 0.28 s after hub saw thread (thread/started broadcast); TUI→daemon thread ~1-2 s after launch |
| Codex row in native **ListAgents** (CC 2.1.281) | PASS after fix | was hidden: procStart in local TZ; CC compares `LC_ALL=C TZ=UTC ps -o lstart=`. Fixed in ccpeer.proc_start. 7 codex rows listed 22:32 |
| Claude `SendMessage` → idle Codex wakes | PASS | inject RPC accepted 4 ms; hub inbound event ≤1.6 s after a pre-send stamp (includes my own tool-call gap) |
| Codex `pb send` → Claude native `<cross-session-message from-name="codex-peertest-42" from-mode="bypass">` | PASS (no hold) | pb→hub→stub→socket 5 ms (ping 3) |
| Round trip, ping 3 | PASS | stamp 22:35:00.99 → Codex outbound 22:35:05.63 (4.6 s total; Codex model turn ≈3 s; transport < 20 ms) |
| Busy steer (raw, 22:17) | PASS | same turn id returned; model folded text in ("DONE ZEBRA") |
| Kill switch `pb off` / `pb on` | PASS | 5 → 0 → 5 Codex peers within 2.5 s; cxsend refuses while off |
| Opt-in policy | PASS | optin+nothing exposed → 0 peers, cxsend "NOT exposed"; `pb expose --cwd /tmp/peertest` → only that thread |
| Ping 1 failure (honest) | FAIL→fixed | Codex login shell PATH lacked pb → `command not found`; fixed by ~/.local/bin/pb symlink (installer does this) |

Protocol corrections applied after lane B (research/lane-B-cc-protocol.md):
- success = silence (CC renders `delivered` as "released after hold"); refusals go as `expired`+`status_detail:refused`.
- every outbound frame leaves from the stub pid (CC pins receipts/idle notices to the connecting pid).
- body escapes `</cross-session-message`; idle notice `finished_at` = epoch ms.

Live confirmation of lane B's receipt finding (22:38): this Claude session received two
"[Cross-session delivery notice] … approved and released to that session (recipient: uds:/tmp/cc-socks/44894.sock)"
— 44894 = the pre-fix stub whose hub sent `delivered` on success for pings 1-2. CC renders `delivered` as a
released hold, so success must be silent (fixed in hub v0.2.0; ping 3 produced no notice).
