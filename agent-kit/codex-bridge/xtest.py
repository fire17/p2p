#!/usr/bin/env python3
"""xtest.py - headless cross-platform acceptance gate for peerbridge (no Codex TUI needed).

Runs on macOS/Linux (Unix sockets) and native Windows (named pipes). Steps:
  1. hub up (pb ensure), Codex daemon reachable; exposes the test cwd temporarily if policy is optin
  2. creates a Codex thread on the daemon (thread/start, read-only sandbox, no approvals)
  3. waits for the hub to publish its Claude Code peer row (record + key + live inbox)
  4. acts as a Claude Code SENDER: auth + user frame into the Codex peer inbox -> Codex must reply (model turn)
  5. a frame with a WRONG token must be rejected (auth enforced)
  6. acts as a Claude Code RECEIVER: own inbox + record + key; hub sends from the Codex peer -> frame must arrive
     authenticated with our token and carry the Codex peer as `from`
  7. cleanup: archive the thread, remove our fake peer, restore policy
Prints PASS/FAIL per step; exit 0 only if all pass. Uses one tiny model turn. ASCII only.
Usage: python xtest.py [--cwd DIR]
"""
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.realpath(__file__))
for cand in (os.path.join(HERE, "peerbridge"), os.path.join(HERE, "lib", "peerbridge"),
             os.path.join(os.path.expanduser("~"), ".peerbridge", "lib", "peerbridge")):
    if os.path.exists(os.path.join(cand, "ccpeer.py")):
        sys.path.insert(0, cand)
        PKG = cand
        break
import ccpeer  # noqa: E402
import policy  # noqa: E402
from cxrpc import CodexRPC  # noqa: E402

PB = next((p for p in (os.path.join(HERE, "bin", "pb"), os.path.join(os.path.dirname(PKG), "..", "bin", "pb")) if os.path.exists(p)), None)
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)
    return ok


def pb(*args, timeout=30):
    return subprocess.run([sys.executable, PB, *args], capture_output=True, text=True, timeout=timeout)


def wait_until(fn, timeout, step=0.2):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return None


class FakeClaude:
    """A minimal Claude Code peer endpoint (receiver) on this platform's transport."""

    def __init__(self):
        self.pid = os.getpid()
        self.token = secrets.token_hex(16)
        self.frames = []
        self.authed_frames = []
        if ccpeer.WINDOWS:
            self.sock = ccpeer.winpipe.new_inbox_name()
        else:
            self.sock = os.path.join(ccpeer.socks_dir(), f"{self.pid}.sock")
        self.rec = os.path.join(ccpeer.SESSIONS_DIR, f"{self.pid}.json")
        self.key = ccpeer.key_path(self.pid, self.sock)
        self.name = f"xtest-claude-{secrets.token_hex(2)}"

    def _stream(self, chunks):
        buf, first, authed = b"", True, False
        for c in chunks:
            buf += c
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                f = json.loads(line)
                if first and f.get("type") == "auth":
                    authed = f.get("token") == self.token
                    first = False
                    continue
                first = False
                self.frames.append(f)
                if authed:
                    self.authed_frames.append(f)

    def start(self):
        if ccpeer.WINDOWS:
            self.srv = ccpeer.winpipe.PipeServer(self.sock, lambda chunks, reply: self._stream(chunks))
            self.srv.start()
        else:
            import socket
            os.makedirs(os.path.dirname(self.sock), mode=0o700, exist_ok=True)
            try:
                os.unlink(self.sock)
            except OSError:
                pass
            self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.srv.bind(self.sock)
            os.chmod(self.sock, 0o600)
            self.srv.listen(8)

            def loop():
                while True:
                    try:
                        c, _ = self.srv.accept()
                    except OSError:
                        return

                    def gen(c=c):
                        with c:
                            while True:
                                d = c.recv(65536)
                                if not d:
                                    return
                                yield d
                    threading.Thread(target=self._stream, args=(gen(),), daemon=True).start()
            threading.Thread(target=loop, daemon=True).start()
        ps = ccpeer.proc_start(self.pid)
        now = int(time.time() * 1000)
        with open(self.key, "w") as f:
            json.dump({"peerToken": self.token, ccpeer.start_field(): ps, "pidDomain": ccpeer.pid_domain()}, f)
        with open(self.rec, "w") as f:
            json.dump({"pid": self.pid, "sessionId": "xtest-" + secrets.token_hex(8), "cwd": os.getcwd(), "startedAt": now,
                       ccpeer.start_field(): ps, "version": "xtest", "peerProtocol": 1, "peerFeatures": ["notify_idle"],
                       "kind": "interactive", "entrypoint": "cli", "pidDomain": ccpeer.pid_domain(),
                       "messagingSocketPath": self.sock, "name": self.name, "nameSource": "user", "nameSince": now,
                       "status": "idle", "updatedAt": now, "statusUpdatedAt": now}, f)

    def stop(self):
        for p in (self.rec, self.key):
            try:
                os.unlink(p)
            except OSError:
                pass
        try:
            self.srv.stop() if ccpeer.WINDOWS else (self.srv.close(), os.unlink(self.sock))
        except Exception:
            pass


def main():
    cwd = os.path.realpath(sys.argv[sys.argv.index("--cwd") + 1]) if "--cwd" in sys.argv else \
        os.path.realpath(os.path.join(tempfile.gettempdir(), "pbxtest"))
    os.makedirs(cwd, exist_ok=True)
    exposed, rpc, tid, fake = False, None, None, None
    try:
        r = pb("ensure")

        def ping_now():
            st = pb("status")
            try:
                return json.loads(st.stdout[st.stdout.index("{"):])
            except Exception:
                return {}
        ping = ping_now()
        if ping.get("ok") and not ping.get("codex"):  # a freshly started hub attaches to the daemon ~1 s later
            ping = wait_until(lambda: (lambda p: p if p.get("codex") else None)(ping_now()), 10, 0.5) or ping_now()
        if not check("hub_up", ping.get("ok"), f"pid={ping.get('pid')} v={ping.get('version')} {r.stderr.strip()[:200]}"):
            return 1
        if not check("hub_connected_to_codex_daemon", ping.get("codex"), "start one CLI codex or `codex app-server daemon start`"):
            return 1
        if policy.load().get("off"):
            check("policy_not_off", False, "kill switch is on (pb on)")
            return 1
        if not policy.allowed("-", cwd):
            exposed = True  # set first: a timeout inside expose must still trigger the hide in finally
            pb("expose", "--cwd", cwd)
        check("policy_allows_test_cwd", policy.allowed("-", cwd), cwd)

        events = []
        rpc = CodexRPC(on_notify=lambda m, p: events.append((time.time(), m, p)), client_name="pb-xtest", version="0.3.0")
        th = rpc.call("thread/start", {"cwd": cwd, "sandbox": "read-only", "approvalPolicy": "never", "threadSource": "user"},
                      timeout=60)["thread"]
        tid = th["id"]
        check("codex_thread_started", tid, tid)

        def state():
            try:
                with open(os.path.join(ccpeer.STATE_DIR, "threads", f"{tid}.json")) as f:
                    return json.load(f)
            except Exception:
                return None
        t0 = time.time()
        stt = wait_until(state, 30)
        if not check("peer_row_published", stt, f"{time.time() - t0:.2f}s" if stt else "hub did not bridge the thread in 30s"):
            return 1
        rec = next((x for x in ccpeer.records() if x.get("codexThreadId") == tid), None)
        check("registry_record_live", rec, stt["address"])
        if not rec:
            return 1
        sf = ccpeer.start_field()
        actual = ccpeer.proc_start(rec["pid"])
        check(f"record_{sf}_matches_process", rec.get(sf) == actual, f"{rec.get(sf)} vs {actual}")
        check("key_file_present", os.path.exists(ccpeer.key_path(rec["pid"], rec["messagingSocketPath"])))
        tok = ccpeer.read_token(rec)
        check("key_token_readable", tok and len(tok) == 32)

        # 4 Claude -> Codex
        nonce = secrets.token_hex(3)
        frm = "uds:" + (ccpeer.winpipe.new_inbox_name() if ccpeer.WINDOWS else "/tmp/cc-socks/1.sock")
        text = f"peerbridge xtest: reply with exactly XTEST-OK-{nonce} and nothing else. Do not run any tools."
        frame = ccpeer.user_frame(frm, ccpeer.envelope(text, frm, "xtest-sender", "bypass"))
        ts = time.time()
        ccpeer.write_frames(rec["messagingSocketPath"], [frame], tok)

        def replied():
            for (t, m, p) in events:
                if m == "item/completed" and p.get("threadId") == tid and f"XTEST-OK-{nonce}" in json.dumps(p.get("item") or {}) \
                        and (p.get("item") or {}).get("type") in ("agentMessage", "AgentMessage"):
                    return t
        started = wait_until(lambda: next((t for (t, m, p) in events if m == "turn/started" and p.get("threadId") == tid), None), 20)
        check("claude_to_codex_injected", started, f"{started - ts:.3f}s to turn start" if started else "no turn started")
        rt = wait_until(replied, 120, 0.5)
        check("codex_replied", rt, f"{rt - ts:.2f}s" if rt else "no reply in 120s")

        # 5 wrong token rejected
        n_before = sum(1 for (t, m, p) in events if m == "turn/started" and p.get("threadId") == tid)
        try:
            ccpeer.write_frames(rec["messagingSocketPath"], [ccpeer.user_frame(frm, ccpeer.envelope("must not arrive", frm, "x", "bypass"))],
                                "0" * 32)
        except Exception:
            pass
        time.sleep(3)
        n_after = sum(1 for (t, m, p) in events if m == "turn/started" and p.get("threadId") == tid)
        check("wrong_token_rejected", n_after == n_before, "no turn started by the bad-token frame")

        # 6 Codex -> Claude (hub sends from the Codex peer's own process into our inbox)
        fake = FakeClaude()
        fake.start()
        n2 = secrets.token_hex(3)
        env = dict(os.environ, PEERBRIDGE_THREAD_ID=tid)
        out = subprocess.run([sys.executable, PB, "send", fake.name, f"XTEST-OUT-{n2}", "--wait", "1"],
                             capture_output=True, text=True, timeout=30, env=env)
        got = wait_until(lambda: next((f for f in fake.authed_frames
                                       if f"XTEST-OUT-{n2}" in json.dumps(f)), None), 15)
        check("codex_to_claude_delivered_authenticated", got, (out.stdout + out.stderr).strip()[:300])
        if got:
            e = ccpeer.parse_envelope(got["message"]["content"])
            check("from_is_codex_peer", e.get("from") == stt["address"], f"from={e.get('from')} mode={e.get('from_mode')}")
        print("\nManual check in a REAL Claude Code session on this machine: run ListAgents and look for "
              f"'{stt['name']}' (this test's Codex peer); it disappears when the test ends.", flush=True)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("unexpected_exception", False, f"{type(e).__name__}: {e}")
    finally:
        if fake:
            fake.stop()
        if rpc and tid:
            try:
                rpc.call("thread/archive", {"threadId": tid}, timeout=15)
            except Exception:
                pass
            rpc.close()
        if exposed:
            pb("hide", "--cwd", cwd)
    fails = [r for r in results if not r[1]]
    print(f"\nOVERALL: {'PASS' if not fails else 'FAIL'} ({len(results) - len(fails)}/{len(results)}) "
          f"platform={sys.platform} transport={'named-pipe' if ccpeer.WINDOWS else 'unix-socket'}")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
