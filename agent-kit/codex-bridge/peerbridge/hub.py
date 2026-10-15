"""peerbridge hub: makes every live Codex thread a native Claude Code peer.

One per machine (flock). Holds one JSON-RPC connection to Codex's shared app-server daemon, keeps one
stub process (a CC peer endpoint) per loaded user thread, turns inbound CC frames into `turn/start`
(wakes an idle thread, steers a busy one), mirrors thread status into the CC registry, and answers
receipts / idle notices honestly. Control socket ~/.peerbridge/hub.sock serves the `pb` CLI.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ccpeer  # noqa: E402
import policy  # noqa: E402
from cxrpc import CodexRPC, RPCError  # noqa: E402

VERSION = "0.2.0"
HOME = ccpeer.STATE_DIR
THREADS_DIR = os.path.join(HOME, "threads")
LOG = os.path.join(HOME, "hub.log")
EVENTS = os.path.join(HOME, "events.jsonl")
RECEIPTS = os.path.join(HOME, "receipts.jsonl")
NAMES = os.path.join(HOME, "names.json")
CTL = os.path.join(HOME, "hub.sock")
STUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stub.py")
INCLUDE_SUBAGENTS = os.environ.get("PEERBRIDGE_INCLUDE_SUBAGENTS") == "1"
IDLE_SETTLE = 0.75
LATE_NOTICE_AFTER = 1.5  # a non-delivered receipt arriving after `pb send` returned is injected as a notice

os.makedirs(THREADS_DIR, exist_ok=True)


def log(msg: str) -> None:
    with open(LOG, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")


def jappend(path: str, obj: dict) -> None:
    obj = {"t": round(time.time(), 3), **obj}
    with open(path, "a") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def atomic_json(path: str, obj) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def map_status(st: dict | None) -> str | None:
    t = (st or {}).get("type")
    if t == "idle" or t == "systemError":
        return "idle"
    if t == "active":
        return "waiting" if st.get("activeFlags") else "busy"
    return None  # notLoaded / unknown -> not a live peer


def approval_of(rollout: str | None) -> str | None:
    """Latest turn_context approval_policy from the rollout tail (the honest source for from-mode)."""
    if not rollout or not os.path.exists(rollout):
        return None
    try:
        with open(rollout, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 512 * 1024))
            lines = f.read().decode("utf-8", "replace").splitlines()
        for line in reversed(lines):
            if '"turn_context"' in line:
                p = json.loads(line).get("payload") or {}
                ap = p.get("approval_policy")
                return ap if isinstance(ap, str) else json.dumps(ap)
    except Exception:
        return None
    return None


class Thread_:
    def __init__(self, tid: str, info: dict):
        self.tid = tid
        self.info = info
        self.status = map_status(info.get("status")) or "idle"
        self.proc: subprocess.Popen | None = None
        self.address: str | None = None
        self.ref: str | None = None
        self.name: str = ""
        self.idle_subs: list[tuple[str, str]] = []
        self.idle_timer: threading.Timer | None = None


class Hub:
    def __init__(self):
        self.q: queue.Queue = queue.Queue()
        self.threads: dict[str, Thread_] = {}
        self.rpc: CodexRPC | None = None
        self.codex_version = "?"
        self.names: dict = {}
        self.pending_ctl: dict[str, tuple] = {}  # req id -> (reply box, result) waiting for the stub's write
        self.pending_sent: dict[str, dict] = {}  # msg_id -> {tid, to, t} for messages Codex sent via pb
        self.skip: set[str] = set()  # ephemeral / subagent threads: never bridged, never re-read
        self.policy = policy.load()
        self.policy_mtime = policy.mtime()
        self.stub_err = open(os.path.join(HOME, "stub-stderr.log"), "a")
        self.crashes: dict[str, list[float]] = {}  # tid -> recent unexpected stub exits (respawn backoff)
        try:
            self.names = json.load(open(NAMES))
        except Exception:
            pass

    # ---- codex connection ---------------------------------------------------------------
    def connect_loop(self) -> None:
        delay = 1.0
        while True:
            try:
                rpc = CodexRPC(on_notify=lambda m, p: self.q.put(("notify", m, p)), client_name="peerbridge-hub", version=VERSION)
                self.rpc = rpc
                ua = (rpc.init or {}).get("userAgent", "")
                self.codex_version = ua.split("/")[1].split(" ")[0] if "/" in ua else "?"
                log(f"connected to codex app-server ({rpc.mode}) {ua}")
                self.q.put(("resync",))
                delay = 1.0
                rpc.closed.wait()
                log("codex app-server connection closed")
                self.rpc = None
            except Exception as e:
                self.rpc = None
                if delay >= 8:
                    log(f"codex app-server not reachable: {e}")
            time.sleep(delay)
            delay = min(delay * 2, 15.0)

    def call(self, method: str, params: dict, timeout: float = 15.0):
        if not self.rpc:
            raise ConnectionError("codex app-server not connected")
        return self.rpc.call(method, params, timeout)

    # ---- thread / stub lifecycle ------------------------------------------------------
    def eligible(self, th: dict) -> bool:
        if th.get("ephemeral"):
            return False
        src = th.get("source")
        if not INCLUDE_SUBAGENTS and (th.get("parentThreadId") or (isinstance(src, dict) and "subAgent" in src)):
            return False
        if src == "exec" or th.get("threadSource") not in (None, "user"):
            return False  # headless `codex exec` runs and non-user (review/compact/memory) workers are not peers
        return True

    def derive_name(self, tid: str, cwd: str) -> str:
        if tid in self.names:
            return self.names[tid]
        base = os.path.basename((cwd or "").rstrip("/")) or "codex"
        name = f"codex-{base}-{hashlib.sha256(tid.encode()).hexdigest()[:2]}"
        taken = {r.get("name") for r in ccpeer.records() if r.get("codexThreadId") != tid}
        taken |= {t.name for t in self.threads.values() if t.tid != tid}
        n, i = name, 2
        while n in taken:
            n, i = f"{name}-{i}", i + 1
        return n

    def ensure(self, tid: str, info: dict | None = None) -> None:
        if tid in self.threads and self.threads[tid].proc and self.threads[tid].proc.poll() is None:
            if info and map_status(info.get("status")):
                self.set_status(self.threads[tid], map_status(info["status"]))
            return
        if tid in self.skip:
            return
        if info is None:
            try:
                info = self.call("thread/read", {"threadId": tid})["thread"]
            except Exception as e:
                log(f"thread/read {tid} failed: {e}")
                return
        if not self.eligible(info):
            self.skip.add(tid)
            return
        cwd0 = info.get("cwd") or ((info.get("environments") or [{}])[0] or {}).get("cwd") or ""
        if not policy.allowed(tid, cwd0, self.policy):
            return
        if not map_status(info.get("status")):
            return
        t = Thread_(tid, info)
        cwd = info.get("cwd") or ((info.get("environments") or [{}])[0] or {}).get("cwd") or ""
        t.name = self.derive_name(tid, cwd)
        cfg = {"threadId": tid, "cwd": cwd, "name": t.name, "nameSource": "user" if tid in self.names else "derived",
               "status": t.status, "version": VERSION, "codexVersion": self.codex_version,
               "startedAt": int((info.get("createdAt") or time.time()) * 1000)}
        env = dict(os.environ, PEERBRIDGE_STUB=json.dumps(cfg), PYTHONIOENCODING="utf-8")
        t.proc = subprocess.Popen([sys.executable, STUB], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=self.stub_err, env=env, text=True, encoding="utf-8", bufsize=1)
        self.threads[tid] = t
        threading.Thread(target=self.stub_reader, args=(t,), daemon=True).start()
        log(f"stub spawned for {tid} name={t.name} pid={t.proc.pid}")

    def stub_reader(self, t: Thread_) -> None:
        proc = t.proc
        for line in proc.stdout:
            try:
                self.q.put(("stub", t.tid, json.loads(line)))
            except Exception:
                pass
        self.q.put(("stub_exit", t.tid, proc.pid))

    def stub_cmd(self, t: Thread_, obj: dict) -> None:
        try:
            if t.proc and t.proc.poll() is None:
                t.proc.stdin.write(json.dumps(obj) + "\n")
                t.proc.stdin.flush()
        except Exception:
            pass

    def reap(self, tid: str, why: str) -> None:
        t = self.threads.pop(tid, None)
        if not t:
            return
        self.flush_idle(t, "exited")
        self.stub_cmd(t, {"cmd": "exit"})
        try:
            t.proc.wait(timeout=3)
        except Exception:
            t.proc.kill()
        try:
            os.unlink(os.path.join(THREADS_DIR, f"{tid}.json"))
        except OSError:
            pass
        log(f"stub reaped for {tid} ({why})")

    def write_state(self, t: Thread_) -> None:
        if not t.address:
            return
        atomic_json(os.path.join(THREADS_DIR, f"{t.tid}.json"), {
            "threadId": t.tid, "name": t.name, "address": t.address, "ref": t.ref, "stubPid": t.proc.pid,
            "status": t.status, "cwd": t.info.get("cwd"), "rollout": t.info.get("path"), "hubPid": os.getpid()})

    def set_status(self, t: Thread_, st: str) -> None:
        if st == t.status:
            return
        t.status = st
        self.stub_cmd(t, {"cmd": "status", "status": st})
        self.write_state(t)
        if st == "idle":
            self.schedule_idle(t)
        elif t.idle_timer:
            t.idle_timer.cancel()
            t.idle_timer = None

    # ---- idle notices ---------------------------------------------------------------
    def schedule_idle(self, t: Thread_) -> None:
        if not t.idle_subs or t.idle_timer:
            return
        t.idle_timer = threading.Timer(IDLE_SETTLE, lambda: self.q.put(("idle_fire", t.tid)))
        t.idle_timer.daemon = True
        t.idle_timer.start()

    def flush_idle(self, t: Thread_, state: str) -> None:
        if t.idle_timer:
            t.idle_timer.cancel()
            t.idle_timer = None
        subs, t.idle_subs = t.idle_subs, []
        for reply_to, orig in subs:
            frame = ccpeer.control("peer_idle_notice", t.address or "", orig_msg_id=orig, state=state,
                                   finished_at=int(time.time() * 1000), from_mode=self.from_mode(t))
            self.via_stub(t, reply_to, [frame])
            jappend(EVENTS, {"ev": "idle_notice_sent", "thread": t.tid, "to": reply_to, "state": state})

    # ---- inbound from CC peers -----------------------------------------------------------
    def via_stub(self, t: Thread_, to_address: str, frames: list, req: str | None = None) -> bool:
        """Write frames to a peer socket FROM the stub's process (CC checks the connecting pid)."""
        rec = next((r for r in ccpeer.records() if r["address"] == to_address), None)
        path = rec["messagingSocketPath"] if rec else to_address[4:] if to_address.startswith("uds:") else to_address
        token = ccpeer.read_token(rec) if rec else None
        self.stub_cmd(t, {"cmd": "send", "req": req, "path": path, "frames": frames, "token": token})
        return True

    def receipt(self, t: Thread_, to: str, orig: str, status: str, reason: str) -> None:
        """CC convention: an accepted message gets NO receipt (CC renders `delivered` as 'released after hold').
        Only failures are reported, as CC itself does: refused travels as status expired + status_detail refused."""
        jappend(EVENTS, {"ev": "receipt", "thread": t.tid, "to": to, "msgId": orig, "status": status, "reason": reason})
        if status == "accepted":
            return
        if status == "refused":
            extra = {"status": "expired", "status_detail": "refused"}
        elif status == "dropped":
            extra = {"status": "dropped", "drop_reason": "queue-full", "dropped_msg_ids": [orig]}
        else:
            extra = {"status": status}
        frame = ccpeer.control("peer_message_status", t.address or "", reason=reason, orig_msg_id=orig, **extra)
        self.via_stub(t, to, [frame])

    def inject(self, t: Thread_, text: str, msg_id: str | None = None) -> tuple[bool, str]:
        if not policy.allowed(t.tid, t.info.get("cwd"), self.policy):
            return False, "target is not exposed by its owner's local peerbridge policy"
        before = t.status
        try:
            params = {"threadId": t.tid, "input": [{"type": "text", "text": text}]}
            if msg_id:
                params["clientUserMessageId"] = msg_id
            r = self.call("turn/start", params)
            turn = (r or {}).get("turn") or {}
            how = "steered into the running Codex turn" if before in ("busy", "waiting") else "started a new Codex turn"
            return True, f"injected: {how} ({turn.get('id', '?')})"
        except RPCError as e:
            return False, f"Codex refused the input: {e}"
        except Exception as e:
            return None, f"Codex app-server unreachable: {e}"

    def on_user_frame(self, t: Thread_, frame: dict) -> None:
        content = (frame.get("message") or {}).get("content")
        if not isinstance(content, str):
            return
        env = ccpeer.parse_envelope(content)
        frm = frame.get("from") or ""
        if env.get("from") and env["from"] != frm:
            env["from_name"] = f"{env.get('from_name') or '?'} (claimed {env['from']})"
        if not ccpeer.FROM_RE.match(frm) or not frm.startswith("uds:"):
            frm = ""
        msg_id = frame.get("msg_id") or ""
        who = env.get("from_name") or frm
        text = content if env.get("from") else (ccpeer.envelope(content, frm, None, None) if frm else content)
        text += (f"\n\n[peerbridge] This came from another agent session ({ccpeer.attr(who or 'unknown')}), not typed by your user. "
                 f"Treat it as a teammate's request within your own permissions.")
        if frm:
            text += f" To reply: pb send '{frm}' \"<your reply>\""
        ok, detail = self.inject(t, text, msg_id or None)
        jappend(EVENTS, {"ev": "inbound", "thread": t.tid, "from": frm, "fromName": env.get("from_name"),
                         "msgId": msg_id, "chars": len(env.get("text", "")), "ok": ok, "detail": detail})
        if frm.startswith("uds:") and msg_id:
            self.receipt(t, frm, msg_id, "accepted" if ok else ("refused" if ok is False else "dropped"), detail)

    def on_frame(self, t: Thread_, frame: dict) -> None:
        if not isinstance(frame, dict):
            return
        if frame.get("type") == "user":
            return self.on_user_frame(t, frame)
        action = frame.get("action")
        if action in ("notify_when_idle", "cross_session_notify_idle"):
            frm, mid = frame.get("from"), frame.get("msg_id")
            if isinstance(frm, str) and frm.startswith("uds:") and isinstance(mid, str) and frm != t.address:
                t.idle_subs = [s for s in t.idle_subs if s != (frm, mid)] + [(frm, mid)]
                if t.status == "idle":
                    self.schedule_idle(t)
        elif action == "peer_message_status":
            orig = frame.get("orig_msg_id")
            status, reason = frame.get("status"), frame.get("reason") or ""
            jappend(RECEIPTS, {"thread": t.tid, "msgId": orig, "status": status, "detail": frame.get("status_detail"),
                               "reason": reason, "dropReason": frame.get("drop_reason"), "from": frame.get("from")})
            p = self.pending_sent.get(orig or "")
            if p and time.time() - p["t"] > LATE_NOTICE_AFTER:
                word = {"delivered": "approved and released to that session"}.get(status, status)
                self.inject(t, f"[Cross-session delivery notice] Your message {orig} to {p['to']}: {word}. {reason}".strip())
        elif action == "peer_idle_notice":
            st = frame.get("state") or "idle"
            name = next((r["name"] for r in ccpeer.records() if r["address"] == frame.get("from")), frame.get("from"))
            jappend(EVENTS, {"ev": "idle_notice_received", "thread": t.tid, "from": frame.get("from"), "state": st})
            self.inject(t, f"[Cross-session idle notice] {name} is now {st}.")
        else:
            jappend(EVENTS, {"ev": "frame_ignored", "thread": t.tid, "action": action, "type": frame.get("type")})

    def from_mode(self, t: Thread_) -> str:
        return "bypass" if approval_of(t.info.get("path")) == "never" else "prompting"

    def ctl_send(self, req: dict, box: queue.Queue) -> None:
        t = self.threads.get(req.get("threadId", ""))
        if not t or not t.address:
            return box.put({"ok": False, "error": "this Codex thread is not bridged (not exposed, or hub just started)"})
        if self.policy.get("off"):
            return box.put({"ok": False, "error": "peerbridge is OFF on this machine"})
        matches = [r for r in ccpeer.resolve(req.get("to", "")) if r["address"] != t.address]
        if len(matches) != 1:
            c = ", ".join(f"{r['name']} [{r['ref'][:6]}]" for r in matches) or "none"
            return box.put({"ok": False, "error": f"expected exactly one live peer for '{req.get('to')}', found {len(matches)}: {c}"})
        target = matches[0]
        mode = self.from_mode(t)
        frames, msg_id = [], None
        text = req.get("text") or ""
        if text.strip():
            f = ccpeer.user_frame(t.address, ccpeer.envelope(text, t.address, t.name, mode))
            frames.append(f)
            msg_id = f["msg_id"]
        if req.get("notifyIdle"):
            sub = ccpeer.control("notify_when_idle", t.address, from_mode=mode)
            frames.append(sub)
            msg_id = msg_id or sub["msg_id"]
        if not frames:
            return box.put({"ok": False, "error": "empty message"})
        rid = msg_id
        self.pending_ctl[rid] = (box, {"ok": True, "msgId": msg_id, "to": target["name"], "ref": target["ref"][:6],
                                       "address": target["address"], "toHarness": target.get("harness") or target.get("entrypoint"),
                                       "as": t.name, "fromMode": mode})
        now = time.time()
        self.pending_sent = {k: v for k, v in self.pending_sent.items() if now - v["t"] < 3600}
        self.pending_sent[msg_id] = {"tid": t.tid, "to": target["name"], "t": now}
        jappend(EVENTS, {"ev": "outbound", "thread": t.tid, "to": target["address"], "toName": target["name"], "msgId": msg_id, "chars": len(text)})
        self.via_stub(t, target["address"], frames, rid)

    # ---- control socket (pb) -------------------------------------------------------------
    def ctl_serve(self) -> None:
        try:
            os.unlink(CTL)
        except OSError:
            pass
        old = os.umask(0o077)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(CTL)
        os.umask(old)
        srv.listen(16)
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=self.ctl_conn, args=(conn,), daemon=True).start()

    def ctl_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            data = b""
            while b"\n" not in data:
                c = conn.recv(65536)
                if not c:
                    break
                data += c
            req = json.loads(data.split(b"\n")[0] or b"{}")
            box: queue.Queue = queue.Queue(1)
            self.q.put(("ctl", req, box))
            conn.sendall((json.dumps(box.get(timeout=20)) + "\n").encode())
        except Exception as e:
            try:
                conn.sendall((json.dumps({"ok": False, "error": str(e)}) + "\n").encode())
            except Exception:
                pass
        finally:
            conn.close()

    def on_ctl(self, req: dict) -> dict:
        cmd = req.get("cmd")
        if cmd == "ping":
            return {"ok": True, "pid": os.getpid(), "version": VERSION, "codex": bool(self.rpc), "codexVersion": self.codex_version,
                    "policy": {k: self.policy.get(k) for k in ("expose", "off")},
                    "threads": [{"threadId": t.tid, "name": t.name, "status": t.status, "address": t.address} for t in self.threads.values()]}
        t = self.threads.get(req.get("threadId", ""))
        if cmd == "rename":
            if not t:
                return {"ok": False, "error": "thread not bridged"}
            name = str(req.get("name", "")).strip()
            if not name or any(r.get("name") == name and r.get("codexThreadId") != t.tid for r in ccpeer.records()):
                return {"ok": False, "error": f"name '{name}' empty or taken"}
            t.name = name
            self.names[t.tid] = name
            atomic_json(NAMES, self.names)
            self.stub_cmd(t, {"cmd": "name", "name": name})
            self.write_state(t)
            return {"ok": True, "name": name}
        if cmd == "sent":
            self.pending_sent[req.get("msgId", "")] = {"tid": req.get("threadId"), "to": req.get("to"), "t": time.time()}
            return {"ok": True}
        if cmd == "resync":
            self.resync()
            return {"ok": True}
        return {"ok": False, "error": f"unknown cmd {cmd}"}

    # ---- main loop ---------------------------------------------------------------------
    def resync(self) -> None:
        try:
            ids = self.call("thread/loaded/list", {}).get("data", [])
        except Exception as e:
            log(f"resync failed: {e}")
            return
        for tid in ids:
            if tid in self.threads:
                try:
                    info = self.call("thread/read", {"threadId": tid})["thread"]
                    st = map_status(info.get("status"))
                    if st:
                        self.set_status(self.threads[tid], st)
                except Exception as e:
                    log(f"resync status {tid} failed: {e}")
            else:
                self.ensure(tid)
        for tid in list(self.threads):
            if tid not in ids:
                self.reap(tid, "not loaded at resync")

    def on_notify(self, m: str, p: dict) -> None:
        tid = p.get("threadId") or (p.get("thread") or {}).get("id")
        if m == "thread/started" and tid:
            self.ensure(tid, p.get("thread"))
        elif m == "thread/status/changed" and tid:
            st = map_status(p.get("status"))
            if st is None:
                self.reap(tid, f"status {p.get('status')}")
            elif tid in self.threads:
                self.set_status(self.threads[tid], st)
            else:
                self.ensure(tid)
        elif m == "thread/closed" and tid:
            self.reap(tid, "thread/closed")
        elif m in ("thread/archived", "thread/deleted") and tid:
            self.reap(tid, m)

    def run(self) -> None:
        threading.Thread(target=self.connect_loop, daemon=True).start()
        threading.Thread(target=self.ctl_serve, daemon=True).start()
        threading.Thread(target=self.policy_watch, daemon=True).start()
        log(f"hub {VERSION} up pid={os.getpid()} socks={ccpeer.socks_dir()}")
        while True:
            ev = self.q.get()
            try:
                kind = ev[0]
                if kind == "notify":
                    self.on_notify(ev[1], ev[2])
                elif kind == "resync":
                    self.resync()
                elif kind == "respawn":
                    self.ensure(ev[1])
                elif kind == "policy":
                    self.apply_policy()
                elif kind == "stub":
                    t = self.threads.get(ev[1])
                    msg = ev[2]
                    if not t:
                        continue
                    if msg.get("ev") == "ready":
                        t.address, t.ref = msg["address"], msg["ref"]
                        self.write_state(t)
                        jappend(EVENTS, {"ev": "peer_up", "thread": t.tid, "name": t.name, "address": t.address})
                    elif msg.get("ev") == "frame":
                        self.on_frame(t, msg["frame"])
                    elif msg.get("ev") == "sent":
                        p = self.pending_ctl.pop(msg.get("req") or "", None)
                        if p:
                            p[0].put(p[1] if msg.get("ok") else {"ok": False, "error": msg.get("error")})
                        elif not msg.get("ok"):
                            log(f"stub {t.name} send failed: {msg.get('error')}")
                    elif msg.get("ev") == "auth_fail":
                        jappend(EVENTS, {"ev": "auth_fail", "thread": t.tid})
                elif kind == "stub_exit":
                    t = self.threads.get(ev[1])
                    if t and t.proc and t.proc.pid == ev[2]:
                        self.threads.pop(ev[1], None)
                        now = time.time()
                        hist = [x for x in self.crashes.get(ev[1], []) if now - x < 300] + [now]
                        self.crashes[ev[1]] = hist
                        if len(hist) > 5:
                            log(f"stub for {ev[1]} crashed {len(hist)}x in 5 min; giving up (see stub-stderr.log)")
                        else:
                            delay = min(2 ** len(hist), 30)
                            log(f"stub for {ev[1]} exited unexpectedly; respawning in {delay}s")
                            threading.Timer(delay, lambda tid=ev[1]: self.q.put(("respawn", tid))).start()
                elif kind == "idle_fire":
                    t = self.threads.get(ev[1])
                    if t:
                        t.idle_timer = None
                        if t.status == "idle":
                            self.flush_idle(t, "idle")
                elif kind == "ctl" and ev[1].get("cmd") == "send":
                    self.ctl_send(ev[1], ev[2])
                elif kind == "ctl":
                    try:
                        ev[2].put(self.on_ctl(ev[1]))
                    except Exception as e:
                        ev[2].put({"ok": False, "error": str(e)})
            except Exception:
                log("loop error: " + traceback.format_exc())

    def policy_watch(self) -> None:
        while True:
            time.sleep(1.0)
            m = policy.mtime()
            if m != self.policy_mtime:
                self.policy_mtime = m
                self.q.put(("policy",))

    def apply_policy(self) -> None:
        self.policy = policy.load()
        log(f"policy reloaded: expose={self.policy.get('expose')} off={self.policy.get('off')} "
            f"threads={len(self.policy.get('threads') or [])} cwds={len(self.policy.get('cwds') or [])}")
        for tid, t in list(self.threads.items()):
            if not policy.allowed(tid, t.info.get("cwd"), self.policy):
                self.reap(tid, "policy")
        if not self.policy.get("off"):
            self.resync()

    def shutdown(self, *_):
        for tid in list(self.threads):
            self.reap(tid, "hub shutdown")
        try:
            os.unlink(CTL)
        except OSError:
            pass
        os._exit(0)


def main() -> None:
    os.makedirs(HOME, exist_ok=True)
    lock = open(os.path.join(HOME, "hub.lock"), "a+")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("peerbridge hub already running", file=sys.stderr)
        sys.exit(0)
    lock.seek(0)
    lock.truncate()
    lock.write(str(os.getpid()))
    lock.flush()
    hub = Hub()
    import signal
    signal.signal(signal.SIGTERM, hub.shutdown)
    signal.signal(signal.SIGINT, hub.shutdown)
    hub.run()


if __name__ == "__main__":
    main()
