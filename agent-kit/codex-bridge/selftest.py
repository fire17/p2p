#!/usr/bin/env python3
"""peerbridge acceptance gate (stdlib only).

Drives ONLY throwaway sessions it spawns itself (tmux peertest-st-*, cwd /tmp/peertest-st), against the
hub that is already running (or `pb ensure`). It plays a fake Claude Code peer ("peertest-st-claude": its
own unix socket + registry row + key file, exactly the CC peer layout) and measures transport vs model time.

  1 hub up + Codex daemon reachable          5 notify_when_idle -> peer_idle_notice
  2 Codex TUI -> CC registry row (latency)   6 Codex -> Codex via pb (and back to us)
  3 CC -> Codex PONG round trip + inject ack  7 teardown: rows vanish (<= 90 s), our row removed
  4 busy steer (2nd message steers)

Usage: selftest.py [--no-c2c] [--no-sandbox-leg]   Exit 0 only when every check PASSes.
Evidence: evidence/selftest-<timestamp>.json
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid

REPO = os.path.dirname(os.path.realpath(__file__))
PB = os.path.join(REPO, "bin", "pb")
sys.path.insert(0, os.path.join(REPO, "peerbridge"))
import ccpeer  # noqa: E402
from cxrpc import CodexRPC  # noqa: E402
import policy  # noqa: E402

CWD = "/tmp/peertest-st"
CWD2 = "/tmp/peertest-st/codex2"
TMUX1, TMUX2 = "peertest-st-codex", "peertest-st-codex2"
FAKE_NAME = "peertest-st-claude"
STATE = ccpeer.STATE_DIR
THREADS = os.path.join(STATE, "threads")
EVENTS = os.path.join(STATE, "events.jsonl")
RECEIPTS = os.path.join(STATE, "receipts.jsonl")
HUBLOG = os.path.join(STATE, "hub.log")
MODEL_TIMEOUT = float(os.environ.get("SELFTEST_MODEL_TIMEOUT", "180"))

T0 = time.time()
checks: list[dict] = []
timings: dict[str, float | None] = {}
notes: list = []


def log(msg: str) -> None:
    print(f"[{time.time() - T0:7.2f}s] {msg}", flush=True)


def check(name: str, ok: bool, detail: str = "") -> bool:
    checks.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
    log(f"{'PASS' if ok else 'FAIL'} {name} {detail}")
    return ok


def wait_until(pred, timeout: float, step: float = 0.05):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return None


def rd(t: float | None) -> float | None:
    return None if t is None else round(t, 3)


# ---- fake Claude Code peer ---------------------------------------------------------------
class FakePeer:
    """A CC-compatible peer endpoint owned by this pid (socket + registry row + 0600 key)."""

    def __init__(self, name: str):
        self.pid = os.getpid()
        self.sock = os.path.join(ccpeer.socks_dir(), f"{self.pid}.sock")
        self.address = f"uds:{self.sock}"
        self.rec_path = os.path.join(ccpeer.SESSIONS_DIR, f"{self.pid}.json")
        self.key_path = ccpeer.key_path(self.pid, self.sock)
        self.token = secrets.token_hex(16)
        self.frames: list[tuple[float, dict]] = []
        self.auth_fail = 0
        self.cv = threading.Condition()
        self.name = name
        self.srv: socket.socket | None = None

    def start(self) -> None:
        os.makedirs(os.path.dirname(self.sock), mode=0o700, exist_ok=True)
        try:
            os.unlink(self.sock)
        except OSError:
            pass
        old = os.umask(0o077)
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.sock)
        os.umask(old)
        self.srv.listen(32)
        threading.Thread(target=self._serve, daemon=True).start()
        ps = ccpeer.proc_start(self.pid)
        dom = "darwin" if sys.platform == "darwin" else sys.platform
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"peerToken": self.token, "procStart": ps, "pidDomain": dom}, f)
        now = int(time.time() * 1000)
        rec = {"pid": self.pid, "sessionId": f"peertest-st-{uuid.uuid4()}", "cwd": CWD, "startedAt": now,
               "procStart": ps, "version": "peerbridge-selftest", "peerProtocol": 1, "peerFeatures": ["notify_idle"],
               "kind": "interactive", "entrypoint": "selftest", "harness": "selftest", "pidDomain": dom,
               "messagingSocketPath": self.sock, "name": self.name, "nameSource": "user", "nameSince": now,
               "status": "idle", "updatedAt": now, "statusUpdatedAt": now}
        tmp = self.rec_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(rec, f)
        os.replace(tmp, self.rec_path)

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._conn, args=(conn,), daemon=True).start()

    def _conn(self, conn: socket.socket) -> None:
        buf, first, authed = b"", True, False
        conn.settimeout(30)
        try:
            while True:
                c = conn.recv(65536)
                if not c:
                    break
                buf += c
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    try:
                        fr = json.loads(raw)
                    except Exception:
                        continue
                    if first:
                        first = False
                        if isinstance(fr, dict) and fr.get("type") == "auth":
                            authed = isinstance(fr.get("token"), str) and hmac.compare_digest(fr["token"], self.token)
                            if not authed:
                                self.auth_fail += 1
                            continue
                    fr["_authed"] = authed  # never store the token itself
                    with self.cv:
                        self.frames.append((time.time(), fr))
                        self.cv.notify_all()
        except OSError:
            pass
        finally:
            conn.close()

    def wait(self, pred, timeout: float, since: float = 0.0):
        end = time.time() + timeout
        with self.cv:
            while True:
                for t, fr in self.frames:
                    if t >= since and pred(fr):
                        return t, fr
                left = end - time.time()
                if left <= 0:
                    return None, None
                self.cv.wait(min(left, 0.5))

    def stop(self) -> None:
        try:
            if self.srv:
                self.srv.close()
        except OSError:
            pass
        for p in (self.rec_path, self.key_path, self.sock):
            try:
                os.unlink(p)
            except OSError:
                pass


def is_receipt(mid):
    return lambda f: f.get("action") == "peer_message_status" and f.get("orig_msg_id") == mid


def has_text(s):
    return lambda f: f.get("type") == "user" and s in str((f.get("message") or {}).get("content", ""))


# ---- Codex daemon status monitor ----------------------------------------------------------
class Monitor:
    def __init__(self):
        self.ev: list[tuple[float, str, dict]] = []
        self.server_requests = 0
        self.lock = threading.Lock()
        self.rpc = CodexRPC(on_notify=self._on, client_name="peerbridge-selftest", version="0.1.0")
        # Never answer server requests (approvals belong to the TUI that owns the thread): log only.
        self.rpc._answer_server_request = self._srvreq  # type: ignore[method-assign]

    def _srvreq(self, msg: dict) -> None:
        self.server_requests += 1

    def _on(self, m: str, p: dict) -> None:
        with self.lock:
            self.ev.append((time.time(), m, p))

    def statuses(self, tid: str, since: float = 0.0) -> list[tuple[float, str]]:
        with self.lock:
            return [(t, (p.get("status") or {}).get("type", "?")) for t, m, p in self.ev
                    if m == "thread/status/changed" and p.get("threadId") == tid and t >= since]

    def first(self, tid: str, typ: str, since: float):
        for t, s in self.statuses(tid, since):
            if s == typ:
                return t
        return None

    def current(self, tid: str) -> str | None:
        s = self.statuses(tid)
        return s[-1][1] if s else None

    def wait_idle(self, tid: str, timeout: float, settle: float = 1.0) -> bool:
        def ok():
            s = self.statuses(tid)
            cur = s[-1][1] if s else (thread_state(tid) or {}).get("status")
            last = s[-1][0] if s else 0
            return cur == "idle" and time.time() - last >= settle
        return bool(wait_until(ok, timeout, 0.2))


# ---- helpers over hub state -------------------------------------------------------------
def thread_state(tid: str) -> dict | None:
    try:
        return json.load(open(os.path.join(THREADS, f"{tid}.json")))
    except Exception:
        return None


def thread_files() -> dict[str, dict]:
    out = {}
    try:
        for f in os.listdir(THREADS):
            if f.endswith(".json"):
                try:
                    out[f[:-5]] = json.load(open(os.path.join(THREADS, f)))
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return out


def registry_row(stub_pid: int) -> dict | None:
    try:
        return json.load(open(os.path.join(ccpeer.SESSIONS_DIR, f"{stub_pid}.json")))
    except Exception:
        return None


def jsonl_since(path: str, offset: int) -> list[dict]:
    out = []
    try:
        with open(path) as f:
            f.seek(offset)
            for line in f:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return out


def fsize(p: str) -> int:
    return os.path.getsize(p) if os.path.exists(p) else 0


def spawn_codex(session: str, cwd: str, default_sandbox: bool = False) -> None:
    """default_sandbox=True launches plain `codex` with the user's DEFAULT approval policy + sandbox (real use)."""
    os.makedirs(cwd, exist_ok=True)
    # mode (b) legs launch through the opt-in launcher itself, so the gate tests exactly what users run
    exe = "codex" if default_sandbox else shlex.quote(os.path.join(REPO, "bin", "codex-unsandboxed"))
    inner = (f"env -u HERDR_PANE_ID -u HERDR_SESSION -u HERDR_ENV PATH={shlex.quote(os.path.join(REPO, 'bin'))}:$PATH "
             f"{exe} --no-alt-screen -C {shlex.quote(cwd)}")
    subprocess.run(["tmux", "new-session", "-d", "-s", session, "-x", "200", "-y", "50", "-c", cwd, inner], check=True)


def tui_hint(session: str) -> str:
    """Why a TUI never registered: read its pane instead of guessing."""
    try:
        pane = subprocess.run(["tmux", "capture-pane", "-p", "-t", session], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        pane = ""
    low = pane.lower()
    if "trust" in low and ("folder" in low or "directory" in low or "project" in low):
        return ("TUI is at Codex's first-run 'trust this folder?' screen: pre-trust the test folder in ~/.codex/config.toml "
                "([projects.\"<abs path>\"] trust_level = \"trusted\") or answer it once")
    if "skipping the shared" in low or "app-server daemon" in low and "skip" in low:
        return "TUI skipped the shared daemon (a -c/--enable/--disable/--search flag or an elevated launch)"
    last = [ln for ln in pane.splitlines() if ln.strip()][-3:]
    return "no registry row; pane tail: " + " | ".join(x.strip()[:80] for x in last)


def tmux_alive(session: str) -> bool:
    return subprocess.run(["tmux", "has-session", "-t", session], capture_output=True).returncode == 0


def wait_registered(cwd: str, before: set[str], timeout: float = 60):
    """New bridged thread whose cwd is `cwd`, plus its CC registry row with codexThreadId."""
    def find():
        for tid, st in thread_files().items():
            if tid in before or not str(st.get("cwd") or "").rstrip("/").endswith(cwd.rstrip("/")):
                continue
            row = registry_row(st.get("stubPid", 0))
            if row and row.get("codexThreadId") == tid and ccpeer.pid_alive(st["stubPid"]):
                return tid, st, row
        return None
    return wait_until(find, timeout, 0.1)


def live_target(tid: str, timeout: float = 15.0) -> dict:
    """The thread's CURRENT peer record. Re-resolved per send: the hub may respawn stubs (policy reload, restart)."""
    def find():
        st = thread_state(tid)
        if not st:
            return None
        for r in ccpeer.records():
            if r["pid"] == st.get("stubPid") and r.get("codexThreadId") == tid:
                return r
        return None
    r = wait_until(find, timeout, 0.1)
    if not r:
        raise RuntimeError(f"thread {tid} has no live peer row (stub gone / policy hides it)")
    return r


def send_user(fake: FakePeer, tid: str, text: str, extra: list[dict] | None = None) -> tuple[str, float]:
    target = live_target(tid)
    f = ccpeer.user_frame(fake.address, ccpeer.envelope(text, fake.address, fake.name, "bypass"), target.get("sessionId"))
    t = time.time()
    ccpeer.send_to(target, [f] + (extra or []))
    return f["msg_id"], t


def send_control(tid: str, frame: dict) -> float:
    target = live_target(tid)
    t = time.time()
    ccpeer.send_to(target, [frame])
    return t


OK_STATUSES = ("accepted", "delivered")


def hub_ack(mid: str, since_off: int, timeout: float = 15.0):
    """The hub's own record of how it answered message `mid` (events.jsonl `receipt` / legacy `receipt_sent`).
    Hub >= 0.2 follows the CC convention: success sends NO wire receipt, only failures travel back."""
    return wait_until(lambda: next((e for e in jsonl_since(EVENTS, since_off)
                                    if e.get("ev") in ("receipt", "receipt_sent") and e.get("msgId") == mid), None), timeout, 0.05)


def wire_receipt_ok(fake: "FakePeer", mid: str, since: float, wait: float = 1.0):
    """No failure receipt may come back on the wire; a legacy `delivered` one is fine."""
    t, f = fake.wait(is_receipt(mid), wait, since)
    return (f is None or f.get("status") == "delivered"), f


def turn_of(reason: str) -> str | None:
    m = re.search(r"\(([0-9a-f-]{8,})\)\s*$", reason or "")
    return m.group(1) if m else None


def wait_reply(fake: FakePeer, mon: "Monitor", tid: str, text: str, since: float, grace: float = 8.0):
    """Wait for a user frame containing `text`; give up `grace` s after the thread's turn went active->idle."""
    end = time.time() + MODEL_TIMEOUT
    while time.time() < end:
        t, f = fake.wait(has_text(text), 0.5, since)
        if t:
            return t, f
        a = mon.first(tid, "active", since)
        i = mon.first(tid, "idle", a) if a else None
        if i and mon.current(tid) == "idle" and time.time() - i > grace:
            return None, None
    return None, None


def rollout_hint(tid: str, needle: str) -> str:
    st = thread_state(tid) or {}
    try:
        tail = open(st.get("rollout") or "", encoding="utf-8", errors="replace").read()[-200000:]
        if needle in tail:
            return f"rollout shows '{needle}'"
    except Exception:
        pass
    return ""


# ---- the test --------------------------------------------------------------------------
def main() -> int:
    no_c2c = "--no-c2c" in sys.argv
    os.makedirs(CWD, exist_ok=True)
    fake = FakePeer(FAKE_NAME)
    mon: Monitor | None = None
    spawned: list[str] = []
    bridged: dict[str, dict] = {}  # label -> {tid, stubPid}
    ev_off, rc_off, log_off = fsize(EVENTS), fsize(RECEIPTS), fsize(HUBLOG)
    exposed = False
    exposed_extra: list[str] = []
    stage = "init"
    try:
        # 1 ---- hub + daemon + policy
        stage = "1-hub"
        r = subprocess.run([PB, "status"], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            log("hub not running; pb ensure")
            r = subprocess.run([PB, "ensure"], capture_output=True, text=True, timeout=20)
        try:
            ping = json.loads(r.stdout[r.stdout.index("{"):])
        except Exception:
            ping = {}
        if not check("hub_up", bool(ping.get("ok")), f"pid={ping.get('pid')} codex={ping.get('codex')} v={ping.get('codexVersion')}"):
            return 1
        check("hub_connected_to_daemon", bool(ping.get("codex")))
        pol = policy.load()
        if pol.get("off"):
            check("policy_not_off", False, "peerbridge kill switch is ON (pb on to re-enable); not touching it")
            return 1
        if not policy.allowed("-", os.path.realpath(CWD), pol):
            subprocess.run([PB, "expose", "--cwd", CWD], capture_output=True, text=True, timeout=10)
            exposed = True
            notes.append(f"policy expose={pol.get('expose')}: temporarily exposed --cwd {CWD} (hidden again at teardown)")
        check("policy_allows_test_cwd", policy.allowed("-", os.path.realpath(CWD)), f"expose={policy.load().get('expose')}")
        try:
            mon = Monitor()
            loaded = mon.rpc.call("thread/loaded/list", {}).get("data", [])
            check("daemon_reachable", True, f"{len(loaded)} loaded threads, transport={mon.rpc.mode}")
        except Exception as e:
            check("daemon_reachable", False, str(e))
            return 1
        fake.start()
        check("fake_peer_listed", any(x["address"] == fake.address for x in ccpeer.records()), fake.address)

        # 2 ---- spawn Codex #1, time to CC registry row
        stage = "2-register"
        before = set(thread_files())
        ts = time.time()
        spawn_codex(TMUX1, CWD)
        spawned.append(TMUX1)
        got = wait_registered(CWD, before, 60)
        if not check("codex_registered", bool(got), tui_hint(TMUX1) if not got else ""):
            return 1
        tid1, st1, row1 = got
        timings["register_s"] = rd(time.time() - ts)
        bridged["codex1"] = {"tid": tid1, "stubPid": st1["stubPid"], "name": st1["name"]}
        log(f"codex1 thread={tid1} peer={st1['name']} stub={st1['stubPid']} in {timings['register_s']}s")
        check("registry_row_shape", row1.get("entrypoint") == "codex" and row1.get("harness") == "codex"
              and row1.get("messagingSocketPath") == st1["address"][4:], f"status={row1.get('status')}")
        mon.wait_idle(tid1, 20, settle=0.5)

        # 3 ---- PONG round trip (bare `pb`, exactly as a Codex user would type it)
        stage = "3-pong"
        pbcmd = "pb"
        nonce = secrets.token_hex(3)
        off = fsize(EVENTS)
        mid, t = send_user(fake, tid1, f"Reply by running exactly: pb send '{fake.address}' 'PONG {nonce}'")
        ack = hub_ack(mid, off)
        timings["inject_ack_s"] = rd(ack["t"] - t) if ack else None
        check("pong_injected", bool(ack) and ack.get("status") in OK_STATUSES,
              f"{timings['inject_ack_s']}s {ack and ack.get('status')} {ack and ack.get('reason')}")
        wok, wf = wire_receipt_ok(fake, mid, t)
        check("pong_no_failure_receipt", wok, f"wire receipt: {wf and wf.get('status')}" if wf else "none (CC convention: success is silent)")
        ta = wait_until(lambda: mon.first(tid1, "active", t), 20)
        timings["wake_s"] = rd(ta - t) if ta else None
        check("pong_wake_active", bool(ta), f"{timings['wake_s']}s to thread active")
        pt, pf = wait_reply(fake, mon, tid1, f"PONG {nonce}", t)
        timings["pong_roundtrip_s"] = rd(pt - t) if pt else None
        mon.wait_idle(tid1, MODEL_TIMEOUT)
        ti = mon.first(tid1, "idle", ta) if ta else None
        timings["pong_model_turn_s"] = rd(ti - ta) if (ti and ta) else None
        check("pong_roundtrip_bare_pb", bool(pt), f"{timings['pong_roundtrip_s']}s" if pt else
              (rollout_hint(tid1, "command not found: pb") or "no PONG"))
        if not pt:  # isolate transport from PATH: retry with the absolute pb path
            pbcmd = PB
            nonce = secrets.token_hex(3)
            mid, t = send_user(fake, tid1, f"Reply by running exactly: {PB} send '{fake.address}' 'PONG {nonce}'")
            ta = wait_until(lambda: mon.first(tid1, "active", t), 20)
            timings["wake_abs_s"] = rd(ta - t) if ta else None
            pt, pf = wait_reply(fake, mon, tid1, f"PONG {nonce}", t)
            timings["pong_roundtrip_abs_s"] = rd(pt - t) if pt else None
            mon.wait_idle(tid1, MODEL_TIMEOUT)
            ti = mon.first(tid1, "idle", ta) if ta else None
            timings["pong_model_turn_abs_s"] = rd(ti - ta) if (ti and ta) else None
            check("pong_roundtrip_abs_pb", bool(pt), f"{timings['pong_roundtrip_abs_s']}s" if pt else
                  (rollout_hint(tid1, "CODEX_THREAD_ID unset") or rollout_hint(tid1, "not bridged") or "no PONG"))
        if pf:
            env = ccpeer.parse_envelope(pf["message"]["content"])
            cur = thread_state(tid1) or {}
            check("pong_provenance", env.get("from") == cur.get("address") and pf.get("_authed"),
                  f"from-name={env.get('from_name')} from-mode={env.get('from_mode')}")
        log(f"split: wake={timings.get('wake_s')}s model-turn(active->idle)={timings.get('pong_model_turn_s')}s")

        # 4 ---- busy steer
        stage = "4-steer"
        n = secrets.token_hex(3)
        off = fsize(EVENTS)
        mid_a, ta0 = send_user(fake, tid1, f"Run this exact shell command first: sleep 8 . After it finishes, run exactly: {pbcmd} send '{fake.address}' 'STEER-A {n}'")
        rfa = hub_ack(mid_a, off)
        wait_until(lambda: mon.first(tid1, "active", ta0), 20)
        time.sleep(3.0)  # well inside the sleep 8 tool call
        busy_now = mon.current(tid1)
        mid_b, tb0 = send_user(fake, tid1, f"Additional request: also run exactly: {pbcmd} send '{fake.address}' 'STEER-B {n}'")
        rfb = hub_ack(mid_b, off)
        rbt = rfb["t"] if rfb else None
        reason_a, reason_b = (rfa or {}).get("reason", ""), (rfb or {}).get("reason", "")
        timings["steer_ack_s"] = rd(rbt - tb0) if rbt else None
        check("steer_second_injected_steered", bool(rfb) and rfb.get("status") in OK_STATUSES and "steer" in reason_b,
              f"status-at-send={busy_now} reason={reason_b}")
        check("steer_same_turn_id", bool(turn_of(reason_a)) and turn_of(reason_a) == turn_of(reason_b),
              f"A={turn_of(reason_a)} B={turn_of(reason_b)}")
        at, _ = wait_reply(fake, mon, tid1, f"STEER-A {n}", ta0)
        bt, _ = wait_reply(fake, mon, tid1, f"STEER-B {n}", ta0)
        timings["steer_a_s"] = rd(at - ta0) if at else None
        timings["steer_b_s"] = rd(bt - tb0) if bt else None
        check("steer_both_handled", bool(at and bt), f"A={timings['steer_a_s']}s B={timings['steer_b_s']}s")
        mon.wait_idle(tid1, MODEL_TIMEOUT)

        # 5 ---- notify_when_idle
        stage = "5-idle"
        # 5a: subscribe while the thread is busy
        _, t5 = send_user(fake, tid1, "Run this exact shell command: sleep 5 . Then reply with the single word DONE5 (do not run pb).")
        a5 = wait_until(lambda: mon.first(tid1, "active", t5), 20)
        time.sleep(1.0)
        sub = ccpeer.control("notify_when_idle", fake.address, from_mode="bypass")
        ts5 = send_control(tid1, sub)
        nt, nf = fake.wait(lambda f: f.get("action") == "peer_idle_notice" and f.get("orig_msg_id") == sub["msg_id"], MODEL_TIMEOUT, ts5)
        i5 = mon.first(tid1, "idle", a5 or t5)
        timings["idle_notice_after_idle_s"] = rd(nt - i5) if (nt and i5) else None
        check("idle_notice_busy_sub", bool(nt) and bool(i5) and nt >= i5 - 0.05,
              f"notice {timings['idle_notice_after_idle_s']}s after idle, state={nf and nf.get('state')}")
        check("hub_frames_authenticated", bool(nf and nf.get("_authed")) and fake.auth_fail == 0,
              f"idle notice carried our peer token; auth failures={fake.auth_fail}")
        mon.wait_idle(tid1, MODEL_TIMEOUT)
        # 5b: `pb send --notify-idle` shape: user frame + subscription in one write while the thread is idle
        sub2 = ccpeer.control("notify_when_idle", fake.address, from_mode="bypass")
        _, t5b = send_user(fake, tid1, "Reply with the single word OK (do not run pb).", [sub2])
        nt2, _ = fake.wait(lambda f: f.get("action") == "peer_idle_notice" and f.get("orig_msg_id") == sub2["msg_id"], MODEL_TIMEOUT, t5b)
        mon.wait_idle(tid1, MODEL_TIMEOUT)
        a5b = mon.first(tid1, "active", t5b)
        i5b = mon.first(tid1, "idle", a5b) if a5b else None
        premature = bool(nt2 and i5b and nt2 < i5b - 0.05)
        check("idle_notice_combined_not_premature", bool(nt2) and bool(i5b) and not premature,
              f"notice +{rd(nt2 - t5b) if nt2 else None}s, active +{rd(a5b - t5b) if a5b else None}s, idle +{rd(i5b - t5b) if i5b else None}s")

        # 6 ---- Codex -> Codex
        if not no_c2c:
            stage = "6-c2c"
            before = set(thread_files())
            spawn_codex(TMUX2, CWD2)
            spawned.append(TMUX2)
            got2 = wait_registered(CWD2, before, 60)
            if check("codex2_registered", bool(got2), "" if got2 else tui_hint(TMUX2)):
                tid2, st2, _ = got2
                bridged["codex2"] = {"tid": tid2, "stubPid": st2["stubPid"], "name": st2["name"]}
                mon.wait_idle(tid2, 20, settle=0.5)
                n6 = secrets.token_hex(3)
                ev6, rc6 = fsize(EVENTS), fsize(RECEIPTS)
                addr1 = (thread_state(tid1) or {}).get("address")
                addr2 = (thread_state(tid2) or {}).get("address")
                inner = f"C2C {n6}: please reply by running exactly: {pbcmd} send {FAKE_NAME} C2C-ACK-{n6}"
                _, t6 = send_user(fake, tid1, f"Run exactly: {pbcmd} send {st2['name']} '{inner}'")
                inbound = wait_until(lambda: next((e for e in jsonl_since(EVENTS, ev6) if e.get("ev") == "inbound"
                                                   and e.get("thread") == tid2 and e.get("from") == addr1), None), 90, 0.2)
                timings["c2c_inbound_s"] = rd(inbound["t"] - t6) if inbound else None
                check("c2c_codex1_to_codex2_injected", bool(inbound and inbound.get("ok")),
                      f"{timings['c2c_inbound_s']}s {inbound and inbound.get('detail')}")
                rcpt = hub_ack(inbound["msgId"], ev6, 15) if inbound else None
                bad = [e for e in jsonl_since(RECEIPTS, rc6) if e.get("thread") == tid1 and e.get("from") == addr2
                       and e.get("status") != "delivered"]
                check("c2c_codex2_accepted_no_failure", bool(rcpt and rcpt.get("status") in OK_STATUSES and rcpt.get("to") == addr1) and not bad,
                      f"{rcpt and rcpt.get('status')} failures={len(bad)}")
                ackt, ackf = wait_reply(fake, mon, tid2, f"C2C-ACK-{n6}", t6, grace=10)
                timings["c2c_ack_roundtrip_s"] = rd(ackt - t6) if ackt else None
                ok_from = bool(ackf) and ccpeer.parse_envelope(ackf["message"]["content"]).get("from") == (thread_state(tid2) or {}).get("address")
                check("c2c_codex2_ack_to_fake_claude", bool(ackt) and ok_from, f"{timings['c2c_ack_roundtrip_s']}s")
        # 7 ---- DEFAULT sandbox + approval policy (plain `codex`): pb must reply without escalation
        if "--no-sandbox-leg" not in sys.argv:
            stage = "7-default-sandbox"
            cwd3, tmux3 = CWD + "-sbx", "peertest-st-sbx"
            if not policy.allowed("-", os.path.realpath(cwd3)):
                subprocess.run([PB, "expose", "--cwd", cwd3], capture_output=True, text=True, timeout=10)
                notes.append(f"temporarily exposed --cwd {cwd3}")
                exposed_extra.append(cwd3)
            before = set(thread_files())
            spawn_codex(tmux3, cwd3, default_sandbox=True)
            spawned.append(tmux3)
            got3 = wait_registered(cwd3, before, 60)
            if check("sbx_codex_registered", bool(got3), "plain `codex`, default sandbox/approvals" if got3 else tui_hint(tmux3)):
                tid3, st3, _ = got3
                bridged["codex_sbx"] = {"tid": tid3, "stubPid": st3["stubPid"], "name": st3["name"]}
                mon.wait_idle(tid3, 20, settle=0.5)
                n7, ev7 = secrets.token_hex(3), fsize(EVENTS)
                _, t7 = send_user(fake, tid3, f"Reply by running exactly: pb send '{fake.address}' 'SBX {n7}'")
                st7, f7 = wait_reply(fake, mon, tid3, f"SBX {n7}", t7, grace=10)
                timings["sbx_roundtrip_s"] = rd(st7 - t7) if st7 else None
                via = next((e for e in jsonl_since(EVENTS, ev7) if e.get("ev") == "outbox" and e.get("thread") == tid3), None)
                check("sbx_reply_via_output_channel", bool(via), "pb fell back to the rollout marker" if via else
                      (rollout_hint(tid3, "Operation not permitted") or "no outbox event"))
                env7 = ccpeer.parse_envelope(f7["message"]["content"]) if f7 else {}
                check("sbx_reply_arrived", bool(st7), f"{timings['sbx_roundtrip_s']}s from-mode={env7.get('from_mode')}")
                check("sbx_from_mode_honest", env7.get("from_mode") == "prompting",
                      "sandboxed on-request Codex declares prompting (a bypass Claude will HOLD it for its user)")
        stage = "done"
    except Exception:
        check(f"unexpected_exception@{stage}", False, traceback.format_exc().strip().splitlines()[-1])
        traceback.print_exc()
    finally:
        # 7 ---- teardown (always)
        for b in bridged.values():  # remember the CURRENT stub pid too (it may have been respawned)
            b["stubPids"] = sorted({b["stubPid"], (thread_state(b["tid"]) or {}).get("stubPid") or b["stubPid"]})
        tk = time.time()
        for s in spawned:
            subprocess.run(["tmux", "kill-session", "-t", s], capture_output=True)
        check("tmux_sessions_killed", not any(tmux_alive(s) for s in spawned), ",".join(spawned))
        if bridged:
            def gone():
                for b in bridged.values():
                    if thread_state(b["tid"]) or any(registry_row(p) or ccpeer.pid_alive(p) for p in b["stubPids"]):
                        return False
                return True
            g = wait_until(gone, 90, 0.5)
            timings["rows_gone_s"] = rd(time.time() - tk) if g else None
            left = [k for k, b in bridged.items() if thread_state(b["tid"]) or any(registry_row(p) for p in b["stubPids"])]
            check("registry_rows_removed", bool(g), f"{timings['rows_gone_s']}s" if g else f"still listed: {left}")
        if exposed:
            subprocess.run([PB, "hide", "--cwd", CWD], capture_output=True, text=True, timeout=10)
        for c in exposed_extra:
            subprocess.run([PB, "hide", "--cwd", c], capture_output=True, text=True, timeout=10)
        fake.stop()
        check("fake_peer_removed", not any(os.path.exists(p) for p in (fake.rec_path, fake.key_path, fake.sock)))
        if mon:
            try:
                mon.rpc.close()
            except Exception:
                pass
    hub_log = []
    try:
        with open(HUBLOG) as f:
            f.seek(log_off)
            hub_log = [ln.rstrip() for ln in f if any(k in ln for k in ("policy", "hub ", "respawn", "loop error", "connection closed"))]
    except Exception:
        pass
    if hub_log:
        notes.append({"hub_log_during_run": hub_log[-40:]})
    return finish(mon, bridged, ev_off, rc_off)


def finish(mon, bridged, ev_off, rc_off) -> int:
    fails = [c for c in checks if c["result"] != "PASS"]
    w = max(len(c["check"]) for c in checks) if checks else 10
    print("\n" + "=" * (w + 60))
    print(f"{'CHECK':<{w}}  RESULT  DETAIL")
    for c in checks:
        print(f"{c['check']:<{w}}  {c['result']:<6}  {c['detail'][:110]}")
    print("-" * (w + 60))
    print("TIMINGS: " + "  ".join(f"{k}={v}" for k, v in timings.items()))
    print(f"OVERALL: {'PASS' if not fails else f'FAIL ({len(fails)})'}")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    os.makedirs(os.path.join(REPO, "evidence"), exist_ok=True)
    out = os.path.join(REPO, "evidence", f"selftest-{stamp}.json")
    ev = {"started": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(T0)), "duration_s": round(time.time() - T0, 2),
          "overall": "PASS" if not fails else "FAIL", "checks": checks, "timings": timings, "bridged": bridged,
          "notes": notes, "server_requests_seen_by_monitor": mon.server_requests if mon else None,
          "status_events": [{"t": round(t - T0, 3), "thread": p.get("threadId"), "status": p.get("status")}
                            for t, m, p in (mon.ev if mon else []) if m == "thread/status/changed"
                            and p.get("threadId") in {b["tid"] for b in bridged.values()}],
          "hub_events": [e for e in jsonl_since(EVENTS, ev_off) if e.get("thread") in {b["tid"] for b in bridged.values()}],
          "hub_receipts": [e for e in jsonl_since(RECEIPTS, rc_off) if e.get("thread") in {b["tid"] for b in bridged.values()}]}
    with open(out, "w") as f:
        json.dump(ev, f, indent=1)
    print(f"evidence: {out}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
