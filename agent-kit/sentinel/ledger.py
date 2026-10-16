#!/usr/bin/env python3
"""ledger.py - passive incident ledger for the agent mesh. Python 3.8+, standard library only.

READ-ONLY: it reads our own logs and appends typed lines to its own incidents file. It changes nothing,
stops nothing, runs nothing it reads, reads no pane screens and no project files. Zero tokens.

  ledger.py watch  --logs DIR [--out DIR] [--every 5] [--deadline FILE=SEC ...] [--from-start]
                                        follow DIR/*.log (keeper, hub, hub.err, agent-bridge logs)
  ledger.py replay --logs DIR [--out DIR]   read every log once from the start, print the incidents, exit
  ledger.py show   [--out DIR] [--open]     the incidents so far, one line each
  ledger.py plan   [--out DIR] --minutes N --why TEXT
                                        a planned change (restart, deploy): for N minutes hits are only counted as
                                        planned, never opened. Say it BEFORE you restart our own links.
  ledger.py selftest                        offline test on made-up logs

Out dir (default ~/.agent-sentinel): planned.json (windows from `plan`), incidents.jsonl (one line per NEW incident), state.json (offsets,
counters: a known fingerprint only bumps its counter, so a crash loop is one incident with a count).

Incident: {ts_utc, mono, host, cls, fp, count, evidence, file, state:"open"}. Classes:
  link_exit      keeper: "hub link exited (code N)", N != 0                     hard, 1 hit
  keeper_lint    keeper: "hub link exited (code )" - the exit code got lost     hard, 1 hit
  err_empty      a nonzero link exit while <link>.hub.err.log and .prev.log are both empty
  link_down      LINK <me> DOWN with no UP within 30 s                           hard
  flap           LINK DOWN then UP within 30 s; a pair counts once                soft (>=3 in 10 min)
  step_error     hub "STEP ERROR"                                                soft
  winerr         WinError 5 / 32 (file held by another process)                  soft
  traceback      a Python traceback; fingerprint = exception type + message without numbers
  log_reset      a log got shorter and no .prev.log kept the old run             hard
  clock_step     wall clock moved > 5 s against the monotonic clock (watch only) hard
  deadline       a --deadline FILE was not touched for SEC seconds (watch only)  hard
A link killed on purpose exits with code -1 and writes no error: that is a link_exit, never an err_empty.
Rotated logs (*.prev.log, *.prev.N.log) are history, not followed.
Soft classes open at 3 hits in 10 minutes. Any class closes after 20 minutes without a hit, so it can open again.
"""
import argparse, calendar, glob, hashlib, json, os, re, socket, sys, tempfile, time

SOFT = {"flap", "step_error", "winerr"}
SOFT_N, SOFT_WIN, QUIET, FLAP_S, STEP_S = 3, 600, 1200, 30, 5.0
TS_RE = re.compile(r"^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)")
EXIT_RE = re.compile(r"hub link exited \(code ([^)]*)\)")
LINK_RE = re.compile(r"\bLINK (\S+) (DOWN|UP) (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)(?: \((.*)\))?")
EXC_RE = re.compile(r"^([A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt))(?::\s*(.*))?$")


def iso(t=None): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if t is None else t))
def norm(s): return re.sub(r"\d+", "N", s or "")[:160]
def link_of(path):  # <link>.keeper.log / <link>.hub.err.log / agent-bridge.log -> link name
    b = os.path.basename(path)
    return b.split(".")[0] if "." in b else b


class Ledger:
    def __init__(self, out, host=None):
        self.out, self.host = out, host or socket.gethostname()
        os.makedirs(out, exist_ok=True)
        self.sf, self.inc = os.path.join(out, "state.json"), os.path.join(out, "incidents.jsonl")
        try: self.st = json.load(open(self.sf, encoding="utf-8"))
        except (OSError, ValueError): self.st = {}
        for k in ("offsets", "fps", "hits", "planned_hits"): self.st.setdefault(k, {})
        self.pf = os.path.join(out, "planned.json"); self.load_planned()
        self.pending_down = {}   # link -> (t, file, line): a DOWN waiting for its UP
        self.tb = {}             # file -> lines of a traceback in progress
        self.new = []

    def load_planned(self):   # its own file: `plan` (another process) never races the watcher's state.json
        try: self.planned = json.load(open(self.pf, encoding="utf-8"))
        except (OSError, ValueError): self.planned = []

    def save(self):
        fd, tmp = tempfile.mkstemp(dir=self.out, prefix=".state.")
        with os.fdopen(fd, "w", encoding="utf-8") as f: json.dump(self.st, f)
        for i in range(20):   # Windows: a reader can hold the target for a moment
            try: os.replace(tmp, self.sf); return
            except PermissionError: time.sleep(0.05)
        os.unlink(tmp)

    def hit(self, cls, key, evidence, path, t):
        fp = hashlib.sha1(f"{self.host}|{cls}|{key}".encode()).hexdigest()[:12]
        if any(p["from"] <= t <= p["to"] for p in self.planned):   # inside a planned change: count only
            self.st["planned_hits"][cls] = self.st["planned_hits"].get(cls, 0) + 1; return None
        if cls in SOFT:
            h = [x for x in self.st["hits"].get(fp, []) if t - x < SOFT_WIN] + [t]
            self.st["hits"][fp] = h
            if len(h) < SOFT_N and fp not in self.st["fps"]: return None
        rec = self.st["fps"].get(fp)
        if rec and t - rec["last"] < QUIET:   # known and not quiet yet: count it, write nothing
            rec["count"] += 1; rec["last"] = t; return None
        self.st["fps"][fp] = {"cls": cls, "first": t, "last": t, "count": 1}
        inc = {"ts_utc": iso(t), "mono": round(time.monotonic(), 1), "host": self.host, "cls": cls, "fp": fp,
               "count": 1, "evidence": evidence[:200], "file": os.path.basename(path), "state": "open"}
        with open(self.inc, "a", encoding="utf-8") as f: f.write(json.dumps(inc, ensure_ascii=False) + "\n")
        self.new.append(inc); return inc

    def line_time(self, line, fallback):
        m = TS_RE.match(line)
        if not m: return fallback
        try: return time.mktime(time.strptime(m.group(1).replace("T", " "), "%Y-%m-%d %H:%M:%S"))
        except ValueError: return fallback

    def err_empty(self, logdir, link):
        for n in (".hub.err.log", ".hub.err.prev.log"):
            p = os.path.join(logdir, link + n)
            if os.path.exists(p) and os.path.getsize(p) > 0: return False
        return True

    def feed(self, path, line, now):
        t, link = self.line_time(line, now), link_of(path)
        tb = self.tb.get(path)
        if line.startswith("Traceback (most recent call last)"):
            self.tb[path] = []; return
        if tb is not None:
            if line.startswith((" ", "\t")): tb.append(line); return
            m = EXC_RE.match(line.strip()); del self.tb[path]
            if m: self.hit("traceback", f"{link}|{m.group(1)}|{norm(m.group(2))}", line.strip(), path, t)
        m = EXIT_RE.search(line)
        if m:
            code = m.group(1).strip()
            if code == "": self.hit("keeper_lint", link, line.strip(), path, t)
            elif code != "0":
                self.hit("link_exit", f"{link}|{code}", line.strip(), path, t)
                if code != "-1" and self.err_empty(os.path.dirname(path), link): self.hit("err_empty", link, line.strip(), path, t)
        m = LINK_RE.search(line)
        if m:
            me, state = m.group(1), m.group(2)
            lt = calendar.timegm(time.strptime(m.group(3), "%Y-%m-%dT%H:%M:%SZ"))
            if state == "DOWN": self.pending_down[me] = (lt, path, line.strip())
            else:
                d = self.pending_down.pop(me, None)
                if d and lt - d[0] <= FLAP_S: self.hit("flap", me, f"{d[2]} | {line.strip()}", path, lt)
                elif d: self.hit("link_down", me, d[2], d[1], d[0])
        if "STEP ERROR" in line: self.hit("step_error", f"{link}|{norm(line.split('STEP ERROR', 1)[1])}", line.strip(), path, t)
        if re.search(r"WinError (5|32)\b", line): self.hit("winerr", f"{link}|{re.search(r'WinError (5|32)', line).group(1)}", line.strip(), path, t)

    def settle(self, now):   # a DOWN with no UP for FLAP_S seconds is an outage, not a flap
        for me, d in list(self.pending_down.items()):
            if now - d[0] > FLAP_S: del self.pending_down[me]; self.hit("link_down", me, d[2], d[1], d[0])

    def scan(self, logdir, from_start=False, now=None):
        now = time.time() if now is None else now
        for p in sorted(glob.glob(os.path.join(logdir, "*.log"))):
            if ".prev." in os.path.basename(p): continue
            try: size = os.path.getsize(p)
            except OSError: continue
            off = self.st["offsets"].get(p)
            if off is None: off = 0 if from_start else size
            if size < off:   # shorter than before: rotated or truncated
                prev = p[:-4] + ".prev.log"
                if not (os.path.exists(prev) and time.time() - os.path.getmtime(prev) < 600):
                    self.hit("log_reset", os.path.basename(p), f"{os.path.basename(p)}: {off} B -> {size} B, no .prev.log kept", p, now)
                off = 0
            if size > off:
                with open(p, "rb") as f:
                    f.seek(off); data = f.read()
                cut = data.rfind(b"\n") + 1   # only whole lines; the rest is read next time
                for raw in data[:cut].splitlines():
                    self.feed(p, raw.decode("utf-8", "replace").rstrip("\r"), now)
                off += cut
            self.st["offsets"][p] = off
        self.settle(now)


def watch(a):
    lg = Ledger(a.out); first = True
    dl = [(d.rsplit("=", 1)[0], float(d.rsplit("=", 1)[1])) for d in a.deadline]
    w0, m0 = time.time(), time.monotonic()
    print(f"{iso()} LEDGER watching {a.logs} every {a.every}s -> {lg.inc} (read-only)", flush=True)
    while True:
        lg.load_planned()
        lg.scan(a.logs, from_start=a.from_start and first); first = False
        w1, m1 = time.time(), time.monotonic()
        step = (w1 - w0) - (m1 - m0)
        if abs(step) > STEP_S: lg.hit("clock_step", "wall", f"wall clock moved {step:+.0f} s against monotonic", "clock", w1)
        w0, m0 = w1, m1
        for f, sec in dl:
            try: age = w1 - os.path.getmtime(f)
            except OSError: age = float("inf")
            if age > sec: lg.hit("deadline", f, f"{f} not touched for {age:.0f} s (limit {sec:.0f})", f, w1)
        for i in lg.new: print(f"{i['ts_utc']} INCIDENT {i['cls']} {i['fp']}: {i['evidence']}", flush=True)
        lg.new = []; lg.save(); time.sleep(a.every)


def plan(a):
    os.makedirs(a.out, exist_ok=True); pf, now = os.path.join(a.out, "planned.json"), time.time()
    try: cur = json.load(open(pf, encoding="utf-8"))
    except (OSError, ValueError): cur = []
    cur = [p for p in cur if p["to"] > now - 86400] + [{"from": now, "to": now + a.minutes * 60, "why": a.why[:200]}]
    fd, tmp = tempfile.mkstemp(dir=a.out, prefix=".planned.")
    with os.fdopen(fd, "w", encoding="utf-8") as f: json.dump(cur, f)
    for i in range(20):
        try: os.replace(tmp, pf); break
        except PermissionError: time.sleep(0.05)
    print(f"{iso()} PLANNED {a.minutes} min: {a.why}")


def show(a):
    try: st = json.load(open(os.path.join(a.out, "state.json"), encoding="utf-8"))["fps"]
    except (OSError, ValueError, KeyError): st = {}
    try: rows = [json.loads(l) for l in open(os.path.join(a.out, "incidents.jsonl"), encoding="utf-8")]
    except OSError: rows = []
    seen = {}
    for r in rows: seen[r["fp"]] = r
    for fp, r in seen.items():
        c = st.get(fp, {}); quiet = time.time() - c.get("last", 0) >= QUIET
        if a.open and quiet: continue
        print(f"{r['ts_utc']} {r['cls']:<11} x{c.get('count', r['count'])} {'closed' if quiet else 'open  '} {r['evidence']}")


def selftest():
    import io, shutil
    ok = [0, 0]
    def check(cond, label):
        ok[0 if cond else 1] += 1; print(("ok   " if cond else "FAIL ") + label)
    d = tempfile.mkdtemp(prefix="ledger-test-"); logs, out = os.path.join(d, "logs"), os.path.join(d, "out")
    os.makedirs(logs)
    def w(name, text):
        with open(os.path.join(logs, name), "a", encoding="utf-8") as f: f.write(text)
    w("desktop.keeper.log",
      "2026-10-16 10:00:00  KEEPER desktop up (pid 1)\n"
      "2026-10-16 10:05:00  hub link exited (code 1); restarting\n"
      "2026-10-16 10:06:00  hub link exited (code 1); restarting\n"
      "2026-10-16 10:07:00  hub link exited (code ); restarting\n")
    w("desktop.hub.err.log",
      "Traceback (most recent call last):\n  File \"hub.py\", line 12, in write_atomic\n    os.replace(t, p)\n"
      "PermissionError: [WinError 5] Access is denied: 'agents/a1.json'\n")
    w("desktop.hub.log",
      "LINK desktop UP 2026-10-16T07:00:00Z\n"
      "LINK desktop DOWN 2026-10-16T07:10:00Z (state unreadable)\nLINK desktop UP 2026-10-16T07:10:10Z\n"
      "LINK desktop DOWN 2026-10-16T07:20:00Z\nLINK desktop UP 2026-10-16T07:30:00Z\n"
      "STEP ERROR desktop (1/5): OSError: x\n")
    w("agent-bridge.log", "2026-10-16T10:00:00 START bridge pid 5 started\n")
    lg = Ledger(out, host="t"); lg.scan(logs, from_start=True); lg.save()
    cls = sorted(i["cls"] for i in lg.new)
    check(cls.count("link_exit") == 1, "two exits with code 1 = ONE link_exit incident")
    check(lg.st["fps"][[i for i in lg.new if i["cls"] == "link_exit"][0]["fp"]]["count"] == 2, "its counter says 2")
    check(cls.count("keeper_lint") == 1, "blank exit code = keeper_lint")
    check("err_empty" not in cls, "err log has content: no err_empty")
    check(cls.count("traceback") == 1, "traceback = one incident")
    check("flap" not in cls, "one flap pair under the soft threshold: no incident yet")
    check(cls.count("link_down") == 1, "DOWN with UP 10 min later = link_down")
    check("step_error" not in cls and "winerr" not in cls, "single soft hits open nothing")
    # soft threshold: 3 flaps within 10 min open one incident; a 4th only counts
    lg.new = []
    w("desktop.hub.log", "".join(f"LINK desktop DOWN 2026-10-16T08:0{i}:00Z\nLINK desktop UP 2026-10-16T08:0{i}:05Z\n" for i in range(4)))
    lg.scan(logs); flaps = [i for i in lg.new if i["cls"] == "flap"]
    check(len(flaps) == 1, "3+ flap pairs in 10 min = ONE flap incident")
    # restart: offsets kept, nothing re-reported
    lg.save(); lg2 = Ledger(out, host="t"); lg2.scan(logs)
    check(lg2.new == [], "restart with saved offsets reports nothing again")
    # truncation without .prev.log
    open(os.path.join(logs, "desktop.hub.err.log"), "w").close()
    lg2.scan(logs); check([i["cls"] for i in lg2.new] == ["log_reset"], "err log truncated, no .prev.log = log_reset")
    # nonzero exit with both err logs empty
    lg2.new = []; w("lap.keeper.log", "2026-10-16 11:00:00  hub link exited (code 3); restarting\n")
    lg3 = Ledger(os.path.join(d, "out3"), host="t"); lg3.scan(logs, from_start=True)
    check(any(i["cls"] == "err_empty" for i in lg3.new), "exit 3 with no err log = err_empty")
    # partial line is not read until its newline arrives
    lg3.new = []; w("lap.keeper.log", "2026-10-16 11:01:00  hub link exited (code 4)")
    lg3.scan(logs); check(lg3.new == [], "half a line waits")
    w("lap.keeper.log", "; restarting\n"); lg3.scan(logs)
    check(any(i["cls"] == "link_exit" and "code 4" in i["evidence"] for i in lg3.new), "the rest of the line completes it")
    # incidents.jsonl lines are valid JSON with the fields
    rows = [json.loads(l) for l in open(os.path.join(out, "incidents.jsonl"), encoding="utf-8")]
    check(all({"ts_utc", "mono", "host", "cls", "fp", "count", "evidence", "file", "state"} <= set(r) for r in rows), "incident lines carry every field")
    # the ledger writes only inside its out dir
    before = {p: os.path.getmtime(p) for p in glob.glob(os.path.join(logs, "*"))}
    Ledger(os.path.join(d, "out4"), host="t").scan(logs, from_start=True)
    check(before == {p: os.path.getmtime(p) for p in glob.glob(os.path.join(logs, "*"))}, "logs are never written")
    # a link killed on purpose (code -1): link_exit, no err_empty
    lg5 = Ledger(os.path.join(d, "out5"), host="t"); w("k5.keeper.log", "2026-10-16 12:00:00  hub link exited (code -1); restarting\n")
    lg5.scan(logs, from_start=True); c5 = [i["cls"] for i in lg5.new if i["file"] == "k5.keeper.log"]
    check(c5 == ["link_exit"], "code -1 = link_exit only, no err_empty")
    # rotated history is not followed
    w("k6.hub.prev.2.log", "2026-10-16 12:00:00  hub link exited (code 9); restarting\n")
    lg6 = Ledger(os.path.join(d, "out6"), host="t"); lg6.scan(logs, from_start=True)
    check(not any(i["file"].startswith("k6.") for i in lg6.new), "*.prev.N.log is history, not followed")
    # planned window: hits inside are counted, not opened; after it, they open again
    o7 = os.path.join(d, "out7"); lg7 = Ledger(o7, host="t"); lg7.save()
    plan(argparse.Namespace(out=o7, minutes=10, why="test restart"))
    lg7 = Ledger(o7, host="t"); lg7.hit("link_exit", "k|1", "x", "k.keeper.log", time.time())
    check(lg7.new == [] and lg7.st["planned_hits"].get("link_exit") == 1, "inside a planned window: counted, not opened")
    lg7.hit("link_exit", "k|1", "x", "k.keeper.log", time.time() + 700)
    check(len(lg7.new) == 1, "after the window: opens again")
    shutil.rmtree(d)
    print(f"{ok[0]} ok, {ok[1]} failed"); return 0 if ok[1] == 0 else 1


def main():
    ap = argparse.ArgumentParser(description="passive incident ledger (read-only)")
    sp = ap.add_subparsers(dest="cmd", required=True)
    default_out = os.path.join(os.path.expanduser("~"), ".agent-sentinel")
    for n in ("watch", "replay"):
        p = sp.add_parser(n); p.add_argument("--logs", required=True); p.add_argument("--out", default=default_out)
        if n == "watch":
            p.add_argument("--every", type=float, default=5); p.add_argument("--from-start", action="store_true")
            p.add_argument("--deadline", action="append", default=[], help="FILE=SEC")
    p = sp.add_parser("show"); p.add_argument("--out", default=default_out); p.add_argument("--open", action="store_true")
    p = sp.add_parser("plan"); p.add_argument("--out", default=default_out)
    p.add_argument("--minutes", type=float, required=True); p.add_argument("--why", required=True)
    sp.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "selftest": return selftest()
    if a.cmd == "show": return show(a)
    if a.cmd == "plan": return plan(a)
    if a.cmd == "replay":
        lg = Ledger(a.out); lg.scan(a.logs, from_start=True); lg.settle(time.time()); lg.save()
        for i in lg.new: print(f"{i['ts_utc']} {i['cls']:<11} {i['fp']} {i['evidence']}")
        print(f"{len(lg.new)} incident(s) -> {lg.inc}"); return 0
    try: watch(a)
    except KeyboardInterrupt: return 0


if __name__ == "__main__":
    sys.exit(main())
