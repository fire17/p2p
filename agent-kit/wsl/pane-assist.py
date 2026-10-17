#!/usr/bin/env python3
"""pane-assist.py - non-AI helper: lets Shai read and answer interactive questions in herdr panes of session "gony",
even when the agent in that pane is the one that is blocked (Gony 3EB009B2, via Shai).

Input : the Shai tunnel mailbox <P2P_HOME>/tunnel/<name>/<current.json id>/inbox.jsonl (same path as shai-ear.ps1
        Get-MailDir), tailed READ-ONLY from its current end: it never touches cursor.json/offset.json, opens the file
        only for each poll (a WSL handle held on /mnt/c can block the Windows writer), and acts only on chat rows
        from the tunnel's pinned peer whose text starts with "ASSIST ". shai-ear keeps printing every row as before.
Verbs : ASSIST <id> HEALTH                             kit windows/health.ps1: VERDICT + WARN/FAIL lines
        ASSIST <id> LIST
        ASSIST <id> READ <label|agent-name> [n]           n = visible lines, default 40, max 120
        ASSIST <id> KEYS <label|agent-name> <tok> [tok...] tokens only: Up Down Left Right Enter Esc Tab Space BSpace
                                                          0-9 y n; max 20; never free text
        anything else -> error reply.
Safety: session "gony" only (never "default"); the only commands it runs are herdr pane/agent list|read|send-keys
        and shai-send. KEYS goes only to a pane whose agent herdr reports "blocked" (waiting on a dialog) or to a
        pane whose last screen lines are a choice dialog (herdr says "done" on some), or to a
        pane labelled assist-test*: keys into an idle shell/agent prompt (e.g. Up Enter) would re-run a command.
Reply : shai-send "LOG ASSIST-REPLY <id> <ok|error> <payload>" (shai-send only accepts its fixed tags, so LOG
        carries it), control chars stripped, capped at 6000 chars, --redact.
Log   : ~/.agent-assist/assist.log (request + action, no pane text). Single instance (flock).
Run   : python3 <kit>/wsl/pane-assist.py [--name join-...]   (default: the only join-* tunnel; start.sh starts it)
Stop  : kill $(cat ~/.agent-assist/assist.pid)
"""
import argparse, fcntl, json, os, re, subprocess, sys, tempfile, time

SESSION = "gony"
def win_profile():
    """The Windows %USERPROFILE% as a WSL path (/mnt/c/Users/<you>), or "" without interop."""
    try:
        r = subprocess.run(["cmd.exe", "/c", "echo %USERPROFILE%"], capture_output=True, text=True, timeout=10,
                           cwd="/mnt/c")
        w = r.stdout.strip()
        return subprocess.run(["wslpath", "-u", w], capture_output=True, text=True, timeout=10).stdout.strip() if w else ""
    except (OSError, subprocess.SubprocessError):
        return ""


KIT = os.environ.get("AGENT_KIT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P2P_HOME = os.environ.get("P2P_HOME") or os.path.join(win_profile(), ".p2p")
STATE = os.path.expanduser("~/.agent-assist")
LOG = os.path.join(STATE, "assist.log")
KEYMAP = {"Up": "Up", "Down": "Down", "Left": "Left", "Right": "Right", "Enter": "Enter", "Esc": "esc",
          "Tab": "Tab", "Space": "Space", "BSpace": "Backspace", "y": "y", "n": "n",
          **{str(d): str(d) for d in range(10)}}
MAX_TOKENS, MAX_LINES, DEF_LINES, CAP = 20, 120, 40, 6000
ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
CHOICE_RE = re.compile(r"^\s*❯ \d+\. ")
DIALOG_HINTS = ("Enter to select", "Esc to cancel", "Ready to submit your answers?")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]|\x1b\[[0-9;?]*[A-Za-z]")


def log(msg):
    os.makedirs(STATE, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + msg + "\n")


def herdr(*args, timeout=20):
    r = subprocess.run(["herdr", "--session", SESSION, *args], capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"herdr {' '.join(args[:2])} failed: {(r.stderr or r.stdout).strip()[:200]}")
    return r.stdout


def panes():
    """[{pane, label, name, agent, status}] for session gony; agent names come from `agent list`."""
    names = {a["pane_id"]: a.get("name") or "" for a in json.loads(herdr("agent", "list"))["result"]["agents"]}
    out = []
    for p in json.loads(herdr("pane", "list"))["result"]["panes"]:
        out.append({"pane": p["pane_id"], "label": p.get("label") or "", "name": names.get(p["pane_id"], ""),
                    "agent": p.get("agent") or "", "status": p.get("agent_status") or ""})
    return out


def shows_dialog(pane):
    """True when the pane's last screen lines are a choice dialog: herdr reports some (e.g. a multi-question
    Submit screen) as "done", so the status alone would leave them stuck."""
    tail = herdr("pane", "read", pane).rstrip("\n").split("\n")[-16:]
    return any(CHOICE_RE.match(l) for l in tail) and any(h in l for l in tail for h in DIALOG_HINTS)


def find(target):
    hits = [p for p in panes() if target in (p["label"], p["name"]) and target]
    if len(hits) != 1:
        raise ValueError(f"target '{target}' matches {len(hits)} panes (use a label or agent name from LIST)")
    return hits[0]


def health():
    """windows/health.ps1 of this kit: the VERDICT line plus every WARN/FAIL line (one screen, read-only check)."""
    script = os.path.join(KIT, "windows", "health.ps1")
    win = subprocess.run(["wslpath", "-w", script], capture_output=True, text=True, timeout=10).stdout.strip()
    r = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", win],
                       capture_output=True, text=True, timeout=120, cwd="/mnt/c")
    lines = [l.rstrip() for l in (r.stdout or "").splitlines() if l.strip()]
    keep = [l for l in lines if l.startswith("VERDICT") or " WARN" in l or " FAIL" in l or l.startswith(("WARN", "FAIL"))]
    return "\n".join(keep) or f"health.ps1 gave no VERDICT (exit {r.returncode}): {(r.stderr or '').strip()[:200]}"


def handle(text):
    """Returns (id, ok, payload). Raises nothing: every failure becomes an error reply."""
    parts = text.split()
    rid = parts[1] if len(parts) > 1 and ID_RE.match(parts[1]) else "?"
    try:
        if len(parts) < 3 or rid == "?":
            raise ValueError("grammar: ASSIST <id> LIST | HEALTH | READ <target> [n] | KEYS <target> <tok>...")
        verb, rest = parts[2], parts[3:]
        if verb == "HEALTH" and not rest:
            log(f"{rid} HEALTH")
            return rid, True, health()
        if verb == "LIST" and not rest:
            log(f"{rid} LIST")
            return rid, True, "\n".join(f"{p['pane']} label={p['label'] or '-'} name={p['name'] or '-'} "
                                        f"agent={p['agent'] or '-'} status={p['status'] or '-'}" for p in panes())
        if verb == "READ" and 1 <= len(rest) <= 2:
            n = DEF_LINES
            if len(rest) == 2:
                if not rest[1].isdigit():
                    raise ValueError("READ n must be a number")
                n = max(1, min(MAX_LINES, int(rest[1])))
            p = find(rest[0])
            log(f"{rid} READ {p['pane']} ({rest[0]}) n={n}")
            if p["agent"]:
                txt = herdr("agent", "read", p["pane"], "--source", "visible", "--lines", str(n))
            else:
                txt = herdr("pane", "read", p["pane"])
            lines = txt.rstrip("\n").split("\n")[-n:]
            return rid, True, f"{p['pane']} {p['label']} ({p['status'] or 'no agent'}):\n" + "\n".join(lines)
        if verb == "KEYS" and len(rest) >= 2:
            toks = rest[1:]
            if len(toks) > MAX_TOKENS:
                raise ValueError(f"max {MAX_TOKENS} tokens")
            bad = [t for t in toks if t not in KEYMAP]
            if bad:
                raise ValueError(f"tokens not allowed: {' '.join(bad)} (allowed: {' '.join(KEYMAP)})")
            p = find(rest[0])
            if not (p["status"] == "blocked" or p["label"].startswith("assist-test")
                    or (p["agent"] and shows_dialog(p["pane"]))):
                raise ValueError(f"{p['pane']} {p['label']} is '{p['status'] or 'no agent'}', not blocked on a "
                                 "dialog: KEYS refused (only blocked agent panes, panes showing a choice dialog, "
                                 "or assist-test* panes)")
            log(f"{rid} KEYS {p['pane']} ({rest[0]}, {p['status']}) {' '.join(toks)}")
            for t in toks:   # one key per call: an unsupported key name stops before any later key is sent
                herdr("pane", "send-keys", p["pane"], KEYMAP[t])
                time.sleep(0.15)
            time.sleep(1.0)
            after = herdr("pane", "read", p["pane"]).rstrip("\n").split("\n")[-12:]
            return rid, True, f"sent {' '.join(toks)} to {p['pane']} {p['label']}; screen after:\n" + "\n".join(after)
        raise ValueError("grammar: ASSIST <id> LIST | HEALTH | READ <target> [n] | KEYS <target> <tok>...")
    except Exception as e:   # reply with the error; the log keeps it too
        log(f"{rid} ERROR {type(e).__name__}: {e}")
        return rid, False, f"{type(e).__name__}: {e}"


def reply(rid, ok, payload):
    body = CTRL_RE.sub("", f"LOG ASSIST-REPLY {rid} {'ok' if ok else 'error'} {payload}")[:CAP]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(body)
    try:
        r = subprocess.run(["bash", f"{KIT}/wsl/shai-send.sh", "--redact", "-f", f.name],
                           capture_output=True, text=True, timeout=120)
        log(f"{rid} reply {'ok' if ok else 'error'} {len(body)} chars -> shai-send exit {r.returncode} "
            f"{(r.stdout + r.stderr).strip()[:120]}")
    finally:
        os.unlink(f.name)


def mail_dir(name):
    try:
        with open(os.path.join(P2P_HOME, "tunnel", name, "current.json"), encoding="utf-8") as f:
            i = json.load(f).get("id", "")
        if re.fullmatch(r"[a-f0-9]{32}", i):
            return os.path.join(P2P_HOME, "tunnel", name, i)
    except (OSError, ValueError):
        pass
    return ""


def peer_of(d):
    try:
        with open(os.path.join(d, "session.json"), encoding="utf-8") as f:
            return json.load(f).get("share", "")
    except (OSError, ValueError):
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="", help="tunnel session (default: the only join-* session)")
    ap.add_argument("--every", type=float, default=2.0)
    a = ap.parse_args()
    if not a.name:
        try: joins = [n for n in os.listdir(os.path.join(P2P_HOME, "tunnel")) if n.startswith("join-")]
        except OSError: joins = []
        if len(joins) != 1:
            print(f"pane-assist: pass --name (join-* sessions found: {joins})", file=sys.stderr); sys.exit(2)
        a.name = joins[0]
    os.makedirs(STATE, exist_ok=True)
    lock = open(os.path.join(STATE, "assist.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("pane-assist: already running", file=sys.stderr); sys.exit(1)
    with open(os.path.join(STATE, "assist.pid"), "w") as f:
        f.write(str(os.getpid()))
    d, pos, buf, seen, peer = "", 0, b"", set(), ""
    log(f"START pid {os.getpid()} tunnel {a.name} session {SESSION}")
    while True:
        try: step_once = poll(a, d, pos, buf, seen, peer)
        except Exception as e:   # a vanished file or a slow drvfs must never end the helper
            log(f"POLL ERROR {type(e).__name__}: {e}"); time.sleep(a.every); continue
        d, pos, buf, peer = step_once
        time.sleep(a.every)


def poll(a, d, pos, buf, seen, peer):
    """One poll of the mailbox; returns the new (dir, offset, partial line, peer)."""
    nd = mail_dir(a.name)
    if nd != d:   # first poll or a new tunnel session: start at that mailbox's current end
        d, buf = nd, b""
        pos = os.path.getsize(os.path.join(d, "inbox.jsonl")) if d and os.path.exists(os.path.join(d, "inbox.jsonl")) else 0
        peer = peer_of(d) if d else ""
        log(f"MAILBOX {d or 'none'} from offset {pos}, peer {peer or '?'}")
    f = os.path.join(d, "inbox.jsonl") if d else ""
    if f and os.path.exists(f):
        size = os.path.getsize(f)
        if size < pos:
            pos, buf = size, b""
        elif size > pos:
            with open(f, "rb") as fh:
                fh.seek(pos); chunk = fh.read(size - pos)
            pos += len(chunk); buf += chunk
            *rows, buf = buf.split(b"\n")
            for raw in rows:
                try:
                    row = json.loads(raw)
                except ValueError:
                    continue
                text = row.get("text")
                if not isinstance(text, str) or not text.startswith("ASSIST "):
                    continue
                if row.get("channel", "chat") != "chat" or not peer or row.get("from") != peer:
                    log(f"IGNORED row {row.get('id')} from {row.get('from')} (not the pinned peer)")
                    continue
                if row.get("id") in seen:
                    continue
                seen.add(row.get("id"))
                reply(*handle(text.strip()))
    return d, pos, buf, peer


if __name__ == "__main__":
    main()
