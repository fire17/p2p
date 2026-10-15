"""Claude Code peer-mesh protocol (peerProtocol 1), stdlib only.

Wire facts (observed live on CC 2.1.261 and 2.1.281):
  registry   ~/.claude/sessions/<pid>.json, listed while <pid> is alive and its socket exists
  inbox      Unix socket at messagingSocketPath, bound by THAT pid (senders check LOCAL_PEERPID)
  key        ~/.claude/sessions/<pid>.<sha256(socketPath)>.key = {peerToken, procStart, pidDomain}, 0600
  frames     NDJSON; optional first line {"type":"auth","token"}; user frame carries a
             <cross-session-message from= from-name= from-mode=> envelope; control frames carry `action`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import uuid

HOME = os.path.expanduser("~")
SESSIONS_DIR = os.environ.get("PEERBRIDGE_SESSIONS_DIR", os.path.join(HOME, ".claude", "sessions"))
STATE_DIR = os.environ.get("PEERBRIDGE_HOME", os.path.join(HOME, ".peerbridge"))
TAG = "cross-session-message"
WINDOWS = os.name == "nt"
if WINDOWS:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import winpipe  # noqa: E402
else:
    winpipe = None


def socks_dir() -> str:
    """Where CC on this machine puts peer sockets: follow the live registry, else CC's defaults."""
    if os.environ.get("PEERBRIDGE_SOCKS_DIR"):
        return os.environ["PEERBRIDGE_SOCKS_DIR"]
    if WINDOWS:
        return "\\\\.\\pipe\\LOCAL"
    seen: dict[str, int] = {}
    try:
        for f in os.listdir(SESSIONS_DIR):
            if f.endswith(".json") and f[:-5].isdigit():
                try:
                    p = json.load(open(os.path.join(SESSIONS_DIR, f))).get("messagingSocketPath", "")
                except Exception:
                    continue
                if p:
                    d = os.path.dirname(p)
                    seen[d] = seen.get(d, 0) + 1
    except FileNotFoundError:
        pass
    if seen:
        return max(seen, key=seen.get)
    if sys.platform == "darwin":
        return "/tmp/cc-socks"
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    return os.path.join(xdg, "cc-socks") if xdg and os.path.isdir(xdg) else "/tmp/cc-socks"


def key_path(pid: int, sock: str) -> str:
    canon = winpipe.canonical(sock) if (WINDOWS and winpipe.is_pipe(sock)) else sock
    return os.path.join(SESSIONS_DIR, f"{pid}.{hashlib.sha256(canon.encode()).hexdigest()}.key")


def start_field() -> str:
    """Record/key field CC uses for process start: procStartFt (FILETIME) on Windows, procStart elsewhere."""
    return "procStartFt" if WINDOWS else "procStart"


def sock_exists(path: str) -> bool:
    if WINDOWS and winpipe.is_pipe(path):
        return winpipe.pipe_exists(path)
    return os.path.exists(path)


def full_ref(sock: str) -> str:
    return hashlib.sha256(f"session:{sock}".encode()).hexdigest()[:12]


def proc_start(pid: int) -> str:
    if WINDOWS:
        return winpipe.proc_start_ft(pid)
    return _proc_start_unix(pid)


def _proc_start_unix(pid: int) -> str:
    """Same string CC stores and re-checks: `LC_ALL=C TZ=UTC ps -o lstart=`. Local time here hides the row
    (CC 2.1.281 treats a procStart mismatch as a recycled pid and drops the record from ListAgents)."""
    try:
        env = dict(os.environ, LC_ALL="C", TZ="UTC")
        out = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, timeout=5, env=env).stdout.strip()
        if out:
            return out
    except Exception:
        pass
    return ""


def pid_alive(pid: int) -> bool:
    if os.name == "nt":  # os.kill(pid, 0) TERMINATES the process on Windows
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(h)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def pid_domain() -> str:
    """CC's pvo(): "darwin" on macOS, "<linux|wsl>:<machine-id>:<pid-ns>" on Linux/WSL."""
    if sys.platform == "darwin":
        return "darwin"
    if WINDOWS:
        import socket as _s
        return f"win32:{_s.gethostname().lower()}"
    if sys.platform.startswith("linux"):
        try:
            wsl = "microsoft" in open("/proc/version").read().lower()
        except OSError:
            wsl = False
        try:
            mid = open("/etc/machine-id").read().strip()
        except OSError:
            mid = ""
        try:
            ns = os.readlink("/proc/self/ns/pid")
        except OSError:
            ns = ""
        return f"{'wsl' if wsl else 'linux'}:{mid}:{ns}"
    return sys.platform


def attr(v: str) -> str:
    """CC's own from-name normaliser (vqe/zh in 2.1.281): drop "<> and Cc/Cf/Cs/Zl/Zp, trim, cap 64 code points.
    Anything else makes CC's round-trip check fail and the whole envelope (incl. from-mode) is ignored."""
    import unicodedata
    v = re.sub(r'["<>]', "", v)
    v = "".join(ch for ch in v if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Zl", "Zp")).strip()
    return v[:64] + "\u2026" if len(v) > 64 else v


FROM_RE = re.compile(r"^[A-Za-z0-9%:_/.\\\-]{1,300}$")  # CC's charset incl. backslash (Windows pipe addresses)
NEST_RE = re.compile(r"<(?=/?cross-session-message)", re.I)


def envelope(text: str, frm: str, from_name: str | None, from_mode: str | None) -> str:
    if not FROM_RE.match(frm):
        raise ValueError(f"invalid from address {frm!r}")
    a = [f'from="{frm}"']
    if from_name and attr(from_name):
        a.append(f'from-name="{attr(from_name)}"')
    if from_mode in ("bypass", "prompting"):
        a.append(f'from-mode="{from_mode}"')
    body = NEST_RE.sub(lambda m: "<\\", text)  # CC's lae(): neutralise nested openers/closers as "<\\"
    return f"<{TAG} {' '.join(a)}>\n{body}\n</{TAG}>"


ENV_RE = re.compile(rf"^<{TAG}\b([^>]*)>\n?([\s\S]*?)\n?</{TAG}>\s*$")


def parse_envelope(content: str) -> dict:
    m = ENV_RE.match(content)
    if not m:
        return {"text": content}
    attrs = dict(re.findall(r'([a-z-]+)="([^"]*)"', m.group(1)))
    return {"text": m.group(2), "from": attrs.get("from"), "from_name": attrs.get("from-name"),
            "from_mode": attrs.get("from-mode")}


def user_frame(frm: str, env: str, session_id: str | None = None, msg_id: str | None = None) -> dict:
    f = {"msgV": 1, "msg_id": msg_id or str(uuid.uuid4()), "type": "user",
         "message": {"role": "user", "content": env}, "priority": "next", "from": frm}
    if session_id:
        f["session_id"] = session_id
    return f


def control(action: str, frm: str, **kw) -> dict:
    return {"type": "control", "action": action, "from": frm, "msgV": 1, "msg_id": str(uuid.uuid4()), **kw}


# ---- discovery -------------------------------------------------------------------------
def records() -> list[dict]:
    """Every live registry record (pid alive + socket present), newest first."""
    out = []
    try:
        names = os.listdir(SESSIONS_DIR)
    except FileNotFoundError:
        return out
    for f in names:
        m = re.match(r"^(\d+)\.json$", f)
        if not m:
            continue
        pid = int(m.group(1))
        if not pid_alive(pid):
            continue
        try:
            r = json.load(open(os.path.join(SESSIONS_DIR, f)))
        except Exception:
            continue
        sock = r.get("messagingSocketPath")
        if not isinstance(sock, str) or not sock_exists(sock):
            continue
        r["pid"] = pid
        r["address"] = f"uds:{sock}"
        r["ref"] = full_ref(sock)
        r.setdefault("name", f"session-{pid}")
        out.append(r)
    out.sort(key=lambda r: r.get("startedAt") or 0, reverse=True)
    return out


def resolve(to: str, recs: list[dict] | None = None) -> list[dict]:
    """Match a target the way CC users write it: name, `name [ref]`, uds:address, ref prefix, sessionId."""
    recs = records() if recs is None else recs
    to = to.strip()
    m = re.match(r"^(.*?)\s*\[([0-9a-f]{4,12})\]$", to)
    if m:
        return [r for r in recs if r["name"] == m.group(1) and r["ref"].startswith(m.group(2))]
    if to.startswith("uds:") or to.startswith("/"):
        addr = to if to.startswith("uds:") else f"uds:{to}"
        return [r for r in recs if r["address"] == addr]
    exact = [r for r in recs if r.get("name") == to or r.get("sessionId") == to]
    if exact:
        return exact
    lower = [r for r in recs if str(r.get("name", "")).lower() == to.lower()]
    if lower:
        return lower
    if re.fullmatch(r"[0-9a-f]{6,12}", to):
        return [r for r in recs if r["ref"].startswith(to)]
    return []


def read_token(rec: dict) -> str | None:
    """The target's peer token, used only to authenticate to that same socket. Never logged or stored."""
    sock = rec["messagingSocketPath"]
    try:
        k = json.load(open(key_path(rec["pid"], sock)))
    except Exception:
        k = None
    if k is None:  # older layout: any <pid>.*.key whose procStart matches the record
        try:
            for f in os.listdir(SESSIONS_DIR):
                if f.startswith(f"{rec['pid']}.") and f.endswith(".key"):
                    c = json.load(open(os.path.join(SESSIONS_DIR, f)))
                    if c.get(start_field()) == rec.get(start_field()):
                        k = c
                        break
        except Exception:
            pass
    f = "procStartFt" if (k or {}).get("procStartFt") is not None else "procStart"
    if not k or k.get(f) != rec.get(f):
        return None
    t = k.get("peerToken")
    return t if isinstance(t, str) else None


def write_frames(sock_path: str, frames: list[dict], token: str | None, timeout: float = 5.0) -> None:
    """Connect, (auth), write NDJSON lines, close. Raises on failure."""
    data = ""
    if token:
        data += json.dumps({"type": "auth", "token": token}) + "\n"
    data += "".join(json.dumps(f, ensure_ascii=False) + "\n" for f in frames)
    if WINDOWS and winpipe.is_pipe(sock_path):
        return winpipe.write(sock_path, data.encode("utf-8"), timeout)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        s.sendall(data.encode("utf-8"))
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    finally:
        s.close()


def send_to(rec: dict, frames: list[dict]) -> None:
    write_frames(rec["messagingSocketPath"], frames, read_token(rec))


def send_to_address(address: str, frames: list[dict]) -> None:
    """Reply path for receipts / idle notices: look the address up in the registry for its token."""
    for r in records():
        if r["address"] == address:
            return send_to(r, frames)
    path = address[4:] if address.startswith("uds:") else address
    write_frames(path, frames, None)
