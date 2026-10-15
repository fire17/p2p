"""Local exposure policy: which Codex threads may be reached at all. Edited ONLY by the local `pb` CLI.

~/.peerbridge/policy.json (0600):
  {"expose": "optin" | "all", "threads": [threadId...], "cwds": [abs path prefix...], "off": false}
- optin (default): a thread is reachable only if its id is listed or its cwd is under a listed prefix.
- all: every live Codex thread of this user is reachable (the owner chose it explicitly).
- off: kill switch. Nothing is reachable; the hub withdraws every peer row and refuses injection.
No network path or hub command can change this file: the hub only reads it.
"""
from __future__ import annotations

import json
import os

HOME = os.environ.get("PEERBRIDGE_HOME", os.path.join(os.path.expanduser("~"), ".peerbridge"))
PATH = os.path.join(HOME, "policy.json")
DEFAULT = {"expose": os.environ.get("PEERBRIDGE_DEFAULT_EXPOSE", "optin"), "threads": [], "cwds": [], "off": False}


def load() -> dict:
    try:
        with open(PATH) as f:
            p = json.load(f)
        return {**DEFAULT, **(p if isinstance(p, dict) else {})}
    except FileNotFoundError:
        return dict(DEFAULT)
    except Exception:
        return {**DEFAULT, "off": True, "error": "policy.json unreadable: failing closed"}


def save(p: dict) -> None:
    os.makedirs(HOME, exist_ok=True)
    tmp = f"{PATH}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({k: p[k] for k in ("expose", "threads", "cwds", "off") if k in p}, f, indent=1)
    os.replace(tmp, PATH)


def mtime() -> float:
    try:
        return os.stat(PATH).st_mtime
    except OSError:
        return 0.0


def _norm(path: str) -> str:
    return os.path.realpath(path or "").rstrip("/")


def allowed(thread_id: str, cwd: str | None, p: dict | None = None) -> bool:
    p = p or load()
    if p.get("off"):
        return False
    if p.get("expose") == "all":
        return True
    if thread_id in (p.get("threads") or []):
        return True
    c = _norm(cwd or "")
    for pre in p.get("cwds") or []:
        pre = _norm(pre)
        if c == pre or c.startswith(pre + "/"):
            return True
    return False
