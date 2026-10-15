"""One Claude-Code peer endpoint for one Codex thread.

Its own process because CC's sender checks that the socket's owner pid (LOCAL_PEERPID / SO_PEERCRED)
is the pid in the registry record, and the record file is named <pid>.json.

Config arrives as JSON in env PEERBRIDGE_STUB. Talks to the hub over stdio, one JSON object per line:
  stub -> hub   {"ev":"ready","pid","address","ref"} | {"ev":"frame","frame":{...}} | {"ev":"auth_fail"}
  hub  -> stub  {"cmd":"status","status":"idle|busy|waiting"} | {"cmd":"name","name"} | {"cmd":"exit"}
                | {"cmd":"send","req","path","frames":[...],"token"}  -> {"ev":"sent","req","ok","error"?}
  Every outbound frame leaves through the stub: CC pins receipts and idle notices to the pid that connected.
stdin EOF (hub gone) = unregister and exit, so a dead hub never leaves ghost peers.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ccpeer  # noqa: E402

MAX_LINE = 1 << 20
cfg = json.loads(os.environ["PEERBRIDGE_STUB"])
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdin.reconfigure(encoding="utf-8")
except Exception:
    pass
PID = os.getpid()
SOCKS = ccpeer.socks_dir()
WINDOWS = ccpeer.WINDOWS
SOCK = ccpeer.winpipe.new_inbox_name() if WINDOWS else os.path.join(SOCKS, f"{PID}.sock")
REC = os.path.join(ccpeer.SESSIONS_DIR, f"{PID}.json")
KEY = ccpeer.key_path(PID, SOCK)
REQUIRE_AUTH = os.environ.get("PEERBRIDGE_REQUIRE_AUTH", "1") != "0"
TOKEN = secrets.token_hex(16)
out_lock = threading.Lock()
rec_lock = threading.Lock()



def _replace(tmp: str, path: str) -> None:
    if os.name == "nt":
        import winpipe
        return winpipe.replace_retry(tmp, path)
    os.replace(tmp, path)

def emit(obj: dict) -> None:
    with out_lock:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def atomic_write(path: str, data: str, mode: int = 0o600) -> None:
    tmp = f"{path}.{PID}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    _replace(tmp, path)


now_ms = lambda: int(time.time() * 1000)  # noqa: E731
started = now_ms()
procstart = ccpeer.proc_start(PID)
record = {
    "pid": PID, "sessionId": cfg["threadId"], "cwd": cfg.get("cwd") or "", "startedAt": cfg.get("startedAt") or started,
    ccpeer.start_field(): procstart, "version": f"peerbridge/{cfg.get('version', '0.1.0')} codex/{cfg.get('codexVersion', '?')}",
    "peerProtocol": 1, "peerFeatures": ["notify_idle", "reply_across_default_dirs"], "kind": "interactive", "entrypoint": "codex",
    "pidDomain": ccpeer.pid_domain(),
    "messagingSocketPath": SOCK, "name": cfg["name"], "nameSource": cfg.get("nameSource", "derived"),
    "nameSince": started, "status": cfg.get("status", "idle"), "updatedAt": started, "statusUpdatedAt": started,
    "bridgeSessionId": None, "harness": "codex", "codexThreadId": cfg["threadId"],
}
if cfg.get("tmux"):
    record["tmux"] = cfg["tmux"]


def write_record() -> None:
    with rec_lock:
        atomic_write(REC, json.dumps(record), 0o644)


def cleanup() -> None:
    for p in (REC, KEY) if WINDOWS else (REC, KEY, SOCK):
        try:
            os.unlink(p)
        except OSError:
            pass


def socket_chunks(conn: socket.socket):
    conn.settimeout(30)
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return
            yield chunk
    except (socket.timeout, OSError):
        return
    finally:
        conn.close()


def handle_conn(conn: socket.socket) -> None:
    handle_stream(socket_chunks(conn))


def handle_stream(chunks) -> None:
    """Shared by Unix sockets and Windows pipes: NDJSON, optional/required auth on the first line."""
    buf = b""
    authed = not REQUIRE_AUTH
    first = True
    try:
        for chunk in chunks:
            buf += chunk
            if len(buf) > MAX_LINE:
                emit({"ev": "oversize"})
                break
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    frame = json.loads(line)
                except Exception:
                    if first and REQUIRE_AUTH:
                        return
                    continue
                if first:
                    first = False
                    if isinstance(frame, dict) and frame.get("type") == "auth":
                        tok = frame.get("token")
                        if isinstance(tok, str) and hmac.compare_digest(tok, TOKEN):
                            authed = True
                        else:
                            emit({"ev": "auth_fail"})
                            return
                        continue
                if not authed:
                    emit({"ev": "auth_fail"})
                    return
                emit({"ev": "frame", "frame": frame})
    except OSError:
        pass


def do_send(cmd: dict) -> None:
    try:
        ccpeer.write_frames(cmd["path"], cmd["frames"], cmd.get("token"))
        emit({"ev": "sent", "req": cmd.get("req"), "ok": True})
    except Exception as e:
        emit({"ev": "sent", "req": cmd.get("req"), "ok": False, "error": f"{type(e).__name__}: {e}"})


def serve(srv: socket.socket) -> None:
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()


def main() -> None:
    os.makedirs(ccpeer.SESSIONS_DIR, exist_ok=True)
    if WINDOWS:
        srv = ccpeer.winpipe.PipeServer(SOCK, lambda chunks, reply: handle_stream(chunks))
        srv.start()  # the first instance exists before the record is published
    else:
        os.makedirs(SOCKS, mode=0o700, exist_ok=True)
        try:
            os.unlink(SOCK)
        except OSError:
            pass
        old = os.umask(0o077)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(SOCK)
        os.umask(old)
        os.chmod(SOCK, 0o600)
        srv.listen(64)
        threading.Thread(target=serve, args=(srv,), daemon=True).start()
    atomic_write(KEY, json.dumps({"peerToken": TOKEN, ccpeer.start_field(): procstart, "pidDomain": record["pidDomain"]}), 0o600)
    write_record()
    emit({"ev": "ready", "pid": PID, "address": f"uds:{SOCK}", "ref": ccpeer.full_ref(SOCK), "procStart": procstart})
    try:
        for line in sys.stdin:
            try:
                cmd = json.loads(line)
            except Exception:
                continue
            c = cmd.get("cmd")
            if c == "exit":
                break
            t = now_ms()
            if c == "status" and cmd.get("status") in ("idle", "busy", "waiting", "shell"):
                if record["status"] != cmd["status"]:
                    record.update(status=cmd["status"], updatedAt=t, statusUpdatedAt=t)
                    write_record()
            elif c == "send":
                threading.Thread(target=do_send, args=(cmd,), daemon=True).start()
            elif c == "name" and cmd.get("name"):
                record.update(name=cmd["name"], nameSource=cmd.get("nameSource", "user"), nameSince=t, updatedAt=t)
                write_record()
    finally:
        try:
            srv.stop() if WINDOWS else srv.close()
        except OSError:
            pass
        cleanup()


if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGTERM, lambda *_: (cleanup(), os._exit(0)))
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda *_: (cleanup(), os._exit(0)))
    try:
        main()
    finally:
        cleanup()
