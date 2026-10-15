"""Minimal JSON-RPC client for the shared local Codex app-server daemon.

The daemon (`codex app-server --listen unix:// --managed-daemon`, auto-started by every Codex
TUI since `daemon_auto_start`) speaks JSON-RPC over WebSocket text frames. We reach it either
through `codex app-server proxy` (byte relay over stdio; Codex picks the OS transport, so this
is the portable path) or straight over the control Unix socket. Stdlib only.
"""
from __future__ import annotations

import base64
import json
import os
import queue
import shutil
import socket
import struct
import subprocess
import threading
import time
from typing import Any, Callable

CODEX_HOME = os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")
CONTROL_SOCK = os.path.join(CODEX_HOME, "app-server-control", "app-server-control.sock")


class _Stream:
    """Byte stream over either a socket or a subprocess's stdio."""

    def __init__(self, mode: str, codex_bin: str | None = None):
        self.mode = mode
        # shutil.which resolves codex.cmd / codex.exe on Windows, where Popen does not search PATHEXT
        codex_bin = codex_bin or os.environ.get("PEERBRIDGE_CODEX_BIN") or shutil.which("codex") or "codex"
        if mode == "unix":
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(CONTROL_SOCK)
            self.proc = None
        else:
            self.sock = None
            self.proc = subprocess.Popen([codex_bin, "app-server", "proxy"], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

    def write(self, b: bytes) -> None:
        if self.sock:
            self.sock.sendall(b)
        else:
            self.proc.stdin.write(b)
            self.proc.stdin.flush()

    def read(self, n: int) -> bytes:
        if self.sock:
            return self.sock.recv(n)
        return self.proc.stdout.read1(n) if hasattr(self.proc.stdout, "read1") else os.read(self.proc.stdout.fileno(), n)

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
            else:
                self.proc.terminate()
        except Exception:
            pass


class CodexRPC:
    """One WebSocket JSON-RPC connection. Notifications go to `on_notify(method, params)`."""

    def __init__(self, on_notify: Callable[[str, dict], None] | None = None, mode: str | None = None,
                 client_name: str = "peerbridge", version: str = "0.1.0"):
        self.on_notify = on_notify or (lambda m, p: None)
        self.on_server_request: Callable[[dict], Any] | None = None
        mode = mode or os.environ.get("PEERBRIDGE_CODEX_TRANSPORT") or (
            "unix" if hasattr(socket, "AF_UNIX") and os.path.exists(CONTROL_SOCK) else "proxy")
        self.mode = mode
        self.s = _Stream(mode)
        self._buf = b""
        self._next = 1
        self._pending: dict[int, queue.Queue] = {}
        self._lock = threading.Lock()
        self.closed = threading.Event()
        self._handshake()
        threading.Thread(target=self._reader, daemon=True, name="cxrpc-reader").start()
        self.init = self.call("initialize", {"clientInfo": {"name": client_name, "version": version},
                                             "capabilities": {"experimentalApi": True}})
        self.notify("initialized")

    # ---- websocket framing -------------------------------------------------------------
    def _handshake(self) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.write((f"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        while b"\r\n\r\n" not in self._buf:
            chunk = self.s.read(4096)
            if not chunk:
                raise ConnectionError("codex app-server closed during websocket handshake")
            self._buf += chunk
        head, _, self._buf = self._buf.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise ConnectionError(f"websocket upgrade refused: {head[:200]!r}")

    def _send_frame(self, payload: bytes, opcode: int = 1) -> None:
        mask = os.urandom(4)
        n = len(payload)
        hdr = bytes([0x80 | opcode])
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        with self._lock:
            self.s.write(hdr + mask + masked)

    def _need(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.s.read(65536)
            if not chunk:
                raise ConnectionError("codex app-server connection closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _read_message(self) -> bytes | None:
        parts: list[bytes] = []
        while True:
            b0, b1 = self._need(2)
            fin, opcode = b0 & 0x80, b0 & 0x0F
            n = b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._need(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._need(8))[0]
            mask = self._need(4) if b1 & 0x80 else None
            data = self._need(n)
            if mask:
                data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
            if opcode == 8:
                return None
            if opcode == 9:
                self._send_frame(data, 10)
                continue
            if opcode == 10:
                continue
            parts.append(data)
            if fin:
                return b"".join(parts)

    def _reader(self) -> None:
        try:
            while True:
                raw = self._read_message()
                if raw is None:
                    break
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                if "id" in msg and ("result" in msg or "error" in msg):
                    q = self._pending.pop(msg["id"], None)
                    if q:
                        q.put(msg)
                elif "id" in msg and "method" in msg:
                    self._answer_server_request(msg)
                elif "method" in msg:
                    try:
                        self.on_notify(msg["method"], msg.get("params") or {})
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            self.closed.set()
            for q in list(self._pending.values()):
                q.put({"error": {"message": "connection closed"}})

    def _answer_server_request(self, msg: dict) -> None:
        # We never own approvals: the TUI that owns the thread answers them. Decline politely.
        result = self.on_server_request(msg) if self.on_server_request else None
        if result is None:
            self._send({"id": msg["id"], "error": {"code": -32601, "message": "peerbridge does not handle server requests"}})
        else:
            self._send({"id": msg["id"], "result": result})

    # ---- json-rpc --------------------------------------------------------------------
    def _send(self, obj: dict) -> None:
        self._send_frame(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def notify(self, method: str, params: dict | None = None) -> None:
        obj: dict = {"method": method}
        if params is not None:
            obj["params"] = params
        self._send(obj)

    def call(self, method: str, params: dict | None = None, timeout: float = 15.0) -> Any:
        with self._lock:
            rid = self._next
            self._next += 1
        q: queue.Queue = queue.Queue(1)
        self._pending[rid] = q
        self._send({"id": rid, "method": method, "params": params or {}})
        try:
            msg = q.get(timeout=timeout)
        except queue.Empty:
            self._pending.pop(rid, None)
            raise TimeoutError(f"{method} timed out after {timeout}s")
        if "error" in msg:
            raise RPCError(method, msg["error"])
        return msg["result"]

    def close(self) -> None:
        self.s.close()


class RPCError(Exception):
    def __init__(self, method: str, err: dict):
        super().__init__(f"{method}: {err.get('message', err)}")
        self.err = err


if __name__ == "__main__":
    import sys
    rpc = CodexRPC(on_notify=lambda m, p: print(f"[{time.strftime('%T')}] notify {m} {json.dumps(p)[:300]}", flush=True))
    print("transport", rpc.mode, "init", json.dumps(rpc.init)[:300])
    for arg in sys.argv[1:]:
        method, _, params = arg.partition(" ")
        try:
            print(method, "=>", json.dumps(rpc.call(method, json.loads(params) if params.strip() else {}))[:2000])
        except Exception as e:
            print(method, "!!", e)
    if os.environ.get("LISTEN"):
        time.sleep(float(os.environ["LISTEN"]))
