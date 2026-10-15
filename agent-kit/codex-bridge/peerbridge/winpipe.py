"""Windows named-pipe transport for peerbridge (Claude Code 2.1.30x peer inbox on native Windows).

Claude Code on Windows (read from claude.exe 2.1.301):
  inbox     \\\\.\\pipe\\LOCAL\\cc-msg-<32 hex>, byte stream, first line MUST be {"type":"auth","token":...}
  key       ~/.claude/sessions/<pid>.<sha256(canonical)>.key, canonical = "\\\\.\\pipe\\" + lower("LOCAL\\cc-msg-<hex>")
  liveness  record/key carry procStartFt = process creation FILETIME (GetProcessTimes) as a decimal string
  sender    refuses an "unvouched" pipe (no key file whose owner pid is live with matching procStartFt);
            it does NOT check the pipe server's pid on Windows.
Stdlib + ctypes only; imported only when os.name == "nt".
"""
from __future__ import annotations

import ctypes
import os
import threading
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PIPE_ACCESS_DUPLEX = 0x3
PIPE_TYPE_BYTE = 0x0
PIPE_READMODE_BYTE = 0x0
PIPE_WAIT = 0x0
PIPE_REJECT_REMOTE_CLIENTS = 0x8
PIPE_UNLIMITED_INSTANCES = 255
ERROR_PIPE_CONNECTED = 535
ERROR_BROKEN_PIPE = 109
ERROR_MORE_DATA = 234
ERROR_PIPE_BUSY = 231
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

k32.CreateNamedPipeW.restype = wintypes.HANDLE
k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
k32.ConnectNamedPipe.restype = wintypes.BOOL
k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
k32.ReadFile.restype = wintypes.BOOL
k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
k32.WriteFile.restype = wintypes.BOOL
k32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
k32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
k32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]


def is_pipe(path: str) -> bool:
    p = (path or "").replace("/", "\\")
    return p.lower().startswith("\\\\.\\pipe\\") or p.lower().startswith("\\\\?\\pipe\\")


def canonical(path: str) -> str:
    """CC's GC(): '\\\\.\\pipe\\' + lowercased name after pipe\\ (single segment, optional LOCAL\\)."""
    p = path.replace("/", "\\")
    rest = p.split("\\pipe\\", 1)[1]
    return "\\\\.\\pipe\\" + rest.lower()


def new_inbox_name() -> str:
    return "\\\\.\\pipe\\LOCAL\\cc-msg-" + os.urandom(16).hex()


def proc_start_ft(pid: int) -> str:
    """Process creation time as a FILETIME decimal string (what CC 2.1.30x stores as procStartFt)."""
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        c, e, k, u = (wintypes.FILETIME() for _ in range(4))
        if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            return ""
        return str((c.dwHighDateTime << 32) | c.dwLowDateTime)
    finally:
        k32.CloseHandle(h)


def pipe_exists(path: str) -> bool:
    """Never open the pipe (that would consume a listening instance). First the pipe-namespace listing, then
    WaitNamedPipeW(1 ms): success or ERROR_SEM_TIMEOUT (121, all instances busy) both mean the pipe exists."""
    name = canonical(path).split("\\pipe\\", 1)[1]
    short = name.split("\\", 1)[1] if name.startswith("local\\") else name
    try:
        listed = {n.lower() for n in os.listdir("\\\\.\\pipe\\")}
        if name in listed or short in listed:
            return True
    except OSError:
        pass
    if k32.WaitNamedPipeW(path, 1):
        return True
    return ctypes.get_last_error() == 121


def write(path: str, data: bytes, timeout: float = 5.0) -> None:
    """Client side: open the pipe (retry while all instances are busy), write, close."""
    deadline = time.time() + timeout
    mode = "r+b"
    while True:
        try:
            with open(path, mode, buffering=0) as f:
                f.write(data)
                try:
                    f.flush()
                except OSError:
                    pass
            return
        except OSError as e:
            if getattr(e, "winerror", None) == ERROR_PIPE_BUSY and time.time() < deadline:
                k32.WaitNamedPipeW(path, 200)
                continue
            if getattr(e, "winerror", None) == 5 and mode == "r+b":  # inbound-only server: open write-only
                mode = "wb"
                continue
            raise


def replace_retry(tmp: str, path: str, tries: int = 50) -> None:
    """os.replace fails on Windows while another process holds the target open; retry briefly."""
    for i in range(tries):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if i == tries - 1:
                raise
            time.sleep(0.02)


class PipeServer:
    """Byte-mode duplex pipe server; always keeps one instance listening so connect probes succeed.
    on_conn(read_all_lines_iter, reply_fn) runs in its own thread per client."""

    def __init__(self, path: str, on_conn):
        self.path = path
        self.on_conn = on_conn
        self.stopped = False
        self._first = True

    def _create(self):
        flags = PIPE_ACCESS_DUPLEX | (0x00080000 if self._first else 0)  # FILE_FLAG_FIRST_PIPE_INSTANCE
        self._first = False
        h = k32.CreateNamedPipeW(self.path, flags, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                 PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, None)
        if h == INVALID_HANDLE_VALUE or not h:
            raise OSError(ctypes.get_last_error(), f"CreateNamedPipeW failed for {self.path}")
        return h

    def serve_forever(self) -> None:
        while not self.stopped:
            h = self._create()
            ok = k32.ConnectNamedPipe(h, None)
            if not ok and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                k32.CloseHandle(h)
                continue
            threading.Thread(target=self._client, args=(h,), daemon=True).start()

    def start(self) -> None:
        h = self._create()  # create the first instance synchronously so the name exists before we publish it
        self._pending = h
        threading.Thread(target=self._loop_with_first, daemon=True).start()

    def _loop_with_first(self) -> None:
        h = self._pending
        ok = k32.ConnectNamedPipe(h, None)
        if ok or ctypes.get_last_error() == ERROR_PIPE_CONNECTED:
            threading.Thread(target=self._client, args=(h,), daemon=True).start()
        else:
            k32.CloseHandle(h)
        self.serve_forever()

    def _reader(self, h):
        buf = ctypes.create_string_buffer(65536)
        n = wintypes.DWORD()
        while True:
            ok = k32.ReadFile(h, buf, 65536, ctypes.byref(n), None)
            if not ok:
                err = ctypes.get_last_error()
                if err == ERROR_MORE_DATA:
                    yield buf.raw[:n.value]
                    continue
                return
            if n.value == 0:
                return
            yield buf.raw[:n.value]

    def _client(self, h) -> None:
        def reply(data: bytes) -> None:
            w = wintypes.DWORD()
            k32.WriteFile(h, data, len(data), ctypes.byref(w), None)
            k32.FlushFileBuffers(h)
        try:
            self.on_conn(self._reader(h), reply)
        except Exception:
            pass
        finally:
            k32.DisconnectNamedPipe(h)
            k32.CloseHandle(h)

    def stop(self) -> None:
        self.stopped = True
        try:  # unblock the pending ConnectNamedPipe
            write(self.path, b"", timeout=0.5)
        except Exception:
            pass


def request(path: str, data: bytes, timeout: float = 20.0) -> bytes:
    """Request/response over a duplex pipe (hub control channel): write one line, read one line."""
    deadline = time.time() + timeout
    while True:
        try:
            f = open(path, "r+b", buffering=0)
            break
        except OSError as e:
            if getattr(e, "winerror", None) == ERROR_PIPE_BUSY and time.time() < deadline:
                k32.WaitNamedPipeW(path, 200)
                continue
            raise
    with f:
        f.write(data)
        out = b""
        while b"\n" not in out:
            chunk = f.read(65536)
            if not chunk:
                break
            out += chunk
        return out
