"""
services.py -- the simulated back-end services that clients reach through the proxy.

Every service is a plain TCP server written directly against the socket API
(socket -> bind -> listen -> accept, one thread per client):

    web    9001  HTTP/1.1 website with persistent (keep-alive) connections
    chat   9002  multi-user chat room, newline-delimited text protocol
    echo   9003  echoes every byte back; honours TCP half-close
    files  9004  tiny file server: LIST, GET <name>, QUIT
    bulk   9005  bulk-transfer service for the benchmarks:
                   DOWNLOAD <n>  -> sends n bytes of text, then closes
                   UPLOAD <n>    -> reads n bytes, replies "OK <n>"

The services trust whoever connects -- access control is the proxy's job.
They bind to 127.0.0.1 by default so the only way in is through the proxy.

    python services.py                    # all services on 127.0.0.1:9001-9005
    python services.py --host 0.0.0.0     # reachable from other machines
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import threading
import time
from datetime import datetime
from html import escape
from urllib.parse import parse_qs, urlsplit

DEFAULT_PORTS = {"web": 9001, "chat": 9002, "echo": 9003, "files": 9004, "bulk": 9005}


# --------------------------------------------------------------------------- server skeleton
class TCPService:
    """A minimal threaded TCP server built on the raw socket API."""

    def __init__(self, name: str, host: str, port: int, handler, quiet: bool = False):
        self.name, self.host, self.port = name, host, port
        self.handler = handler
        self.quiet = quiet
        self._stop = threading.Event()
        self._sock: socket.socket | None = None

    def start(self) -> "TCPService":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":                      # on Windows SO_REUSEADDR allows port hijacking
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(128)
        s.settimeout(0.5)                        # lets Ctrl+C / stop() interrupt accept()
        self._sock = s
        self.port = s.getsockname()[1]           # real port when started with port 0
        threading.Thread(target=self._accept_loop, name=f"svc-{self.name}", daemon=True).start()
        return self

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=self._run, args=(conn, addr), daemon=True).start()

    def _run(self, conn: socket.socket, addr):
        try:
            conn.settimeout(300)
            self.handler(conn, addr)
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        if self._sock:
            self._sock.close()


class LineReader:
    """Reads newline-terminated lines from a blocking socket (TCP is a byte stream)."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def readline(self, limit: int = 65536) -> bytes | None:
        while True:
            i = self.buf.find(b"\n")
            if i >= 0:
                line = bytes(self.buf[: i + 1])
                del self.buf[: i + 1]
                return line
            if len(self.buf) > limit:
                line = bytes(self.buf)
                self.buf.clear()
                return line
            data = self.sock.recv(65536)
            if not data:
                if self.buf:
                    line = bytes(self.buf)
                    self.buf.clear()
                    return line
                return None
            self.buf += data

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            data = self.sock.recv(65536)
            if not data:
                raise ConnectionError("peer closed early")
            self.buf += data
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


# --------------------------------------------------------------------------- web (HTTP/1.1)
_STYLE = (
    "body{font-family:Segoe UI,Helvetica,Arial,sans-serif;max-width:720px;margin:40px auto;"
    "padding:0 16px;color:#1d2433;line-height:1.5}nav a{margin-right:12px}"
    "h1{font-size:1.6em}code{background:#eef1f6;padding:1px 4px;border-radius:3px}"
    ".tag{font-size:.8em;color:#5c6b80}"
)


def _page(title: str, body: str, user: str) -> bytes:
    nav = " ".join(
        f'<a href="{p}">{p}</a>'
        for p in ("/", "/news", "/sports", "/social/feed", "/lucky", "/billing",
                  "/internal/report", "/admin/panel", "/downloads/")
    )
    who = escape(user) if user else "unknown (no proxy header)"
    html = (
        f"<!doctype html><html><head><meta charset='utf-8'><title>{escape(title)}</title>"
        f"<style>{_STYLE}</style></head><body><nav>{nav}</nav><h1>{escape(title)}</h1>{body}"
        f"<p class='tag'>SimWeb backend &middot; request seen as user: <b>{who}</b> &middot; "
        f"{datetime.now():%Y-%m-%d %H:%M:%S}</p></body></html>"
    )
    return html.encode("utf-8")


def _big_text(kb: int) -> bytes:
    line = b"The quick brown fox jumps over the lazy dog. netproxy benchmark filler text.\n"
    reps = (kb * 1024) // len(line) + 1
    return (line * reps)[: kb * 1024]


_FAKE_EXE = b"MZ" + b"\x90\x00\x03\x00" + b"\x00" * 58 + b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 400
_FAKE_PDF = b"%PDF-1.4\n% netproxy demo\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"


def web_route(method: str, target: str, headers: dict, body: bytes):
    """Return (status, reason, content_type, payload) for one request."""
    user = headers.get("x-authenticated-user", "")
    url = urlsplit(target)
    path, query = url.path, parse_qs(url.query)
    html = "text/html; charset=utf-8"

    if path == "/":
        return 200, "OK", html, _page("SimWeb home", (
            "<p>A small simulated website used to exercise the proxy's policies.</p><ul>"
            "<li><code>/news</code>, <code>/sports</code> &ndash; ordinary pages</li>"
            "<li><code>/social/feed</code> &ndash; blocked during working hours (rule R05)</li>"
            "<li><code>/lucky</code> &ndash; blocked-keyword page (content filter F01)</li>"
            "<li><code>/billing</code> &ndash; card numbers, masked in transit (F02)</li>"
            "<li><code>/internal/report</code> &ndash; staff-only internal report (F03)</li>"
            "<li><code>/admin/panel</code> &ndash; admin area, staff only (R04)</li>"
            "<li><code>/downloads/tool.exe</code> &ndash; executable download (F04)</li></ul>"), user)
    if path == "/news":
        return 200, "OK", html, _page("Campus news", (
            "<p>The networks lab moves to Room 101 next week. ISA-2 covers Units III and IV.</p>"
            "<p>Reminder: the socket-programming mini project demo is due before ISA-2.</p>"), user)
    if path == "/sports":
        return 200, "OK", html, _page("Sports", "<p>Inter-department cricket final this Saturday.</p>", user)
    if path in ("/social", "/social/feed"):
        return 200, "OK", html, _page("Social feed", (
            "<p>@aadi: shipping a TCP proxy today</p><p>@bob: who's up for chai at 4?</p>"), user)
    if path == "/lucky":
        return 200, "OK", html, _page("Lucky Spins", (
            "<p>Welcome to the best online casino! Sports betting and gambling, 24x7.</p>"), user)
    if path == "/billing":
        return 200, "OK", html, _page("Billing summary", (
            "<p>Card on file: 4111 1111 1111 1111 (exp 08/29)</p>"
            "<p>Backup card: 5500-0000-0000-0004</p><p>Amount due: Rs. 1,499</p>"), user)
    if path == "/internal/report":
        return 200, "OK", html, _page("Q3 internal report", (
            "<p><b>CONFIDENTIAL</b> &ndash; do not distribute.</p>"
            "<p>Lab budget: Rs. 4.2 lakh. Vendor card: 4012-8888-8888-1881.</p>"), user)
    if path in ("/admin", "/admin/panel") or path.startswith("/admin/"):
        return 200, "OK", html, _page("Admin panel", "<p>Server controls. Reset all passwords?</p>", user)
    if path in ("/downloads", "/downloads/"):
        return 200, "OK", html, _page("Downloads", (
            '<ul><li><a href="/downloads/notes.pdf">notes.pdf</a></li>'
            '<li><a href="/downloads/tool.exe">tool.exe</a></li></ul>'), user)
    if path == "/downloads/notes.pdf":
        return 200, "OK", "application/pdf", _FAKE_PDF
    if path == "/downloads/tool.exe":
        return 200, "OK", "application/x-msdownload", _FAKE_EXE
    if path == "/api/time":
        doc = {"time": datetime.now().isoformat(timespec="seconds"), "user": user or None}
        return 200, "OK", "application/json", json.dumps(doc).encode()
    if path == "/search":
        q = query.get("q", [""])[0]
        return 200, "OK", html, _page("Search", f"<p>No results for <b>{escape(q)}</b>.</p>", user)
    if path == "/echo" and method == "POST":
        return 200, "OK", "text/plain; charset=utf-8", body
    if path == "/big":
        try:
            kb = max(0, min(int(query.get("kb", ["64"])[0]), 102400))
        except ValueError:
            kb = 64
        return 200, "OK", "text/plain; charset=utf-8", _big_text(kb)
    return 404, "Not Found", html, _page("404 - not found", f"<p>No page at <code>{escape(path)}</code>.</p>", user)


def web_handler(conn: socket.socket, addr):
    reader = LineReader(conn)
    while True:
        # --- request line + headers
        start = reader.readline()
        while start in (b"\r\n", b"\n"):          # tolerate stray CRLFs between requests
            start = reader.readline()
        if not start:
            return
        try:
            method, target, version = start.decode("latin-1").strip().split(" ", 2)
        except ValueError:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        headers: dict[str, str] = {}
        while True:
            line = reader.readline()
            if line is None:
                return
            line = line.decode("latin-1").rstrip("\r\n")
            if not line:
                break
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        length = int(headers.get("content-length", "0") or 0)
        body = reader.read_exact(length) if length else b""

        status, reason, ctype, payload = web_route(method.upper(), target, headers, body)
        keep = headers.get("connection", "").lower() != "close" and version.upper() == "HTTP/1.1"
        out = (
            f"HTTP/1.1 {status} {reason}\r\nServer: SimWeb/1.0\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(payload)}\r\nConnection: {'keep-alive' if keep else 'close'}\r\n\r\n"
        ).encode("latin-1")
        conn.sendall(out if method.upper() == "HEAD" else out + payload)
        if not keep:
            return


# --------------------------------------------------------------------------- chat room
class ChatRoom:
    def __init__(self):
        self.lock = threading.Lock()
        self.members: dict[socket.socket, str] = {}
        self.counter = 0

    def broadcast(self, text: str, exclude: socket.socket | None = None):
        data = (text + "\n").encode("utf-8")
        with self.lock:
            targets = [s for s in self.members if s is not exclude]
        for s in targets:
            try:
                s.sendall(data)
            except OSError:
                self.leave(s)

    def leave(self, s: socket.socket) -> str | None:
        with self.lock:
            return self.members.pop(s, None)


ROOM = ChatRoom()


def chat_handler(conn: socket.socket, addr):
    with ROOM.lock:
        ROOM.counter += 1
        nick = f"user{ROOM.counter}"
        ROOM.members[conn] = nick
    conn.sendall(f"* Welcome to SimChat, {nick}. Commands: /nick NAME, /who, /quit\n".encode())
    ROOM.broadcast(f"* {nick} joined", exclude=conn)
    reader = LineReader(conn)
    try:
        while True:
            raw = reader.readline(4096)
            if raw is None:
                break
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                continue
            if text.startswith("/nick "):
                new = text[6:].strip()[:24] or nick
                with ROOM.lock:
                    ROOM.members[conn] = new
                ROOM.broadcast(f"* {nick} is now {new}")
                nick = new
            elif text == "/who":
                with ROOM.lock:
                    names = ", ".join(sorted(ROOM.members.values()))
                conn.sendall(f"* online: {names}\n".encode())
            elif text == "/quit":
                conn.sendall(b"* bye\n")
                break
            else:
                ROOM.broadcast(f"[{nick}] {text}")
    finally:
        if ROOM.leave(conn):
            ROOM.broadcast(f"* {nick} left")


# --------------------------------------------------------------------------- echo
def echo_handler(conn: socket.socket, addr):
    while True:
        data = conn.recv(65536)
        if not data:                     # client half-closed: finish echoing, then close our side
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            return
        conn.sendall(data)


# --------------------------------------------------------------------------- files
FILES = {
    "readme.txt": "Lab file server.\nUse LIST to see files and GET <name> to fetch one.\n",
    "timetable.txt": "Mon DSA 8-9, OS 9-10\nTue CN 8-10\nFri CN 10:30-12:30\n",
    "payroll.csv": (
        "name,role,card\n"
        "Asha,TA,4111 1111 1111 1111\n"
        "Ravi,Lab assistant,5500-0000-0000-0004\n"
        "Meera,Instructor,3400 0000 0000 0009\n"
    ),
    "memo.txt": (
        "From: Department office\n"
        "Subject: ISA-2 question paper\n"
        "CONFIDENTIAL - for faculty only.\n"
        "The paper is in the locked cabinet in Room 204.\n"
    ),
}


def files_handler(conn: socket.socket, addr):
    conn.sendall(b"+OK SimFiles ready. Commands: LIST, GET <name>, QUIT\n")
    reader = LineReader(conn)
    while True:
        raw = reader.readline(4096)
        if raw is None:
            return
        cmd, _, arg = raw.decode("utf-8", "replace").strip().partition(" ")
        cmd = cmd.upper()
        if cmd == "LIST":
            listing = "".join(f"{name} {len(body)}\n" for name, body in sorted(FILES.items()))
            conn.sendall(f"+OK {len(FILES)} files\n{listing}.\n".encode())
        elif cmd == "GET":
            body = FILES.get(arg.strip())
            if body is None:
                conn.sendall(f"-ERR no such file: {arg.strip()}\n".encode())
            else:
                conn.sendall(f"+OK {len(body)} bytes\n{body}.\n".encode())
        elif cmd == "QUIT":
            conn.sendall(b"+OK bye\n")
            return
        elif cmd:
            conn.sendall(b"-ERR unknown command\n")


# --------------------------------------------------------------------------- bulk (benchmarks)
_BULK_LINE = b"netproxy bulk transfer payload, constant text for throughput testing 0123456789\n"


def bulk_handler(conn: socket.socket, addr):
    reader = LineReader(conn)
    raw = reader.readline(256)
    if not raw:
        return
    cmd, _, arg = raw.decode("ascii", "replace").strip().partition(" ")
    try:
        n = max(0, min(int(arg), 2 * 1024 ** 3))
    except ValueError:
        conn.sendall(b"-ERR usage: DOWNLOAD <bytes> | UPLOAD <bytes>\n")
        return
    if cmd.upper() == "DOWNLOAD":
        block = _BULK_LINE * (65536 // len(_BULK_LINE))
        sent = 0
        while sent < n:
            chunk = block[: n - sent]
            conn.sendall(chunk)
            sent += len(chunk)
        conn.shutdown(socket.SHUT_WR)
        # wait for the client to close so the last bytes are not lost to a RST
        try:
            while conn.recv(65536):
                pass
        except OSError:
            pass
    elif cmd.upper() == "UPLOAD":
        got = len(reader.buf)
        reader.buf.clear()
        while got < n:
            data = conn.recv(65536)
            if not data:
                break
            got += len(data)
        conn.sendall(f"OK {got}\n".encode())
    else:
        conn.sendall(b"-ERR usage: DOWNLOAD <bytes> | UPLOAD <bytes>\n")


HANDLERS = {"web": web_handler, "chat": chat_handler, "echo": echo_handler,
            "files": files_handler, "bulk": bulk_handler}


def start_services(host: str = "127.0.0.1", ports: dict | None = None, quiet: bool = False) -> dict:
    """Start every service; returns {name: TCPService}. Port 0 picks a free port."""
    ports = {**DEFAULT_PORTS, **(ports or {})}
    return {name: TCPService(name, host, ports[name], HANDLERS[name], quiet).start() for name in HANDLERS}


def main():
    ap = argparse.ArgumentParser(description="Run the simulated back-end services.")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    ap.add_argument("--base-port", type=int, default=9001, help="first port (default 9001)")
    args = ap.parse_args()
    ports = {name: args.base_port + i for i, name in enumerate(DEFAULT_PORTS)}
    services = start_services(args.host, ports)
    print("Simulated services running (Ctrl+C to stop):")
    for name, svc in services.items():
        print(f"  {name:<6} {svc.host}:{svc.port}")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nstopping services")
        for svc in services.values():
            svc.stop()


if __name__ == "__main__":
    main()
