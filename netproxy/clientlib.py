"""
netproxy.clientlib -- client side: open tunnels through the proxy, speak HTTP
inside them, and talk to the admin console. Used by client.py, adminctl.py,
demo.py, benchmark.py and the tests.
"""
from __future__ import annotations

import select
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import ROOT
from .tlsutil import SERVER_NAME, client_context

CERT_DIR = ROOT / "certs"


class ProxyRefused(Exception):
    """The proxy answered the CONNECT with something other than 200."""

    def __init__(self, status: int, reason: str, rule: str, detail: str, body: bytes = b""):
        super().__init__(f"{status} {reason} (rule {rule}): {detail}")
        self.status, self.reason, self.rule, self.detail, self.body = status, reason, rule, detail, body


class Reader:
    """Buffered reads on a blocking socket (with timeout)."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def _more(self) -> bool:
        data = self.sock.recv(65536)
        if not data:
            return False
        self.buf += data
        return True

    def read_until(self, delim: bytes, limit: int = 1 << 20) -> bytes:
        while True:
            i = self.buf.find(delim)
            if i >= 0:
                out = bytes(self.buf[: i + len(delim)])
                del self.buf[: i + len(delim)]
                return out
            if len(self.buf) > limit or not self._more():
                raise ConnectionError("connection closed before the expected data arrived")

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._more():
                raise ConnectionError("connection closed in the middle of a message")
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_to_eof(self) -> bytes:
        try:
            while self._more():
                pass
        except (OSError, ssl.SSLError):
            pass
        out = bytes(self.buf)
        self.buf.clear()
        return out

    def take(self) -> bytes:
        out = bytes(self.buf)
        self.buf.clear()
        return out


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: Dict[str, str]
    body: bytes

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def read_response(reader: Reader, method: str = "GET") -> HttpResponse:
    head = reader.read_until(b"\r\n\r\n").decode("latin-1")
    lines = head.rstrip("\r\n").split("\r\n")
    version, _, rest = lines[0].partition(" ")
    status_s, _, reason = rest.partition(" ")
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    status = int(status_s)
    if method == "HEAD" or status in (204, 304) or 100 <= status < 200 or (method == "CONNECT" and status // 100 == 2):
        body = b""                                        # a 2xx answer to CONNECT starts the tunnel, no body
    elif "content-length" in headers:
        body = reader.read_exact(int(headers["content-length"]))
    elif headers.get("transfer-encoding", "").lower().endswith("chunked"):
        body = bytearray()
        while True:
            size = int(reader.read_until(b"\r\n").split(b";")[0].strip(), 16)
            if size == 0:
                while reader.read_until(b"\r\n") != b"\r\n":
                    pass
                break
            body += reader.read_exact(size)
            reader.read_exact(2)
        body = bytes(body)
    else:
        body = reader.read_to_eof()
    return HttpResponse(status, reason, headers, body)


class Tunnel:
    """An open CONNECT tunnel to one service."""

    def __init__(self, sock: socket.socket, reader: Reader, response: HttpResponse, service: str,
                 timeout: float = 10.0):
        self.sock, self.reader, self.response, self.service = sock, reader, response, service
        self._timeout = timeout
        self.rule = response.header("x-proxy-rule")
        self.inspect = response.header("x-proxy-inspect")
        self.user = response.header("x-proxy-user")

    # --- HTTP inside the tunnel
    def request(self, method: str, path: str, body: bytes = b"", headers: Optional[dict] = None) -> HttpResponse:
        supplied = {str(k).lower() for k in (headers or {})}
        lines = [f"{method} {path} HTTP/1.1"]
        if "host" not in supplied:
            lines.append(f"Host: {self.service}")
        lines.append("User-Agent: netproxy-client/1.0")
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        if body or method in ("POST", "PUT"):
            lines.append(f"Content-Length: {len(body)}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
        return read_response(self.reader, method)

    def get(self, path: str) -> HttpResponse:
        return self.request("GET", path)

    # --- raw / line services
    def send(self, data: bytes):
        self.sock.sendall(data)

    def send_line(self, text: str):
        self.sock.sendall(text.encode("utf-8") + b"\n")

    def recv_for(self, quiet: float = 0.4, total: float = 5.0) -> bytes:
        """Collect everything that arrives until the line has been quiet for `quiet` seconds."""
        out = bytearray(self.reader.take())
        deadline = time.monotonic() + total
        self.sock.settimeout(quiet)
        try:
            while time.monotonic() < deadline:
                try:
                    data = self.sock.recv(65536)
                except (socket.timeout, ssl.SSLWantReadError):
                    break
                if not data:
                    break
                out += data
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.sock.settimeout(self._timeout)
        return bytes(out)

    def recv_until(self, needle: bytes, timeout: float = 5.0) -> bytes:
        """Read until `needle` appears (or the connection closes / times out)."""
        out = bytearray(self.reader.take())
        deadline = time.monotonic() + timeout
        try:
            while needle not in out and time.monotonic() < deadline:
                self.sock.settimeout(max(0.05, deadline - time.monotonic()))
                try:
                    data = self.sock.recv(65536)
                except socket.timeout:
                    break
                if not data:
                    break
                out += data
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.sock.settimeout(self._timeout)
        return bytes(out)

    def is_closed(self, timeout: float = 2.0) -> bool:
        """True if the proxy closes the connection within `timeout` (reads and discards data)."""
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                self.sock.settimeout(max(0.05, deadline - time.monotonic()))
                try:
                    if not self.sock.recv(65536):
                        return True
                except socket.timeout:
                    return False
        except (OSError, ssl.SSLError):
            return True
        finally:
            try:
                self.sock.settimeout(self._timeout)
            except OSError:
                pass
        return False

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class ProxyClient:
    """Connects to the proxy (TLS by default), optionally with a client certificate."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8443, *, tls: bool = True, user: Optional[str] = None,
                 ca: Optional[str] = None, cert: Optional[str] = None, key: Optional[str] = None,
                 cert_dir: Path = CERT_DIR, server_name: str = SERVER_NAME, timeout: float = 10.0):
        self.host, self.port, self.tls, self.user = host, port, tls, user
        self.server_name, self.timeout = server_name, timeout
        self.ctx = None
        if tls:
            if user and not cert:
                cert = str(Path(cert_dir) / "clients" / f"{user}.crt")
                key = str(Path(cert_dir) / "clients" / f"{user}.key")
            self.ctx = client_context(ca or str(Path(cert_dir) / "ca.crt"), cert, key)

    def raw_connect(self) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.ctx is not None:
            s = self.ctx.wrap_socket(s, server_hostname=self.server_name)
        return s

    def connect(self, service: str) -> Tunnel:
        sock = self.raw_connect()
        reader = Reader(sock)
        try:
            sock.sendall(f"CONNECT {service} HTTP/1.1\r\nHost: {service}\r\nUser-Agent: netproxy-client/1.0\r\n\r\n"
                         .encode("latin-1"))
            resp = read_response(reader, "CONNECT")
        except Exception:
            sock.close()
            raise
        if resp.status != 200:
            sock.close()
            raise ProxyRefused(resp.status, resp.reason, resp.header("x-proxy-rule", "?"),
                               resp.header("x-proxy-reason", resp.text.strip()), resp.body)
        return Tunnel(sock, reader, resp, service, self.timeout)

    def forward(self, url: str, method: str = "GET", body: bytes = b"") -> HttpResponse:
        """One absolute-form request (forward-proxy mode, like a browser or curl -x)."""
        sock = self.raw_connect()
        try:
            host = url.split("//", 1)[1].split("/", 1)[0]
            lines = [f"{method} {url} HTTP/1.1", f"Host: {host}", "Connection: close"]
            if body:
                lines.append(f"Content-Length: {len(body)}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
            return read_response(Reader(sock), method)
        finally:
            sock.close()


# --------------------------------------------------------------------------- admin console client
class AdminClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 9443, token: str = "", ca: Optional[str] = None,
                 server_name: str = SERVER_NAME, timeout: float = 10.0):
        ctx = client_context(ca or str(CERT_DIR / "ca.crt"))
        raw = socket.create_connection((host, port), timeout=timeout)
        self.sock = ctx.wrap_socket(raw, server_hostname=server_name)
        self.reader = Reader(self.sock)
        self.banner = self._read_reply()
        if token:
            ok, text = self.command(f"AUTH {token}")
            if not ok:
                raise PermissionError(text)

    def _read_reply(self) -> Tuple[bool, str]:
        lines: List[str] = []
        while True:
            line = self.reader.read_until(b"\n").decode("utf-8").rstrip("\r\n")
            if line == ".":
                break
            lines.append(line[1:] if line.startswith("..") else line)
        first = lines[0] if lines else "ERR"
        ok = first.startswith("OK")
        lines[0] = first[3:] if ok else first[4:]
        return ok, "\n".join(lines).strip("\n")

    def command(self, text: str) -> Tuple[bool, str]:
        self.sock.sendall(text.encode("utf-8") + b"\n")
        return self._read_reply()

    def close(self):
        try:
            self.sock.sendall(b"QUIT\n")
        except OSError:
            pass
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def duplex_exchange(sock: socket.socket, payload: bytes, expect: int, initial: bytes = b"",
                    timeout: float = 60.0) -> bytes:
    """Send payload while receiving `expect` bytes, in one thread.

    A TLS socket must not be read and written from two threads at once, so a
    full-duplex transfer (e.g. through the echo service) uses select() instead.
    """
    sock.setblocking(False)
    view, got = memoryview(payload), bytearray(initial)
    deadline = time.monotonic() + timeout
    try:
        while len(got) < expect:
            if time.monotonic() > deadline:
                raise TimeoutError(f"received {len(got)} of {expect} bytes")
            progressed = False
            while True:
                try:
                    data = sock.recv(65536)
                except (ssl.SSLWantReadError, BlockingIOError):
                    break
                if not data:
                    return bytes(got)
                got += data
                progressed = True
            if view:
                try:
                    n = sock.send(view[:65536])
                    view = view[n:]
                    progressed = True
                except (ssl.SSLWantWriteError, ssl.SSLWantReadError, BlockingIOError):
                    pass
            if not progressed:
                select.select([sock], [sock] if view else [], [], 0.1)
    finally:
        sock.setblocking(True)
    return bytes(got)


def nb_send_all(sock: socket.socket, data: bytes, timeout: float = 30.0):
    """sendall() for a non-blocking (possibly TLS) socket."""
    view = memoryview(data)
    deadline = time.monotonic() + timeout
    while view:
        try:
            n = sock.send(view)
            view = view[n:]
            continue
        except (ssl.SSLWantWriteError, BlockingIOError):
            r, w = [], [sock]
        except ssl.SSLWantReadError:
            r, w = [sock], []
        if time.monotonic() > deadline:
            raise TimeoutError("send timed out")
        select.select(r, w, [], 0.25)
