"""
netproxy.httpmsg -- just enough HTTP/1.1 (RFC 9110/9112) for a filtering proxy.

The proxy speaks HTTP in two places:
  * the CONNECT handshake that opens a tunnel to a service, and
  * inside http-inspected sessions, where it parses every request and
    response so it can apply per-path rules and inspect bodies.

Parsing is deliberately strict: ambiguous framing (both Content-Length and
Transfer-Encoding, conflicting lengths, whitespace before ':') is rejected,
because those ambiguities are what request-smuggling attacks exploit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html import escape
from typing import List, Optional, Tuple

_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
              "te", "trailer", "transfer-encoding", "upgrade"}


class HttpError(Exception):
    def __init__(self, status: int, reason: str, detail: str = ""):
        super().__init__(f"{status} {reason}: {detail}" if detail else f"{status} {reason}")
        self.status, self.reason, self.detail = status, reason, detail


class TooLarge(Exception):
    """A header block or body exceeded the configured limit."""


@dataclass
class HttpHead:
    start: Tuple[str, str, str]                       # (method, target, version) or (version, status, reason)
    headers: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def status(self) -> int:
        return int(self.start[1])

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return default

    def get_all(self, name: str) -> List[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def set(self, name: str, value: str):
        self.remove(name)
        self.headers.append((name, value))

    def remove(self, name: str):
        name = name.lower()
        self.headers = [(k, v) for k, v in self.headers if k.lower() != name]

    def to_bytes(self) -> bytes:
        lines = [" ".join(self.start)] + [f"{k}: {v}" for k, v in self.headers]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")


def _parse_headers(lines: List[str]) -> List[Tuple[str, str]]:
    headers = []
    for line in lines:
        if not line:
            continue
        if line[0] in " \t":
            raise HttpError(400, "Bad Request", "obsolete header folding is not allowed")
        name, sep, value = line.partition(":")
        if not sep or not _TOKEN.match(name):
            raise HttpError(400, "Bad Request", f"malformed header line {line[:40]!r}")
        headers.append((name, value.strip()))
    return headers


def _split_lines(raw: bytes) -> List[str]:
    text = raw.decode("latin-1")
    text = text.lstrip("\r\n")                         # RFC 9112: ignore empty lines before a request
    return text.replace("\r\n", "\n").rstrip("\n").split("\n")


def parse_request_head(raw: bytes) -> HttpHead:
    lines = _split_lines(raw)
    parts = lines[0].split(" ")
    if len(parts) != 3 or not _TOKEN.match(parts[0]) or not re.fullmatch(r"HTTP/1\.[01]", parts[2]):
        raise HttpError(400, "Bad Request", f"malformed request line {lines[0][:60]!r}")
    return HttpHead((parts[0].upper(), parts[1], parts[2]), _parse_headers(lines[1:]))


def parse_response_head(raw: bytes) -> HttpHead:
    lines = _split_lines(raw)
    m = re.fullmatch(r"(HTTP/1\.[01]) (\d{3})(?: (.*))?", lines[0])
    if not m:
        raise HttpError(502, "Bad Gateway", f"malformed status line from service {lines[0][:60]!r}")
    return HttpHead((m.group(1), m.group(2), m.group(3) or ""), _parse_headers(lines[1:]))


def wants_keep_alive(head: HttpHead) -> bool:
    tokens = {t.strip().lower() for v in head.get_all("Connection") for t in v.split(",")}
    is_response = head.start[0].startswith("HTTP/")
    version = head.start[0] if is_response else head.start[2]
    if "close" in tokens:
        return False
    if version == "HTTP/1.0":
        return "keep-alive" in tokens
    return True


def body_framing(head: HttpHead, kind: str, request_method: str = "GET") -> Tuple[str, int]:
    """How the message body is delimited: ('none'|'length'|'chunked'|'close', length)."""
    if kind == "response":
        status = head.status
        if request_method == "HEAD" or 100 <= status < 200 or status in (204, 304):
            return "none", 0
    te = [t.strip().lower() for v in head.get_all("Transfer-Encoding") for t in v.split(",") if t.strip()]
    cls = head.get_all("Content-Length")
    if te and cls:
        raise HttpError(400, "Bad Request", "both Transfer-Encoding and Content-Length (possible smuggling)")
    if te:
        if te[-1] != "chunked":
            if kind == "request":
                raise HttpError(400, "Bad Request", "unsupported Transfer-Encoding")
            return "close", 0
        return "chunked", 0
    if cls:
        values = {v.strip() for c in cls for v in c.split(",")}
        if len(values) != 1 or not next(iter(values)).isdigit():
            raise HttpError(400, "Bad Request", "invalid or conflicting Content-Length")
        return "length", int(next(iter(values)))
    return ("close", 0) if kind == "response" else ("none", 0)


def read_body(channel, head: HttpHead, kind: str, limit: int, request_method: str = "GET") -> bytes:
    """Read a complete message body from a Channel according to its framing."""
    mode, length = body_framing(head, kind, request_method)
    if mode == "none":
        return b""
    if mode == "length":
        if length > limit:
            raise TooLarge(f"body of {length} bytes exceeds limit {limit}")
        return channel.read_exact(length) if length else b""
    if mode == "close":
        return channel.read_to_eof(limit)
    body = bytearray()                                 # chunked transfer coding
    while True:
        line = channel.read_until(b"\r\n", 1024)
        if line is None:
            raise HttpError(502, "Bad Gateway", "connection closed inside a chunked body")
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            raise HttpError(400, "Bad Request", "bad chunk size") from None
        if size == 0:
            while True:                                # optional trailers end with an empty line
                trailer = channel.read_until(b"\r\n", 8192)
                if trailer in (None, b"\r\n"):
                    break
            return bytes(body)
        if len(body) + size > limit:
            raise TooLarge(f"chunked body exceeds limit {limit}")
        body += channel.read_exact(size)
        channel.read_exact(2)


def split_absolute_uri(target: str) -> Tuple[str, str]:
    """'http://web:80/news?x=1' -> ('web:80', '/news?x=1')"""
    m = re.fullmatch(r"(?i)http://([^/?#\s]+)([^\s#]*)(?:#.*)?", target)
    if not m:
        raise HttpError(400, "Bad Request", "malformed absolute URI")
    authority, rest = m.group(1), m.group(2) or "/"
    if "@" in authority:
        raise HttpError(400, "Bad Request", "credentials in URI are not allowed")
    if rest.startswith("?"):
        rest = "/" + rest
    return authority, rest


def forward_headers(headers: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Drop hop-by-hop headers (and any listed in Connection) before forwarding."""
    listed = {t.strip().lower() for k, v in headers if k.lower() == "connection" for t in v.split(",")}
    return [(k, v) for k, v in headers
            if k.lower() not in HOP_BY_HOP and k.lower() not in listed and k.lower() != "content-length"]


def simple_response(status: int, reason: str, body: bytes = b"", content_type: str = "text/plain; charset=utf-8",
                    extra: Optional[dict] = None, close: bool = True) -> bytes:
    head = [f"HTTP/1.1 {status} {reason}", "Server: netproxy"]
    for k, v in (extra or {}).items():
        head.append(f"{k}: {v}")
    if status != 200 or body:
        head += [f"Content-Type: {content_type}", f"Content-Length: {len(body)}"]
    if close:
        head.append("Connection: close")
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1", "replace") + body


def block_page(status: int, title: str, reason: str, rule: str, user: str, where: str) -> bytes:
    """The HTML page a browser shows when the proxy refuses a request."""
    color = "#b42318" if status in (403, 429) else "#8a6d00"
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Blocked by netproxy</title><style>"
        "body{font-family:Segoe UI,Helvetica,Arial,sans-serif;background:#f6f7f9;margin:0;padding:48px 16px}"
        ".card{max-width:560px;margin:auto;background:#fff;border:1px solid #dde1e7;border-radius:10px;"
        f"padding:28px 32px}}h1{{margin:0 0 6px;color:{color};font-size:22px}}"
        "table{border-collapse:collapse;margin-top:16px;font-size:14px}"
        "td{padding:4px 14px 4px 0;vertical-align:top}td:first-child{color:#5c6b80}"
        "</style></head><body><div class='card'>"
        f"<h1>{status} &middot; {escape(title)}</h1><p>{escape(reason)}</p><table>"
        f"<tr><td>Rule</td><td><code>{escape(rule)}</code></td></tr>"
        f"<tr><td>User</td><td>{escape(user)}</td></tr>"
        f"<tr><td>Request</td><td>{escape(where)}</td></tr>"
        "</table></div></body></html>"
    ).encode("utf-8")
