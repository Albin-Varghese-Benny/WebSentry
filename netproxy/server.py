"""
netproxy.server -- the proxy itself.

Life of a connection (one thread per client):

  1. accept()        TCP connection from a client, TCP_NODELAY on
  2. TLS handshake   server certificate; optional client certificate -> identity
  3. admit           per-identity concurrent-connection cap and rate limit
  4. request head    either  "CONNECT <service> HTTP/1.1"      (tunnel mode)
                     or      "GET http://<service>/path HTTP/1.1" (forward-proxy mode)
  5. policy check    connect-stage rules; 403 Forbidden if denied
  6. connect()       to the back-end service; 200 Connection Established
  7. relay           according to the service's inspect mode:
                       none -> byte-for-byte relay (fastest)
                       line -> stream reassembled into lines, filters on every line
                       http -> every request/response parsed; per-request rules,
                               body filters, mime filters, HTML block pages
  8. close           access-log summary (bytes, duration, reason)

All socket I/O after the handshake is non-blocking and multiplexed with
select(), with a 250 ms tick, so a session reacts to cancellation (an admin
KILL, or a policy change that now denies it) almost immediately -- even when
it is idle.
"""
from __future__ import annotations

import logging
import os
import select
import socket
import ssl
import threading
import time
from typing import Dict, Optional
from urllib.parse import unquote_plus

from . import httpmsg
from .config import ProxyConfig
from .filters import FilterOutcome, StreamInspector, check_mime, inspect_bytes
from .httpmsg import HttpError, TooLarge
from .policy import ANONYMOUS, Context, Decision, Policy, PolicyStore, Service, normalize_path
from .registry import ConnInfo, Registry
from .tlsutil import peer_common_name, server_context

log = logging.getLogger("netproxy")

BUFSIZE = 64 * 1024
LINE_FLUSH_DELAY = 0.15          # seconds an unterminated line may wait before it is inspected and sent


class Terminated(Exception):
    """The session was cancelled: admin KILL, policy change or a content block."""


class IdleTimeout(Exception):
    pass


class PeerClosed(Exception):
    pass


# =========================================================================== socket channel
class Channel:
    """A non-blocking socket (plain TCP or TLS) with a read buffer.

    Reads try recv() first and only then wait in select(): an SSLSocket can hold
    already-decrypted bytes that select() cannot see, so asking the socket
    first avoids stalling on data that has in fact arrived.
    """
    TICK = 0.1                    # max delay before a cancelled session notices (select timeout)

    def __init__(self, sock: socket.socket, cancel: threading.Event, idle_timeout: float,
                 write_timeout: float = 30.0, on_rx=None):
        self.sock = sock
        sock.setblocking(False)
        self.cancel = cancel
        self.idle_timeout = idle_timeout
        self.write_timeout = write_timeout
        self.on_rx = on_rx                        # byte counter callback
        self.buf = bytearray()
        self.eof = False

    def _recv_nowait(self) -> Optional[bytes]:
        """bytes, b'' at end of stream, or None when nothing is available yet."""
        if self.eof:
            return b""
        try:
            data = self.sock.recv(BUFSIZE)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError, InterruptedError):
            return None
        except (OSError, ssl.SSLError):           # reset, aborted, TLS EOF without close_notify ...
            data = b""
        if not data:
            self.eof = True
        elif self.on_rx:
            self.on_rx(len(data))
        return data

    def try_recv(self) -> Optional[bytes]:
        if self.buf:
            data = bytes(self.buf)
            self.buf.clear()
            return data
        return self._recv_nowait()

    def wait_recv(self, timeout: Optional[float] = None) -> bytes:
        limit = self.idle_timeout if timeout is None else timeout
        deadline = time.monotonic() + limit
        while True:
            data = self._recv_nowait()
            if data is not None:
                return data
            if self.cancel.is_set():
                raise Terminated()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IdleTimeout(f"nothing received for {limit:g}s")
            try:
                select.select([self.sock], [], [], min(self.TICK, remaining))
            except (OSError, ValueError):
                return b""

    def read_until(self, delim: bytes, limit: int, timeout: Optional[float] = None) -> Optional[bytes]:
        """Bytes up to and including delim; None if the peer closed before sending anything."""
        scan = 0
        while True:
            i = self.buf.find(delim, scan)
            if i >= 0:
                end = i + len(delim)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            if len(self.buf) > limit:
                raise TooLarge(f"more than {limit} bytes without {delim!r}")
            scan = max(0, len(self.buf) - len(delim) + 1)
            data = self.wait_recv(timeout)
            if not data:
                if self.buf.strip():
                    raise PeerClosed("connection closed in the middle of a message")
                self.buf.clear()
                return None
            self.buf += data

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            data = self.wait_recv()
            if not data:
                raise PeerClosed("connection closed in the middle of a body")
            self.buf += data
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_to_eof(self, limit: int) -> bytes:
        while True:
            data = self.wait_recv()
            if not data:
                break
            self.buf += data
            if len(self.buf) > limit:
                raise TooLarge(f"body exceeds limit {limit}")
        out = bytes(self.buf)
        self.buf.clear()
        return out

    def send_all(self, data: bytes):
        view = memoryview(data)
        deadline = time.monotonic() + self.write_timeout
        while view:
            try:
                n = self.sock.send(view)
                if n:
                    view = view[n:]
                    deadline = time.monotonic() + self.write_timeout
                continue
            except (ssl.SSLWantWriteError, BlockingIOError, InterruptedError):
                rlist, wlist = [], [self.sock]
            except ssl.SSLWantReadError:
                rlist, wlist = [self.sock], []
            except (OSError, ssl.SSLError) as e:
                raise PeerClosed(f"send failed: {e}") from None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IdleTimeout("peer stopped reading (write timed out)")
            select.select(rlist, wlist, [], min(self.TICK, remaining))

    def shutdown_write(self):
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except (OSError, ValueError):
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# =========================================================================== one client session
class ClientSession:
    def __init__(self, server: "ProxyServer", sock: socket.socket, addr, tls: bool):
        self.server = server
        self.cfg: ProxyConfig = server.cfg
        self.store: PolicyStore = server.store
        self.registry: Registry = server.registry
        self.raw = sock
        self.tls = tls
        self.info: ConnInfo = self.registry.new_conn(addr[0], addr[1], "tls" if tls else "plain")
        self.client: Optional[Channel] = None
        self.backends: Dict[str, Channel] = {}
        self.close_reason = "closed"
        self._filter_cache: dict = {}
        self._filter_version = -1

    @property
    def policy(self) -> Policy:
        return self.store.policy

    # ------------------------------------------------------------------ top level
    def run(self):
        c = self.info
        try:
            sock = self._handshake()
            if sock is None:
                return
            self.client = Channel(sock, c.cancel, self.cfg.idle_timeout, on_rx=self._count_up)
            ok, why = self.registry.admit(c, self.policy.limits)
            if not ok:
                self.close_reason = "rate limited"
                self._log_decision("connect", Decision(False, "LIMIT", why))
                self.client.send_all(httpmsg.simple_response(429, "Too Many Requests", (why + "\n").encode(),
                                                             extra={"X-Proxy-Rule": "LIMIT", "Retry-After": "10"}))
                return
            self._serve()
        except Terminated:
            self.close_reason = f"terminated: {c.kill_reason}" if c.kill_reason else "terminated"
        except IdleTimeout as e:
            self.close_reason = f"timeout: {e}"
        except PeerClosed as e:
            self.close_reason = f"peer closed: {e}"
        except Exception as e:                                             # pragma: no cover
            log.exception("#%d internal error", c.id)
            self.close_reason = f"internal error: {e!r}"
        finally:
            self._cleanup()

    def _handshake(self) -> Optional[socket.socket]:
        c = self.info
        if not self.tls:
            c.tls = "plain"
            return self.raw
        self.raw.settimeout(self.cfg.handshake_timeout)
        try:
            ssock = self.server.tls_ctx.wrap_socket(self.raw, server_side=True, do_handshake_on_connect=False)
            self.raw = ssock
            ssock.do_handshake()
        except (ssl.SSLError, OSError) as e:
            self.close_reason = f"TLS handshake failed: {e}"
            self.registry.count("tls_failures")
            log.info("#%d %s TLS handshake failed: %s", c.id, c.src, e)
            return None
        c.tls = ssock.version() or "TLS"
        c.cipher = (ssock.cipher() or ("-",))[0]
        cn = peer_common_name(ssock)
        if cn and cn != ANONYMOUS:
            c.user = cn
        return ssock

    def _serve(self):
        c = self.info
        try:
            raw = self.client.read_until(b"\r\n\r\n", self.cfg.max_header_bytes, timeout=self.cfg.handshake_timeout)
        except TooLarge:
            self._send_status(431, "Request Header Fields Too Large", "request head too large", "PROTOCOL")
            return
        if raw is None:
            self.close_reason = "client sent no request"
            return
        try:
            head = httpmsg.parse_request_head(raw)
        except HttpError as e:
            self._send_status(e.status, e.reason, e.detail, "PROTOCOL")
            return
        method, target, _ = head.start
        if method == "CONNECT":
            self._connect(head)
        elif target.lower().startswith("http://"):
            c.mode = "forward"
            c.state = "active"
            self._http_session(None, first=head)
        else:
            self._send_status(400, "Bad Request",
                              "send 'CONNECT <service> HTTP/1.1' or an absolute 'http://<service>/path' request",
                              "PROTOCOL")

    # ------------------------------------------------------------------ CONNECT (tunnel mode)
    def _connect(self, head: httpmsg.HttpHead):
        c = self.info
        c.mode = "tunnel"
        target = head.start[1]
        svc = self.policy.resolve_service(target)
        if svc is None:
            c.service = target[:64]
            dec = Decision(False, "UNKNOWN_SERVICE", f"'{target}' is not a registered service")
        else:
            c.service, c.inspect = svc.name, svc.inspect
            dec = self.policy.evaluate(Context(c.user, c.src, svc.name), stage="connect")
        self._log_decision("connect", dec)
        if not dec.allowed:
            self.close_reason = f"denied by {dec.rule_id}"
            self._send_status(403, "Forbidden", dec.reason, dec.rule_id)
            return
        backend = self._open_backend(svc)
        if backend is None:
            self.close_reason = "service unreachable"
            self._send_status(502, "Bad Gateway", f"service '{svc.name}' is unreachable", "UPSTREAM")
            return
        self.client.send_all(httpmsg.simple_response(
            200, "Connection Established",
            extra={"X-Proxy-Rule": dec.rule_id, "X-Proxy-User": c.user, "X-Proxy-Inspect": svc.inspect},
            close=False))
        c.state = "active"
        if svc.inspect == "http":
            self.backends[svc.name] = backend
            self._http_session(svc)
        else:
            self._relay(backend, svc)

    def _open_backend(self, svc: Service) -> Optional[Channel]:
        try:
            s = socket.create_connection((svc.host, svc.port), timeout=self.cfg.connect_timeout)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            log.warning("#%d cannot reach service %s at %s:%d: %s", self.info.id, svc.name, svc.host, svc.port, e)
            self.registry.count("upstream_failures")
            return None
        return Channel(s, self.info.cancel, self.cfg.backend_timeout, on_rx=self._count_down)

    def _count_up(self, n: int):
        self.info.bytes_up += n

    def _count_down(self, n: int):
        self.info.bytes_down += n

    # ------------------------------------------------------------------ byte-stream relay (none / line)
    def _relay(self, backend: Channel, svc: Service):
        c, client = self.info, self.client
        line_mode = svc.inspect == "line"
        up = StreamInspector(lambda: self._filters(svc.name, "request")) if line_mode else None
        down = StreamInspector(lambda: self._filters(svc.name, "response")) if line_mode else None
        self.backends["_relay"] = backend
        client_open = True
        drain_deadline = None
        last_activity = time.monotonic()

        while True:
            if c.cancel.is_set():
                if line_mode:
                    self._notice(c.kill_reason)
                raise Terminated()
            progressed = False

            if client_open:                                   # client -> service
                data = client.try_recv()
                if data is not None:
                    progressed = True
                    if data:
                        self._pass(data, up, backend, "request", svc)
                    else:                                     # client finished sending (half-close)
                        if up:
                            self._deliver(up.finish(), backend, "request", svc)
                        backend.shutdown_write()
                        client_open = False
                        drain_deadline = time.monotonic() + 5.0

            data = backend.try_recv()                         # service -> client
            if data is not None:
                progressed = True
                if data:
                    self._pass(data, down, client, "response", svc)
                else:
                    if down:
                        self._deliver(down.finish(), client, "response", svc)
                    self.close_reason = "service closed the connection"
                    return

            now = time.monotonic()
            if progressed:
                last_activity = now
                continue
            wait = Channel.TICK
            for insp, dst, direction in ((up, backend, "request"), (down, client, "response")):
                if insp is not None and insp.has_partial:
                    age = now - insp.last_feed
                    if age >= LINE_FLUSH_DELAY:
                        self._deliver(insp.flush_partial(), dst, direction, svc)
                    else:
                        wait = min(wait, LINE_FLUSH_DELAY - age)
            if drain_deadline and now > drain_deadline:
                self.close_reason = "client closed the connection"
                return
            if now - last_activity > self.cfg.idle_timeout:
                raise IdleTimeout(f"session idle for {self.cfg.idle_timeout:g}s")
            socks = [backend.sock] + ([client.sock] if client_open else [])
            try:
                select.select(socks, [], [], max(wait, 0.005))
            except (OSError, ValueError):
                return

    def _pass(self, data: bytes, insp: Optional[StreamInspector], dst: Channel, direction: str, svc: Service):
        if insp is None:
            dst.send_all(data)
        else:
            self._deliver(insp.feed(data), dst, direction, svc)

    def _deliver(self, outcome: FilterOutcome, dst: Channel, direction: str, svc: Service):
        if outcome.hits:
            self._record_hits(outcome.hits, direction, svc.name)
        if outcome.data:
            dst.send_all(outcome.data)
        if outcome.blocked:
            f = outcome.blocked
            self.info.kill(f"content filter {f.id}: {f.reason}", f.id)
            self._notice(self.info.kill_reason)
            raise Terminated()

    def _notice(self, reason: str):
        """Tell a line-protocol client why its session is ending."""
        try:
            self.client.send_all(f"\n*** netproxy: connection terminated - {reason} ***\n".encode("utf-8"))
        except (PeerClosed, IdleTimeout, OSError):
            pass

    # ------------------------------------------------------------------ HTTP-aware session
    def _http_session(self, fixed: Optional[Service], first: Optional[httpmsg.HttpHead] = None):
        c = self.info
        head = first
        while True:
            if head is None:
                if c.cancel.is_set():
                    raise Terminated()
                try:
                    raw = self.client.read_until(b"\r\n\r\n", self.cfg.max_header_bytes)
                except TooLarge:
                    self._http_refuse(None, 431, "Request Header Fields Too Large", "request head too large",
                                      "PROTOCOL", keep=False)
                    return
                if raw is None:
                    self.close_reason = "client closed the connection"
                    return
                try:
                    head = httpmsg.parse_request_head(raw)
                except HttpError as e:
                    self._http_refuse(None, e.status, e.reason, e.detail, "PROTOCOL", keep=False)
                    return
            keep = self._http_exchange(head, fixed)
            head = None
            if not keep:
                self.close_reason = "request handled, connection closed"
                return

    def _http_exchange(self, head: httpmsg.HttpHead, fixed: Optional[Service]) -> bool:
        """Handle one request/response. Returns True to keep the client connection open."""
        c = self.info
        method, target, _ = head.start
        keep = httpmsg.wants_keep_alive(head)
        try:
            body = httpmsg.read_body(self.client, head, "request", self.cfg.max_body_bytes)
        except HttpError as e:
            return self._http_refuse(head, e.status, e.reason, e.detail, "PROTOCOL", keep=False)
        except TooLarge as e:
            return self._http_refuse(head, 413, "Payload Too Large", str(e), "PROTOCOL", keep=False)
        c.requests += 1

        # --- which service and path?
        if method == "CONNECT":
            return self._http_refuse(head, 400, "Bad Request", "CONNECT inside a tunnel is not allowed", "PROTOCOL", False)
        authority = fixed.name if fixed else ""
        domain = ""
        try:
            if target.lower().startswith("http://"):
                authority, path = httpmsg.split_absolute_uri(target)
                svc = self.policy.resolve_service(authority)
                if fixed and svc is not None and svc.name != fixed.name:
                    return self._http_refuse(head, 400, "Bad Request",
                                             f"this tunnel is bound to service '{fixed.name}'", "PROTOCOL", False)
            elif target.startswith("/") and fixed:
                authority = head.get("Host", fixed.name) or fixed.name
                svc = self.policy.resolve_service(authority)
                if svc is None and authority.lower().split(":", 1)[0] == fixed.name.lower():
                    svc = self.policy.services.get(fixed.name)
                path = target
            else:
                raise HttpError(400, "Bad Request", "expected an absolute http:// URL")
            domain = authority.strip().lower().split(":", 1)[0].rstrip(".")
        except HttpError as e:
            return self._http_refuse(head, e.status, e.reason, e.detail, "PROTOCOL", False)
        if svc is None:
            return self._http_refuse(head, 403, "Forbidden", f"'{authority}' is not a registered service",
                                     "UNKNOWN_SERVICE", keep)
        if svc.inspect != "http":
            return self._http_refuse(head, 400, "Bad Request",
                                     f"'{svc.name}' is not an HTTP service - open a CONNECT tunnel instead", "PROTOCOL", keep)
        c.service, c.inspect = svc.name, "http"
        try:
            match_path, fwd_target = normalize_path(path)
        except ValueError as e:
            return self._http_refuse(head, 400, "Bad Request", f"malformed path: {e}", "PROTOCOL", False, svc=svc)

        # --- access rules (request stage)
        dec = self.policy.evaluate(Context(c.user, c.src, svc.name, method, match_path, domain), stage="request")
        self.registry.count_rule(dec.rule_id, dec.action)
        if not dec.allowed:
            return self._http_refuse(head, 403, "Forbidden", dec.reason, dec.rule_id, keep, svc=svc, path=match_path, domain=domain)

        # --- request-direction content filters: URL and body
        req_filters = self._filters(svc.name, "request")
        hits = []
        if req_filters:
            url_text = unquote_plus(fwd_target).encode("utf-8", "replace")
            url_check = inspect_bytes(url_text, [f for f in req_filters if f.action in ("block", "log")])
            hits += url_check.hits
            if url_check.blocked:
                f = url_check.blocked
                self._record_hits(hits, "request", svc.name)
                return self._http_refuse(head, 403, "Forbidden", f"request blocked by content filter: {f.reason}",
                                         f.id, keep, svc=svc, path=match_path)
            if body:
                outcome = inspect_bytes(body, req_filters)
                hits += outcome.hits
                if outcome.blocked:
                    f = outcome.blocked
                    self._record_hits(hits, "request", svc.name)
                    return self._http_refuse(head, 403, "Forbidden", f"request body blocked: {f.reason}",
                                             f.id, keep, svc=svc, path=match_path)
                body = outcome.data
        if hits:
            self._record_hits(hits, "request", svc.name)

        # --- forward to the service
        out = httpmsg.HttpHead((method, fwd_target, "HTTP/1.1"), httpmsg.forward_headers(head.headers))
        out.set("Host", svc.name)
        out.remove("Accept-Encoding")             # identity encoding only: compressed bodies can't be inspected
        if body or method in ("POST", "PUT", "PATCH"):
            out.set("Content-Length", str(len(body)))
        out.set("X-Forwarded-For", c.src)
        out.set("X-Authenticated-User", c.user)
        out.set("Via", "1.1 netproxy")
        out.set("Connection", "keep-alive")
        resp, resp_body = self._exchange_with_backend(svc, out.to_bytes() + body, method)
        if resp is None:
            return self._http_refuse(head, 502, "Bad Gateway", f"service '{svc.name}' did not answer", "UPSTREAM",
                                     keep, svc=svc, path=match_path)

        # --- response-direction filters
        resp_filters = self._filters(svc.name, "response")
        rhits = []
        if resp_filters:
            mime = check_mime(resp.get("Content-Type", ""), resp_filters)
            rhits += mime.hits
            if mime.blocked:
                f = mime.blocked
                self._record_hits(rhits, "response", svc.name)
                return self._http_refuse(head, 403, "Forbidden", f"response blocked: {f.reason}", f.id, keep,
                                         svc=svc, path=match_path)
            if resp_body:
                outcome = inspect_bytes(resp_body, resp_filters)
                rhits += outcome.hits
                if outcome.blocked:
                    f = outcome.blocked
                    self._record_hits(rhits, "response", svc.name)
                    return self._http_refuse(head, 403, "Forbidden", f"response blocked: {f.reason}", f.id, keep,
                                             svc=svc, path=match_path)
                resp_body = outcome.data
        if rhits:
            self._record_hits(rhits, "response", svc.name)

        # --- send the (possibly redacted) response to the client
        status = resp.status
        rh = httpmsg.HttpHead(("HTTP/1.1", str(status), resp.start[2] or "OK"), httpmsg.forward_headers(resp.headers))
        no_body = method == "HEAD" or 100 <= status < 200 or status in (204, 304)
        if method == "HEAD" and resp.get("Content-Length"):
            rh.set("Content-Length", resp.get("Content-Length"))
        elif not no_body:
            rh.set("Content-Length", str(len(resp_body)))
        rh.set("Via", "1.1 netproxy")
        modified = [f"{fid}:{act}" for fid, act, _ in hits + rhits if act != "log"]
        if modified:
            rh.set("X-Proxy-Filtered", ", ".join(modified))
        rh.set("Connection", "keep-alive" if keep else "close")
        self.client.send_all(rh.to_bytes() + (b"" if no_body else resp_body))
        self._log_request(method, match_path, svc.name, status, dec, hits + rhits, domain=domain)
        return keep

    def _exchange_with_backend(self, svc: Service, payload: bytes, method: str):
        """Send one request on a (reused) keep-alive connection; retry once if it went stale."""
        for attempt in (1, 2):
            ch = self.backends.get(svc.name)
            reused = ch is not None
            if ch is None:
                ch = self._open_backend(svc)
                if ch is None:
                    return None, None
                self.backends[svc.name] = ch
            try:
                ch.send_all(payload)
                raw = ch.read_until(b"\r\n\r\n", self.cfg.max_header_bytes)
                if raw is None:
                    raise PeerClosed("service closed its keep-alive connection")
                head = httpmsg.parse_response_head(raw)
                while 100 <= head.status < 200:                     # skip interim 1xx responses
                    raw = ch.read_until(b"\r\n\r\n", self.cfg.max_header_bytes)
                    if raw is None:
                        raise PeerClosed("service closed after an interim response")
                    head = httpmsg.parse_response_head(raw)
                body = httpmsg.read_body(ch, head, "response", self.cfg.max_body_bytes, method)
            except (PeerClosed, HttpError, TooLarge, IdleTimeout) as e:
                self._drop_backend(svc.name)
                if reused and attempt == 1 and isinstance(e, PeerClosed):
                    continue
                log.warning("#%d service %s failed: %s", self.info.id, svc.name, e)
                self.registry.count("upstream_failures")
                return None, None
            if not httpmsg.wants_keep_alive(head) or httpmsg.body_framing(head, "response", method)[0] == "close":
                self._drop_backend(svc.name)
            return head, body
        return None, None

    def _drop_backend(self, name: str):
        ch = self.backends.pop(name, None)
        if ch:
            ch.close()

    def _http_refuse(self, head, status, reason, detail, rule, keep, svc: Optional[Service] = None,
                     path: Optional[str] = None, domain: Optional[str] = None) -> bool:
        c = self.info
        if head is None:
            where = "-"
        elif svc is not None and path is not None:
            where = f"{head.start[0]} {svc.name}{path}"
        else:
            where = f"{head.start[0]} {head.start[1]}"
        page = httpmsg.block_page(status, reason, detail, rule, c.user, where)
        self.client.send_all(httpmsg.simple_response(
            status, reason, page, "text/html; charset=utf-8",
            extra={"X-Proxy-Rule": rule, "X-Proxy-Reason": detail[:200]}, close=not keep))
        if head is not None:
            self._log_request(head.start[0], path or head.start[1], svc.name if svc else c.service, status,
                              Decision(False, rule, detail), [], domain=domain)
        return keep

    # ------------------------------------------------------------------ helpers
    def _filters(self, service: str, direction: str):
        p = self.policy
        if p.version != self._filter_version:
            self._filter_cache.clear()
            self._filter_version = p.version
        key = (service, direction)
        got = self._filter_cache.get(key)
        if got is None:
            got = self._filter_cache[key] = p.filters_for(self.info.user, service, direction)
        return got

    def _send_status(self, status: int, reason: str, detail: str, rule: str):
        body = f"{status} {reason}\nrule:   {rule}\nreason: {detail}\n".encode("utf-8")
        try:
            self.client.send_all(httpmsg.simple_response(status, reason, body,
                                                         extra={"X-Proxy-Rule": rule, "X-Proxy-Reason": detail[:200]}))
        except (PeerClosed, IdleTimeout):
            pass

    def _log_decision(self, stage: str, dec: Decision):
        c = self.info
        self.registry.count_rule(dec.rule_id, dec.action)
        self.registry.log({"event": stage, "conn": c.id, "src": c.src, "user": c.user, "tls": c.tls,
                           "service": c.service, "decision": dec.action, "rule": dec.rule_id, "reason": dec.reason})
        level = logging.INFO if dec.allowed else logging.WARNING
        log.log(level, "#%d %s@%s CONNECT %s -> %s by %s (%s)", c.id, c.user, c.src, c.service,
                dec.action.upper(), dec.rule_id, dec.reason)

    def _log_request(self, method, path, service, status, dec: Decision, hits, domain=None):
        c = self.info
        self.registry.log({"event": "request", "conn": c.id, "user": c.user, "service": service, "method": method,
                           "path": path, "domain": domain, "status": status, "decision": dec.action, "rule": dec.rule_id,
                           "reason": dec.reason, "filters": [f"{fid}:{act}" for fid, act, _ in hits]})
        log.info("#%d %s %s %s%s -> %d %s", c.id, c.user, method, service, path, status,
                 "" if dec.allowed else f"(denied by {dec.rule_id})")

    def _record_hits(self, hits, direction: str, service: str):
        c = self.info
        for fid, action, n in hits:
            self.registry.count_filter(fid, action, n)
            self.registry.log({"event": "filter", "conn": c.id, "user": c.user, "service": service,
                               "direction": direction, "filter": fid, "action": action, "matches": n})
            log.info("#%d filter %s %s %s on %s (%d match%s)", c.id, fid, action, direction, service, n,
                     "" if n == 1 else "es")

    def _cleanup(self):
        c = self.info
        c.state = "closing"
        for ch in list(self.backends.values()):
            ch.close()
        self.backends.clear()
        if self.client:
            self.client.close()
        else:
            try:
                self.raw.close()
            except OSError:
                pass
        self.registry.remove(c)
        self.registry.log({"event": "close", "conn": c.id, "user": c.user, "service": c.service, "mode": c.mode,
                           "bytes_up": c.bytes_up, "bytes_down": c.bytes_down, "requests": c.requests,
                           "duration_ms": int(c.age() * 1000), "reason": self.close_reason})
        log.debug("#%d closed: %s (%d B up, %d B down)", c.id, self.close_reason, c.bytes_up, c.bytes_down)


# =========================================================================== server
class ProxyServer:
    def __init__(self, cfg: ProxyConfig, store: PolicyStore, registry: Optional[Registry] = None):
        self.cfg = cfg
        self.store = store
        self.registry = registry or Registry(cfg.access_log)
        self.tls_ctx = server_context(cfg.cert, cfg.key, cfg.ca, cfg.require_client_cert)
        self.ports: Dict[str, int] = {}
        self.last_revalidation = []
        self._listeners = []
        self._stop = threading.Event()
        self._slots = threading.BoundedSemaphore(cfg.max_connections)
        self.admin = None
        store.subscribe(self._on_policy_change)

    def start(self) -> "ProxyServer":
        self._listen("tls", self.cfg.listen_host, self.cfg.tls_port, tls=True)
        if self.cfg.plain_port is not None:
            self._listen("plain", self.cfg.listen_host, self.cfg.plain_port, tls=False)
        if self.cfg.admin_port is not None:
            from .control import AdminServer
            self.admin = AdminServer(self, self.cfg.admin_host, self.cfg.admin_port, self.cfg.admin_token)
            self.ports["admin"] = self.admin.start()
        if self.store.path:
            self.store.start_watcher(self.cfg.policy_poll_seconds)
        return self

    def _listen(self, name: str, host: str, port: int, tls: bool):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        if os.name != "nt":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(128)
        s.settimeout(0.5)
        self.ports[name] = s.getsockname()[1]
        self._listeners.append(s)
        threading.Thread(target=self._accept_loop, args=(s, tls), name=f"accept-{name}", daemon=True).start()

    def _accept_loop(self, lsock: socket.socket, tls: bool):
        while not self._stop.is_set():
            try:
                sock, addr = lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                time.sleep(0.05)
                continue
            if not self._slots.acquire(blocking=False):
                self.registry.count("rejected_capacity")
                sock.close()
                continue
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            threading.Thread(target=self._session, args=(sock, addr, tls), daemon=True).start()

    def _session(self, sock, addr, tls):
        try:
            ClientSession(self, sock, addr, tls).run()
        finally:
            self._slots.release()

    def _on_policy_change(self, old: Optional[Policy], new: Policy, source: str):
        self.registry.log({"event": "policy", "version": new.version, "digest": new.digest, "source": source})
        self.last_revalidation = self.registry.revalidate(new)
        for conn, dec in self.last_revalidation:
            log.warning("#%d %s -> %s terminated by policy v%d: %s (%s)", conn.id, conn.user, conn.service,
                        new.version, dec.rule_id, dec.reason)

    def serve_forever(self):
        try:
            while not self._stop.wait(0.5):
                pass
        except KeyboardInterrupt:
            log.info("Ctrl+C received, shutting down")
        self.shutdown()

    def shutdown(self):
        self._stop.set()
        for s in self._listeners:
            try:
                s.close()
            except OSError:
                pass
        for c in self.registry.active():
            c.kill("proxy shutting down", "SHUTDOWN")
        if self.admin:
            self.admin.stop()
        self.store.stop()
