"""netproxy.sdn -- tell the SDN controller about policy violations.

The proxy is the only place that knows *why* a client was refused (rule,
user, filter hit). The controller is the only place that can stop the packets
before they reach the proxy. This module is the link between the two: every
denied decision in the access log is forwarded as one JSON line to the
controller's control socket, and the controller decides whether the source
host has misbehaved often enough to be quarantined in the network.

The control channel is a UNIX socket on purpose: Mininet hosts have their own
network namespace but share the filesystem, so it behaves like the
out-of-band management network a real SDN deployment uses, and it keeps the
control traffic out of the emulated data plane.

Failure is silent by design: with no controller the proxy works exactly as before.
"""
from __future__ import annotations

import json
import queue
import socket
import threading


class SdnNotifier:
    def __init__(self, path: str):
        self.path = path
        self._q: "queue.Queue[dict]" = queue.Queue(maxsize=1000)
        self._conn_src: dict = {}                    # conn id -> client ip (request/filter records carry no src)
        threading.Thread(target=self._run, daemon=True, name="sdn-notifier").start()

    # ---- called from Registry.log for every access-log record
    def emit(self, rec: dict):
        conn = rec.get("conn")
        if rec.get("src") and conn is not None:
            self._conn_src[conn] = rec["src"]
        src = rec.get("src") or self._conn_src.get(conn)
        if rec.get("event") == "close":
            self._conn_src.pop(conn, None)
            return
        violation = rec.get("decision") == "deny" or (rec.get("event") == "filter" and rec.get("action") == "block")
        if not violation or not src:
            return
        msg = {"type": "violation", "src": src, "user": rec.get("user"), "service": rec.get("service"),
               "rule": rec.get("rule") or rec.get("filter"), "reason": rec.get("reason") or rec.get("event")}
        try:
            self._q.put_nowait(msg)
        except queue.Full:
            pass

    def _run(self):
        sock = None
        while True:
            msg = self._q.get()
            for _ in range(2):                       # one reconnect attempt per message
                try:
                    if sock is None:
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        sock.settimeout(1.0)
                        sock.connect(self.path)
                    sock.sendall((json.dumps(msg) + "\n").encode())
                    break
                except OSError:
                    if sock:
                        sock.close()
                    sock = None
