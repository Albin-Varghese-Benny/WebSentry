"""netproxy.registry -- live connection table, limits, counters and the access log."""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional, Tuple

from .policy import ANONYMOUS, Context, Decision, Limits, Policy

log = logging.getLogger("netproxy")


@dataclass
class ConnInfo:
    id: int
    src: str
    src_port: int
    listener: str                      # "tls" or "plain"
    started: float = field(default_factory=time.time)
    tls: str = "-"
    cipher: str = "-"
    user: str = ANONYMOUS
    service: str = "-"
    mode: str = "-"                    # tunnel | forward
    inspect: str = "-"
    state: str = "handshake"           # handshake | active | closing
    bytes_up: int = 0                  # client -> proxy
    bytes_down: int = 0                # service -> proxy
    requests: int = 0
    limit_key: str = ""
    admitted: bool = False
    kill_reason: str = ""
    kill_rule: str = ""
    cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    def kill(self, reason: str, rule: str = "ADMIN") -> bool:
        if self.cancel.is_set():
            return False
        self.kill_reason, self.kill_rule = reason, rule
        self.cancel.set()
        return True

    def age(self) -> float:
        return time.time() - self.started


class Registry:
    def __init__(self, access_log: Optional[str] = None):
        self._lock = threading.Lock()
        self._conns: Dict[int, ConnInfo] = {}
        self._next_id = 1
        self._active_per_key: Counter = Counter()
        self._recent: Dict[str, Deque[float]] = defaultdict(deque)
        self.counters: Counter = Counter()
        self.rule_hits: Counter = Counter()           # (rule id, action) -> count
        self.filter_hits: Counter = Counter()         # (filter id, action) -> count
        self.user_conns: Counter = Counter()
        self.recent_log: Deque[dict] = deque(maxlen=500)
        self.started = time.time()
        self._log_lock = threading.Lock()
        self._log_fh = None
        if access_log:
            os.makedirs(os.path.dirname(access_log) or ".", exist_ok=True)
            self._log_fh = open(access_log, "a", encoding="utf-8", buffering=1)

    # ------------------------------------------------------------------ connections
    def new_conn(self, src: str, src_port: int, listener: str) -> ConnInfo:
        with self._lock:
            c = ConnInfo(self._next_id, src, src_port, listener)
            self._next_id += 1
            self._conns[c.id] = c
            self.counters["connections"] += 1
        return c

    def admit(self, c: ConnInfo, limits: Limits) -> Tuple[bool, str]:
        """Enforce per-identity limits once the identity is known (after TLS)."""
        key = c.user if c.user != ANONYMOUS else f"{ANONYMOUS}@{c.src}"
        now = time.monotonic()
        with self._lock:
            c.limit_key = key
            if limits.max_conns_per_user and self._active_per_key[key] >= limits.max_conns_per_user:
                self.counters["rate_limited"] += 1
                return False, f"'{key}' already has {limits.max_conns_per_user} open connections (limit)"
            if limits.max_new_conns_per_window:
                window = self._recent[key]
                while window and now - window[0] > limits.window_seconds:
                    window.popleft()
                if len(window) >= limits.max_new_conns_per_window:
                    self.counters["rate_limited"] += 1
                    return False, (f"rate limit: more than {limits.max_new_conns_per_window} new connections "
                                   f"in {limits.window_seconds:g}s for '{key}'")
                window.append(now)
            self._active_per_key[key] += 1
            self.user_conns[c.user] += 1
            c.admitted = True
        return True, ""

    def remove(self, c: ConnInfo):
        with self._lock:
            self._conns.pop(c.id, None)
            if c.admitted:
                self._active_per_key[c.limit_key] -= 1
                if self._active_per_key[c.limit_key] <= 0:
                    del self._active_per_key[c.limit_key]
            self.counters["bytes_up"] += c.bytes_up
            self.counters["bytes_down"] += c.bytes_down

    def active(self) -> List[ConnInfo]:
        with self._lock:
            return sorted(self._conns.values(), key=lambda c: c.id)

    def get(self, conn_id: int) -> Optional[ConnInfo]:
        with self._lock:
            return self._conns.get(conn_id)

    def revalidate(self, policy: Policy) -> List[Tuple[ConnInfo, Decision]]:
        """Re-check every open session against a new policy; cancel the ones now denied."""
        killed = []
        for c in self.active():
            if c.state != "active" or c.service in ("-", ""):
                continue
            dec = policy.evaluate(Context(c.user, c.src, c.service), stage="connect")
            if not dec.allowed and c.kill(f"policy v{policy.version}: {dec.reason}", dec.rule_id):
                killed.append((c, dec))
        return killed

    # ------------------------------------------------------------------ accounting
    def count(self, key: str, n: int = 1):
        with self._lock:
            self.counters[key] += n

    def count_rule(self, rule_id: str, action: str):
        with self._lock:
            self.rule_hits[(rule_id, action)] += 1
            self.counters["allowed" if action == "allow" else "denied"] += 1

    def count_filter(self, filter_id: str, action: str, n: int = 1):
        with self._lock:
            self.filter_hits[(filter_id, action)] += n

    def log(self, record: dict):
        record = {"ts": datetime.now().isoformat(timespec="milliseconds"), **record}
        with self._log_lock:
            self.recent_log.append(record)
            if self._log_fh:
                self._log_fh.write(json.dumps(record) + "\n")

    def close(self):
        with self._log_lock:
            if self._log_fh:
                self._log_fh.close()
                self._log_fh = None
