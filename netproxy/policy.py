"""
netproxy.policy -- the policy engine.

A policy is a JSON document with these sections:

    services         name -> {host, port, inspect: http | line | none, aliases}
    groups           group name -> [user, ...]
    default_action   "allow" | "deny"   (used when no rule matches)
    rules            ordered access-control list -- FIRST MATCH WINS (like a firewall ACL)
    content_filters  payload inspection: keyword / regex / mime, action block | redact | log
    limits           per-identity concurrent-connection cap and new-connection rate limit

Rules are evaluated in two stages:

    connect stage  when a client asks to CONNECT to a service. Identity, source IP,
                   service and time of day are known.
    request stage  for every HTTP request inside an http-inspected session. Method
                   and path are known as well, so path rules ("/admin/*") apply here.

A Policy object is immutable. Every change -- a file edit or an admin command --
builds a brand-new Policy (version + 1) and PolicyStore swaps it in atomically,
so a connection thread never sees a half-applied policy.
"""
from __future__ import annotations

import copy
import fnmatch
import hashlib
import ipaddress
import json
import logging
import os
import posixpath
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple
from urllib.parse import quote, unquote

log = logging.getLogger("netproxy.policy")

ANONYMOUS = "anonymous"
INSPECT_MODES = ("http", "line", "none")
_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PolicyError(ValueError):
    """The policy document is invalid; the message says where and why."""


# =========================================================================== small helpers
def _strings(value, where: str) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise PolicyError(f"{where}: expected a string or a list of non-empty strings")
    return [v.strip() for v in value]


def _check_keys(obj, allowed, where: str):
    if not isinstance(obj, dict):
        raise PolicyError(f"{where}: expected a JSON object")
    for key in obj:
        if key.startswith("_"):          # "_comment" keys are documentation, ignored
            continue
        if key not in allowed:
            raise PolicyError(f"{where}: unknown key {key!r} (allowed: {', '.join(sorted(allowed))})")


def _bool(value, where: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise PolicyError(f"{where}: expected true or false")
    return value


def _hhmm(text, where: str) -> int:
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", str(text).strip())
    if not m or int(m.group(1)) > 24 or int(m.group(2)) > 59 or (int(m.group(1)) == 24 and int(m.group(2))):
        raise PolicyError(f"{where}: time must be HH:MM (00:00-24:00), got {text!r}")
    return int(m.group(1)) * 60 + int(m.group(2))


def _day(text: str, where: str) -> int:
    key = text.strip().lower()[:3]
    if key not in _DAYS:
        raise PolicyError(f"{where}: unknown day {text!r} (use mon..sun)")
    return _DAYS.index(key)


def normalize_path(target: str) -> Tuple[str, str]:
    """Canonicalise an HTTP request target before it is matched against rules.

    Returns (path_for_matching, target_to_forward). Without this step
    '/x/../admin/panel', '//admin/panel' or '/%61dmin/panel' would slip past a
    rule for '/admin/*' while the back end still serves the page. The proxy
    forwards the *normalised* target, so what was checked is exactly what is served.
    """
    if not target.startswith("/"):
        raise ValueError("request target must start with '/'")
    path, sep, query = target.split("#", 1)[0].partition("?")
    decoded = unquote(path, errors="strict")
    if "\x00" in decoded or "\\" in decoded:
        raise ValueError("illegal character in path")
    decoded = re.sub(r"/{2,}", "/", decoded)
    norm = posixpath.normpath(decoded)
    if not norm.startswith("/"):
        norm = "/" + norm
    if decoded.endswith("/") and norm != "/":
        norm += "/"
    forward = quote(norm, safe="/:@!$&'()*+,;=-._~") + (sep + query if sep else "")
    return norm, forward


# =========================================================================== model
@dataclass(frozen=True)
class Service:
    name: str
    host: str
    port: int
    inspect: str                      # http | line | none
    aliases: Tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True)
class Schedule:
    days: FrozenSet[int]              # 0 = Monday
    start: int                        # minutes after midnight
    end: int
    text: str

    def active(self, now: datetime) -> bool:
        minute, day = now.hour * 60 + now.minute, now.weekday()
        if self.start == self.end:                      # whole day
            return day in self.days
        if self.start < self.end:
            return day in self.days and self.start <= minute < self.end
        # window crosses midnight (e.g. 22:00-06:00): it belongs to the day it starts on
        if minute >= self.start:
            return day in self.days
        if minute < self.end:
            return (day - 1) % 7 in self.days
        return False


@dataclass(frozen=True)
class UserMatcher:
    """Matches an identity against patterns: '*', 'alice', '@group', 'anonymous'."""
    include: Tuple[str, ...]          # empty = everyone
    exclude: Tuple[str, ...]

    @staticmethod
    def _hit(user: str, patterns, groups) -> bool:
        for p in patterns:
            if p == "*" or p == user:
                return True
            if p.startswith("@") and user in groups.get(p[1:], ()):
                return True
        return False

    def matches(self, user: str, groups: Dict[str, FrozenSet[str]]) -> bool:
        if self.include and not self._hit(user, self.include, groups):
            return False
        return not (self.exclude and self._hit(user, self.exclude, groups))


@dataclass(frozen=True)
class Context:
    """Everything the policy engine may look at for one decision."""
    user: str
    src: str
    service: str
    method: Optional[str] = None
    path: Optional[str] = None
    domain: Optional[str] = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule_id: str
    reason: str
    provisional: bool = False         # connect-stage allow that still needs per-request checks

    @property
    def action(self) -> str:
        return "allow" if self.allowed else "deny"


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    users: UserMatcher
    networks: tuple
    services: Tuple[str, ...]         # empty = any service
    paths: Tuple[str, ...]
    domains: Tuple[str, ...]
    methods: Tuple[str, ...]
    schedule: Optional[Schedule]
    reason: str
    enabled: bool

    @property
    def request_scoped(self) -> bool:
        return bool(self.paths or self.domains or self.methods)

    def matches_base(self, ctx: Context, groups, now: datetime) -> bool:
        if not self.enabled:
            return False
        if self.services and ctx.service not in self.services:
            return False
        if self.domains and (ctx.domain or "").lower().split(":", 1)[0] not in self.domains:
            return False
        if not self.users.matches(ctx.user, groups):
            return False
        if self.networks:
            try:
                ip = ipaddress.ip_address(ctx.src)
            except ValueError:
                return False
            if not any(ip in net for net in self.networks):
                return False
        return not (self.schedule and not self.schedule.active(now))

    def matches_request(self, ctx: Context) -> bool:
        if self.methods and (ctx.method or "").upper() not in self.methods:
            return False
        if self.paths:
            path = (ctx.path or "").split("?", 1)[0]
            if not any(fnmatch.fnmatchcase(path, p) for p in self.paths):
                return False
        return True

    def describe(self) -> str:
        parts = [f"{self.id:<8}", f"{self.action:<5}"]
        if self.users.include:
            parts.append("users=" + ",".join(self.users.include))
        if self.users.exclude:
            parts.append("except=" + ",".join(self.users.exclude))
        if self.networks:
            parts.append("src=" + ",".join(str(n) for n in self.networks))
        parts.append("services=" + (",".join(self.services) or "*"))
        if self.paths:
            parts.append("paths=" + ",".join(self.paths))
        if self.domains:
            parts.append("domains=" + ",".join(self.domains))
        if self.methods:
            parts.append("methods=" + ",".join(self.methods))
        if self.schedule:
            parts.append("when=" + self.schedule.text)
        if not self.enabled:
            parts.append("(disabled)")
        return "  ".join(parts) + f"   # {self.reason}"


@dataclass(frozen=True)
class ContentFilter:
    id: str
    kind: str                         # keyword | regex | mime
    patterns: Tuple[str, ...]
    action: str                       # block | redact | log
    direction: str                    # request | response | both
    services: Tuple[str, ...]
    users: UserMatcher
    replacement: bytes
    reason: str
    enabled: bool
    regex: Optional["re.Pattern[bytes]"]
    keywords_lower: Tuple[bytes, ...]  # for stream hold-back (keyword filters only)

    def applies(self, user: str, service: str, direction: str, groups) -> bool:
        if not self.enabled:
            return False
        if self.kind == "mime" and direction != "response":
            return False
        if self.direction not in ("both", direction):
            return False
        if self.services and service not in self.services:
            return False
        return self.users.matches(user, groups)

    def mime_matches(self, content_type: str) -> bool:
        ctype = content_type.split(";", 1)[0].strip().lower()
        return any(fnmatch.fnmatchcase(ctype, p.lower()) for p in self.patterns)

    def describe(self) -> str:
        who = ""
        if self.users.include:
            who += "  users=" + ",".join(self.users.include)
        if self.users.exclude:
            who += "  except=" + ",".join(self.users.exclude)
        svcs = ",".join(self.services) or "*"
        pats = ", ".join(self.patterns)
        state = "" if self.enabled else "  (disabled)"
        return (f"{self.id:<8} {self.kind:<7} {self.action:<6} dir={self.direction:<8} services={svcs}{who}"
                f"  patterns=[{pats}]{state}   # {self.reason}")


@dataclass(frozen=True)
class Limits:
    max_conns_per_user: int = 0          # 0 = unlimited
    max_new_conns_per_window: int = 0    # 0 = unlimited
    window_seconds: float = 10.0


# =========================================================================== policy
class Policy:
    """A validated, immutable policy. Build one with Policy(doc) or Policy.from_text(text)."""

    TOP_KEYS = {"name", "default_action", "services", "groups", "rules", "content_filters", "limits"}

    def __init__(self, doc: dict, version: int = 1):
        if not isinstance(doc, dict):
            raise PolicyError("policy: the top level must be a JSON object")
        self.doc = copy.deepcopy(doc)
        self.version = version
        _check_keys(self.doc, self.TOP_KEYS, "policy")
        self.name = str(self.doc.get("name", "policy"))
        self.default_action = self.doc.get("default_action", "deny")
        if self.default_action not in ("allow", "deny"):
            raise PolicyError("default_action: must be 'allow' or 'deny'")
        self.services, self._service_index = self._build_services(self.doc.get("services", {}))
        self.groups = self._build_groups(self.doc.get("groups", {}))
        self.rules = self._build_rules(self.doc.setdefault("rules", []))
        self.filters = self._build_filters(self.doc.setdefault("content_filters", []))
        self.limits = self._build_limits(self.doc.get("limits", {}))
        canonical = json.dumps(self.doc, sort_keys=True, separators=(",", ":"))
        self.digest = hashlib.sha256(canonical.encode()).hexdigest()[:12]

    @classmethod
    def from_text(cls, text: str, version: int = 1) -> "Policy":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise PolicyError(f"invalid JSON at line {e.lineno}, column {e.colno}: {e.msg}") from None
        return cls(doc, version)

    def to_json(self) -> str:
        return json.dumps(self.doc, indent=2) + "\n"

    # ------------------------------------------------------------------ builders
    def _build_services(self, raw):
        if not isinstance(raw, dict):
            raise PolicyError("services: expected a JSON object of name -> {host, port, inspect}")
        services, index = {}, {}
        for name, spec in raw.items():
            if name.startswith("_"):
                continue
            where = f"services.{name}"
            if not _NAME_RE.match(name):
                raise PolicyError(f"{where}: invalid service name")
            _check_keys(spec, {"host", "port", "inspect", "aliases", "description"}, where)
            port = spec.get("port")
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise PolicyError(f"{where}.port: must be an integer 1-65535")
            inspect = spec.get("inspect", "none")
            if inspect not in INSPECT_MODES:
                raise PolicyError(f"{where}.inspect: must be one of {', '.join(INSPECT_MODES)}")
            host = spec.get("host", "127.0.0.1")
            if not isinstance(host, str) or not host:
                raise PolicyError(f"{where}.host: must be a hostname or IP address")
            svc = Service(name, host, port, inspect, tuple(_strings(spec.get("aliases"), f"{where}.aliases")),
                          str(spec.get("description", "")))
            for key in (name, *svc.aliases):
                if key.lower() in index:
                    raise PolicyError(f"{where}: name or alias {key!r} is already used")
                index[key.lower()] = svc
            services[name] = svc
        if not services:
            raise PolicyError("services: at least one service must be defined")
        return services, index

    def _build_groups(self, raw) -> Dict[str, FrozenSet[str]]:
        if not isinstance(raw, dict):
            raise PolicyError("groups: expected a JSON object of group -> [users]")
        groups = {}
        for name, members in raw.items():
            if name.startswith("_"):
                continue
            if not _NAME_RE.match(name):
                raise PolicyError(f"groups.{name}: invalid group name")
            groups[name] = frozenset(_strings(members, f"groups.{name}"))
        return groups

    def _users(self, include, exclude, where) -> UserMatcher:
        inc = _strings(include, f"{where}.users")
        exc = _strings(exclude, f"{where}.except_users")
        for p in inc + exc:
            if p.startswith("@") and p[1:] not in self.groups:
                raise PolicyError(f"{where}: unknown group {p!r}")
        return UserMatcher(tuple(inc), tuple(exc))

    def _service_list(self, raw, where) -> Tuple[str, ...]:
        names = _strings(raw, f"{where}.services")
        if "*" in names:
            return ()
        for n in names:
            if n not in self.services:
                raise PolicyError(f"{where}.services: unknown service {n!r}")
        return tuple(names)

    @staticmethod
    def _assign_ids(items: list, prefix: str):
        """Give every rule/filter without an 'id' the next free one (R01, R02 ... / F01 ...)."""
        taken = {it.get("id") for it in items if isinstance(it, dict)}
        n = 1
        for it in items:
            if isinstance(it, dict) and it.get("id") is None:
                while f"{prefix}{n:02d}" in taken:
                    n += 1
                it["id"] = f"{prefix}{n:02d}"
                taken.add(it["id"])

    @staticmethod
    def _unique_id(item: dict, prefix: str, seen: set, where: str) -> str:
        rid = item.get("id")
        if not isinstance(rid, str) or not _NAME_RE.match(rid):
            raise PolicyError(f"{where}.id: must be a short name like {prefix}01")
        if rid in seen:
            raise PolicyError(f"{where}.id: duplicate id {rid!r}")
        seen.add(rid)
        return rid

    def _build_rules(self, raw) -> Tuple[Rule, ...]:
        if not isinstance(raw, list):
            raise PolicyError("rules: expected a list")
        allowed = {"id", "action", "users", "except_users", "src", "services", "paths", "domains",
                   "methods", "schedule", "reason", "enabled"}
        self._assign_ids(raw, "R")
        seen, rules = set(), []
        for i, item in enumerate(raw):
            where = f"rules[{i}]"
            _check_keys(item, allowed, where)
            rid = self._unique_id(item, "R", seen, where)
            where = f"rule {rid}"
            action = item.get("action")
            if action not in ("allow", "deny"):
                raise PolicyError(f"{where}.action: must be 'allow' or 'deny'")
            nets = []
            for cidr in _strings(item.get("src"), f"{where}.src"):
                try:
                    nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    raise PolicyError(f"{where}.src: {cidr!r} is not an IP address or CIDR block") from None
            paths = _strings(item.get("paths"), f"{where}.paths")
            domains = tuple(x.lower().split(":", 1)[0].rstrip(".") for x in _strings(item.get("domains"), f"{where}.domains"))
            for d in domains:
                if not d or any(ch.isspace() for ch in d) or "/" in d:
                    raise PolicyError(f"{where}.domains: invalid domain {d!r}")
            for p in paths:
                if not p.startswith("/"):
                    raise PolicyError(f"{where}.paths: {p!r} must start with '/'")
            schedule = None
            if item.get("schedule") is not None:
                s = item["schedule"]
                _check_keys(s, {"days", "from", "to"}, f"{where}.schedule")
                days = set()
                for part in _strings(s.get("days", "*"), f"{where}.schedule.days"):
                    p = part.lower()
                    if p in ("*", "all", "daily"):
                        days.update(range(7))
                    elif "-" in p:
                        a, b = (_day(x, f"{where}.schedule.days") for x in p.split("-", 1))
                        d = a
                        while True:
                            days.add(d)
                            if d == b:
                                break
                            d = (d + 1) % 7
                    else:
                        days.add(_day(p, f"{where}.schedule.days"))
                start = _hhmm(s.get("from", "00:00"), f"{where}.schedule.from")
                end = _hhmm(s.get("to", "24:00"), f"{where}.schedule.to")
                text = f"{s.get('days', '*')} {s.get('from', '00:00')}-{s.get('to', '24:00')}"
                schedule = Schedule(frozenset(days), start, end, text)
            rules.append(Rule(
                id=rid, action=action,
                users=self._users(item.get("users"), item.get("except_users"), where),
                networks=tuple(nets),
                services=self._service_list(item.get("services"), where),
                paths=tuple(paths),
                domains=domains,
                methods=tuple(m.upper() for m in _strings(item.get("methods"), f"{where}.methods")),
                schedule=schedule,
                reason=str(item.get("reason") or f"rule {rid}"),
                enabled=_bool(item.get("enabled"), f"{where}.enabled", True),
            ))
        return tuple(rules)

    def _build_filters(self, raw) -> Tuple[ContentFilter, ...]:
        if not isinstance(raw, list):
            raise PolicyError("content_filters: expected a list")
        allowed = {"id", "type", "patterns", "action", "direction", "services", "users", "except_users",
                   "replacement", "reason", "enabled", "whole_word", "case_sensitive"}
        self._assign_ids(raw, "F")
        seen, out = set(), []
        for i, item in enumerate(raw):
            where = f"content_filters[{i}]"
            _check_keys(item, allowed, where)
            fid = self._unique_id(item, "F", seen, where)
            where = f"filter {fid}"
            kind = item.get("type")
            if kind not in ("keyword", "regex", "mime"):
                raise PolicyError(f"{where}.type: must be keyword, regex or mime")
            patterns = _strings(item.get("patterns"), f"{where}.patterns")
            if not patterns:
                raise PolicyError(f"{where}.patterns: at least one pattern is required")
            action = item.get("action", "block")
            if action not in ("block", "redact", "log") or (kind == "mime" and action == "redact"):
                raise PolicyError(f"{where}.action: must be block, redact or log (mime: block or log)")
            direction = item.get("direction", "response" if kind == "mime" else "both")
            if direction not in ("request", "response", "both"):
                raise PolicyError(f"{where}.direction: must be request, response or both")
            # MULTILINE: ^ and $ match at line boundaries, so a pattern behaves the same whether
            # it is applied to one line or to a block of lines (see StreamInspector's fast path)
            flags = re.MULTILINE
            if not _bool(item.get("case_sensitive"), f"{where}.case_sensitive", False):
                flags |= re.IGNORECASE
            regex, kw_lower = None, ()
            if kind == "keyword":
                alts = b"|".join(re.escape(p.encode("utf-8")) for p in sorted(patterns, key=len, reverse=True))
                if _bool(item.get("whole_word"), f"{where}.whole_word", False):
                    alts = rb"\b(?:" + alts + rb")\b"
                regex = re.compile(alts, flags)
                kw_lower = tuple(p.encode("utf-8").lower() for p in patterns)
            elif kind == "regex":
                try:
                    regex = re.compile(b"|".join(b"(?:" + p.encode("utf-8") + b")" for p in patterns), flags)
                except re.error as e:
                    raise PolicyError(f"{where}.patterns: bad regular expression: {e}") from None
            out.append(ContentFilter(
                id=fid, kind=kind, patterns=tuple(patterns), action=action, direction=direction,
                services=self._service_list(item.get("services"), where),
                users=self._users(item.get("users"), item.get("except_users"), where),
                replacement=str(item.get("replacement", "[REDACTED]")).encode("utf-8"),
                reason=str(item.get("reason") or f"filter {fid}"),
                enabled=_bool(item.get("enabled"), f"{where}.enabled", True),
                regex=regex, keywords_lower=kw_lower,
            ))
        return tuple(out)

    def _build_limits(self, raw) -> Limits:
        _check_keys(raw, {"max_conns_per_user", "max_new_conns_per_window", "window_seconds"}, "limits")
        vals = {}
        for key in ("max_conns_per_user", "max_new_conns_per_window"):
            v = raw.get(key, 0)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise PolicyError(f"limits.{key}: must be a non-negative integer (0 = unlimited)")
            vals[key] = v
        w = raw.get("window_seconds", 10)
        if not isinstance(w, (int, float)) or isinstance(w, bool) or w <= 0:
            raise PolicyError("limits.window_seconds: must be a positive number")
        return Limits(vals["max_conns_per_user"], vals["max_new_conns_per_window"], float(w))

    # ------------------------------------------------------------------ queries
    def resolve_service(self, authority: str) -> Optional[Service]:
        """Map 'web', 'web:80' or an alias such as 'web.sim' to a registered service."""
        host = authority.strip().lower()
        if host.count(":") == 1:
            host = host.split(":", 1)[0]
        return self._service_index.get(host)

    def evaluate(self, ctx: Context, stage: str = "request", now: Optional[datetime] = None) -> Decision:
        """First-match evaluation of the rule list.

        At the connect stage a rule with paths/methods cannot be decided yet:
        a deny is skipped (it is enforced per request later) and an allow
        admits the connection provisionally. For services that are not
        HTTP-inspected such rules never apply, because there are no requests.
        """
        svc = self.services.get(ctx.service)
        if svc is None:
            return Decision(False, "UNKNOWN_SERVICE", f"'{ctx.service}' is not a registered service")
        now = now or datetime.now()
        http = svc.inspect == "http"
        for rule in self.rules:
            if not rule.matches_base(ctx, self.groups, now):
                continue
            if rule.request_scoped:
                if not http:
                    continue
                if stage == "connect":
                    if rule.action == "allow":
                        return Decision(True, rule.id, rule.reason + " (per-request checks apply)", provisional=True)
                    continue
                if not rule.matches_request(ctx):
                    continue
            return Decision(rule.action == "allow", rule.id, rule.reason)
        return Decision(self.default_action == "allow", "DEFAULT", f"no rule matched; default action is {self.default_action}")

    def filters_for(self, user: str, service: str, direction: str) -> List[ContentFilter]:
        return [f for f in self.filters if f.applies(user, service, direction, self.groups)]


# =========================================================================== store (hot reload)
def atomic_write(path: str, text: str, attempts: int = 20):
    """Write a file so readers never see it half-written (write a temp file, then rename over).

    On Windows the rename fails while another program has the file open, so retry briefly.
    """
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    for i in range(attempts):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(0.05)


Listener = Callable[[Optional[Policy], Policy, str], None]


class PolicyStore:
    """Holds the active Policy and swaps in new versions atomically.

    Sources of change:
      * the policy file -- a watcher thread polls its modification time and
        reloads it when it changes (works the same on Windows and Linux);
      * admin commands  -- mutate() applies an edit to a copy of the document.
    A change that fails validation is rejected and the old policy stays active.
    Listeners (the proxy) are told about every swap so they can re-check live
    connections against the new rules.
    """

    def __init__(self, path: Optional[str] = None, policy: Optional[Policy] = None):
        self.path = path
        self._lock = threading.RLock()
        self._policy = policy
        self._listeners: List[Listener] = []
        self._file_digest = None
        self._file_stat = None
        self._watcher: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.last_source = "initial"
        self.last_error = ""

    @property
    def policy(self) -> Policy:
        return self._policy

    def subscribe(self, fn: Listener):
        self._listeners.append(fn)

    def _swap(self, new_doc: dict, source: str) -> Policy:
        with self._lock:
            old = self._policy
            new = Policy(new_doc, version=(old.version + 1) if old else 1)   # validates
            self._policy = new
            self.last_source = source
        log.info("policy v%d active (%s, digest %s)", new.version, source, new.digest)
        for fn in list(self._listeners):
            try:
                fn(old, new, source)
            except Exception:                                             # pragma: no cover
                log.exception("policy listener failed")
        return new

    # ------------------------------------------------------------------ file
    def _read_file(self):
        # stat BEFORE reading: if an editor is still writing, its final write changes the
        # stat after this point and the next poll reads the file again
        st = self._stat()
        with open(self.path, "r", encoding="utf-8-sig") as fh:      # -sig: tolerate Notepad's BOM
            text = fh.read()
        return text, hashlib.sha256(text.encode("utf-8")).hexdigest(), st

    def load(self) -> Policy:
        """Initial load; raises PolicyError if the file is invalid."""
        text, digest, st = self._read_file()
        doc = Policy.from_text(text).doc
        self._file_digest, self._file_stat = digest, st
        return self._swap(doc, f"file {os.path.basename(self.path)}")

    def reload(self, source: str = "reload") -> Tuple[bool, str]:
        """Re-read the file. Returns (changed, message). Invalid files are rejected."""
        if not self.path:
            return False, "no policy file configured"
        try:
            text, digest, st = self._read_file()
        except OSError as e:                     # e.g. the editor still holds the file on Windows
            return False, f"cannot read {self.path}: {e}"
        with self._lock:
            self._file_stat = st
            if digest == self._file_digest:
                return False, "policy file unchanged"
            self._file_digest = digest
            try:
                doc = Policy.from_text(text).doc
                new = self._swap(doc, source)
            except PolicyError as e:
                self.last_error = str(e)
                log.error("policy file rejected, keeping v%d: %s", self._policy.version, e)
                return False, f"rejected: {e}"
        self.last_error = ""
        return True, f"policy v{new.version} loaded from file"

    def save(self) -> str:
        """Write the active policy back to the file (atomic replace)."""
        if not self.path:
            raise PolicyError("no policy file configured")
        with self._lock:
            text = self._policy.to_json()
            atomic_write(self.path, text)
            self._file_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            self._file_stat = self._stat()
        return self.path

    def _stat(self):
        try:
            st = os.stat(self.path)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def start_watcher(self, interval: float = 1.0):
        if not self.path or self._watcher:
            return

        def watch():
            while not self._stop.wait(interval):
                if self._stat() != self._file_stat:
                    self.reload(source="file changed")

        self._watcher = threading.Thread(target=watch, name="policy-watcher", daemon=True)
        self._watcher.start()

    def stop(self):
        self._stop.set()

    # ------------------------------------------------------------------ programmatic edits
    def mutate(self, fn: Callable[[dict], object], source: str):
        """Apply fn to a copy of the policy document, validate and swap it in.

        Returns (new_policy, fn_result). Raises PolicyError and leaves the
        active policy untouched if the edited document is invalid.
        """
        with self._lock:
            doc = copy.deepcopy(self._policy.doc)
            result = fn(doc)
            new = self._swap(doc, source)
        return new, result
