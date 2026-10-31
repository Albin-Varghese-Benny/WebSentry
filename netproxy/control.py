"""
netproxy.control -- the admin console: change policy on a running proxy.

A separate TLS listener (127.0.0.1:9443 by default) with a simple line
protocol. The first command must be  AUTH <token>.  Every reply starts with
"OK" or "ERR" and ends with a line containing a single ".".

Every policy edit builds and validates a new policy version, swaps it in,
and immediately re-checks the open connections: sessions the new policy
denies are terminated on the spot. That is what makes filtering *dynamic*.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import socket
import ssl
import threading
import time
from typing import Callable, Dict, List, Tuple

from . import __version__
from .policy import PolicyError

log = logging.getLogger("netproxy.admin")

HELP = """\
Commands (case-insensitive):
  STATUS                          uptime, policy version, counters
  CONNS                           open connections
  KILL <conn-id> | KILL user <name>
  RULES | FILTERS | SERVICES      show the active policy sections
  SHOW                            the full policy document (JSON)
  BLOCK user|group|ip|service <x> insert a deny rule at the top (DYN-n); live sessions are cut
  UNBLOCK <rule-id>               remove a rule (same as RULE DEL)
  RULE ADD <json>                 append a rule, e.g. RULE ADD {"action":"deny","services":["echo"]}
  RULE INSERT <pos> <json>        insert a rule at position pos (1 = top)
  RULE DEL|ENABLE|DISABLE <id>
  FILTER ADD <json>               e.g. FILTER ADD {"type":"keyword","patterns":["exam"],"action":"block"}
  FILTER DEL|ENABLE|DISABLE <id>
  GROUP ADD|DEL <group> <user>
  DEFAULT allow|deny              action when no rule matches
  LIMIT <name> <value>            max_conns_per_user | max_new_conns_per_window | window_seconds
  RELOAD                          re-read the policy file now
  SAVE                            write the running policy back to the policy file
  STATS                           decisions per rule, hits per filter, top users
  LOG [n]                         last n access-log records (default 15)
  QUIT"""


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def _fmt_age(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"


class AdminServer:
    def __init__(self, proxy, host: str, port: int, token: str):
        self.proxy = proxy
        self.store = proxy.store
        self.registry = proxy.registry
        self.host, self.port, self.token = host, port, token
        self._stop = threading.Event()
        self._sock = None
        self.commands: Dict[str, Callable[[str], Tuple[bool, str]]] = {
            "HELP": lambda a: (True, HELP), "STATUS": self.status, "CONNS": self.conns, "KILL": self.kill,
            "RULES": self.rules, "FILTERS": self.filters, "SERVICES": self.services, "SHOW": self.show,
            "BLOCK": self.block, "UNBLOCK": self.unblock, "RULE": self.rule, "FILTER": self.filter,
            "GROUP": self.group, "DEFAULT": self.default, "LIMIT": self.limit, "RELOAD": self.reload,
            "SAVE": self.save, "STATS": self.stats, "LOG": self.log_tail,
        }

    # ------------------------------------------------------------------ network
    def start(self) -> int:
        s = socket.socket(socket.AF_INET6 if ":" in self.host else socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(8)
        s.settimeout(0.5)
        self._sock = s
        self.port = s.getsockname()[1]
        threading.Thread(target=self._accept_loop, name="admin", daemon=True).start()
        return self.port

    def stop(self):
        self._stop.set()
        if self._sock:
            self._sock.close()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                sock, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(sock, addr), daemon=True).start()

    def _serve(self, sock: socket.socket, addr):
        peer = f"{addr[0]}:{addr[1]}"
        try:
            sock.settimeout(10)
            ssock = self.proxy.tls_ctx.wrap_socket(sock, server_side=True)
            ssock.settimeout(1800)
            rfile = ssock.makefile("rb")

            def reply(ok: bool, text: str = ""):
                lines = [("OK" if ok else "ERR") + (f" {text.splitlines()[0]}" if text else "")]
                lines += ["." + ln if ln.startswith(".") else ln for ln in text.splitlines()[1:]]
                ssock.sendall(("\n".join(lines) + "\n.\n").encode("utf-8"))

            reply(True, f"netproxy {__version__} admin console - send: AUTH <token>")
            authed, failures = False, 0
            while True:
                raw = rfile.readline(1 << 16)
                if not raw:
                    break
                text = raw.decode("utf-8", "replace").strip()
                if not text:
                    continue
                if not authed:
                    word, _, tok = text.partition(" ")
                    if word.upper() == "AUTH" and hmac.compare_digest(tok.strip().encode(), self.token.encode()):
                        authed = True
                        log.info("admin %s authenticated", peer)
                        reply(True, "authenticated - type HELP for commands")
                    else:
                        failures += 1
                        log.warning("admin %s: authentication failed (%d)", peer, failures)
                        self.registry.count("admin_auth_failures")
                        reply(False, "authentication required: AUTH <token>")
                        if failures >= 3:
                            break
                    continue
                if text.upper() in ("QUIT", "EXIT"):
                    reply(True, "bye")
                    break
                ok, out = self.execute(text)
                self.registry.log({"event": "admin", "peer": peer, "command": text[:200], "ok": ok})
                reply(ok, out)
        except (OSError, ssl.SSLError) as e:
            log.debug("admin %s: %s", peer, e)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def execute(self, text: str) -> Tuple[bool, str]:
        cmd, _, args = text.strip().partition(" ")
        handler = self.commands.get(cmd.upper())
        if handler is None:
            return False, f"unknown command {cmd!r} - type HELP"
        try:
            return handler(args.strip())
        except PolicyError as e:
            return False, f"rejected, policy unchanged: {e}"
        except (ValueError, KeyError, IndexError, json.JSONDecodeError) as e:
            return False, f"bad arguments: {e}"

    # ------------------------------------------------------------------ helpers
    def _apply(self, fn, source: str) -> Tuple[bool, str]:
        new, result = self.store.mutate(fn, source=f"admin: {source}")
        killed = self.proxy.last_revalidation
        msg = f"{result}  -> policy v{new.version}"
        if killed:
            msg += f"; terminated {len(killed)} live connection(s): " + ", ".join(
                f"#{c.id} {c.user}->{c.service}" for c, _ in killed)
        return True, msg

    @staticmethod
    def _find(items: List[dict], ident: str) -> int:
        for i, it in enumerate(items):
            if it.get("id") == ident:
                return i
        raise KeyError(f"no entry with id {ident!r}")

    # ------------------------------------------------------------------ read-only commands
    def status(self, _):
        p, r, cfg = self.store.policy, self.registry, self.proxy.cfg
        ports = self.proxy.ports
        lines = [
            f"netproxy {__version__}   up {_fmt_age(time.time() - r.started)}",
            f"policy      v{p.version} '{p.name}' digest {p.digest}  default={p.default_action}  "
            f"({len(p.rules)} rules, {len(p.filters)} filters)  last change: {self.store.last_source}",
            f"listeners   tls {cfg.listen_host}:{ports.get('tls')}   plain "
            f"{(cfg.listen_host + ':' + str(ports['plain'])) if 'plain' in ports else 'off'}   admin "
            f"{cfg.admin_host}:{ports.get('admin')}",
            f"connections active {len(r.active())}  total {r.counters['connections']}  allowed "
            f"{r.counters['allowed']}  denied {r.counters['denied']}  rate-limited {r.counters['rate_limited']}  "
            f"tls-failures {r.counters['tls_failures']}",
            f"traffic     up {_fmt_bytes(r.counters['bytes_up'] + sum(c.bytes_up for c in r.active()))}  "
            f"down {_fmt_bytes(r.counters['bytes_down'] + sum(c.bytes_down for c in r.active()))}",
        ]
        if self.store.last_error:
            lines.append(f"last policy file error: {self.store.last_error}")
        return True, "\n".join(lines)

    def conns(self, _):
        rows = self.registry.active()
        if not rows:
            return True, "no open connections"
        out = [f"{len(rows)} open connection(s)",
               f"{'ID':>5}  {'USER':<10} {'SOURCE':<21} {'SERVICE':<13} {'MODE':<7} {'INSPECT':<7} "
               f"{'TLS':<8} {'AGE':>7} {'UP':>9} {'DOWN':>9} REQS"]
        for c in rows:
            out.append(f"{c.id:>5}  {c.user[:10]:<10} {(c.src + ':' + str(c.src_port))[:21]:<21} "
                       f"{c.service[:13]:<13} {c.mode:<7} {c.inspect:<7} {c.tls[:8]:<8} {_fmt_age(c.age()):>7} "
                       f"{_fmt_bytes(c.bytes_up):>9} {_fmt_bytes(c.bytes_down):>9} {c.requests}")
        return True, "\n".join(out)

    def rules(self, _):
        p = self.store.policy
        lines = [f"{len(p.rules)} rule(s), first match wins; default = {p.default_action}"]
        lines += [f"{i:>2}. {r.describe()}" for i, r in enumerate(p.rules, 1)]
        return True, "\n".join(lines)

    def filters(self, _):
        p = self.store.policy
        return True, "\n".join([f"{len(p.filters)} content filter(s)"] + [f.describe() for f in p.filters])

    def services(self, _):
        p = self.store.policy
        lines = [f"{len(p.services)} service(s)"]
        for s in p.services.values():
            alias = f"  aliases={','.join(s.aliases)}" if s.aliases else ""
            lines.append(f"{s.name:<14} {s.host}:{s.port:<6} inspect={s.inspect:<5}{alias}  {s.description}")
        return True, "\n".join(lines)

    def show(self, _):
        p = self.store.policy
        return True, f"policy v{p.version}\n" + p.to_json().rstrip()

    def stats(self, _):
        r = self.registry
        lines = ["decisions by rule:"]
        for (rid, action), n in sorted(r.rule_hits.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {rid:<16} {action:<5} {n}")
        lines.append("content filter hits:")
        if not r.filter_hits:
            lines.append("  (none)")
        for (fid, action), n in sorted(r.filter_hits.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {fid:<16} {action:<6} {n}")
        lines.append("connections by user:")
        for user, n in r.user_conns.most_common(10):
            lines.append(f"  {user:<16} {n}")
        return True, "\n".join(lines)

    def log_tail(self, args):
        n = int(args or 15)
        recs = list(self.registry.recent_log)[-n:]
        return True, f"last {len(recs)} record(s)\n" + "\n".join(json.dumps(x) for x in recs)

    # ------------------------------------------------------------------ actions
    def kill(self, args):
        parts = args.split()
        if len(parts) == 2 and parts[0].lower() == "user":
            hit = [c for c in self.registry.active() if c.user == parts[1] and c.kill("killed by administrator")]
            return True, f"killed {len(hit)} connection(s) of {parts[1]}"
        c = self.registry.get(int(parts[0]))
        if c is None:
            return False, f"no open connection #{parts[0]}"
        c.kill("killed by administrator")
        return True, f"connection #{c.id} ({c.user} -> {c.service}) terminated"

    def block(self, args):
        kind, _, value = args.partition(" ")
        kind, value = kind.lower(), value.strip()
        if not value:
            raise ValueError("usage: BLOCK user|group|ip|service <value>")
        rule = {"action": "deny", "reason": f"{kind} '{value}' blocked by administrator"}
        if kind == "user":
            rule["users"] = [value]
        elif kind == "group":
            rule["users"] = ["@" + value.lstrip("@")]
        elif kind == "ip":
            ipaddress.ip_network(value, strict=False)
            rule["src"] = [value]
        elif kind == "service":
            rule["services"] = [value]
        else:
            raise ValueError("usage: BLOCK user|group|ip|service <value>")

        def fn(doc):
            rules = doc.setdefault("rules", [])
            taken, n = {r.get("id") for r in rules}, 1
            while f"DYN-{n}" in taken:
                n += 1
            rules.insert(0, {"id": f"DYN-{n}", **rule})
            return f"added deny rule DYN-{n} at the top"
        return self._apply(fn, f"BLOCK {kind} {value}")

    def unblock(self, args):
        return self.rule(f"DEL {args}")

    def rule(self, args):
        sub, _, rest = args.partition(" ")
        sub = sub.upper()
        if sub == "ADD":
            item = json.loads(rest)
            return self._apply(lambda d: (d.setdefault("rules", []).append(item), "rule appended")[1], "RULE ADD")
        if sub == "INSERT":
            pos, _, js = rest.strip().partition(" ")
            item, index = json.loads(js), max(int(pos) - 1, 0)
            return self._apply(lambda d: (d.setdefault("rules", []).insert(index, item),
                                          f"rule inserted at position {index + 1}")[1], "RULE INSERT")
        if sub == "DEL":
            ident = rest.strip()

            def fn(doc):
                doc["rules"].pop(self._find(doc["rules"], ident))
                return f"rule {ident} removed"
            return self._apply(fn, f"RULE DEL {ident}")
        if sub in ("ENABLE", "DISABLE"):
            ident = rest.strip()

            def fn(doc):
                doc["rules"][self._find(doc["rules"], ident)]["enabled"] = sub == "ENABLE"
                return f"rule {ident} {sub.lower()}d"
            return self._apply(fn, f"RULE {sub} {ident}")
        raise ValueError("usage: RULE ADD <json> | RULE INSERT <pos> <json> | RULE DEL|ENABLE|DISABLE <id>")

    def filter(self, args):
        sub, _, rest = args.partition(" ")
        sub = sub.upper()
        if sub == "ADD":
            item = json.loads(rest)
            return self._apply(lambda d: (d.setdefault("content_filters", []).append(item), "filter added")[1],
                               "FILTER ADD")
        if sub == "DEL":
            ident = rest.strip()

            def fn(doc):
                doc["content_filters"].pop(self._find(doc["content_filters"], ident))
                return f"filter {ident} removed"
            return self._apply(fn, f"FILTER DEL {ident}")
        if sub in ("ENABLE", "DISABLE"):
            ident = rest.strip()

            def fn(doc):
                doc["content_filters"][self._find(doc["content_filters"], ident)]["enabled"] = sub == "ENABLE"
                return f"filter {ident} {sub.lower()}d"
            return self._apply(fn, f"FILTER {sub} {ident}")
        raise ValueError("usage: FILTER ADD <json> | FILTER DEL|ENABLE|DISABLE <id>")

    def group(self, args):
        sub, group, user = (args.split() + ["", "", ""])[:3]
        if sub.upper() not in ("ADD", "DEL") or not group or not user:
            raise ValueError("usage: GROUP ADD|DEL <group> <user>")

        def fn(doc):
            members = doc.setdefault("groups", {}).setdefault(group, [])
            if sub.upper() == "ADD":
                if user not in members:
                    members.append(user)
                return f"{user} added to group {group}"
            if user not in members:
                raise KeyError(f"{user} is not in group {group}")
            members.remove(user)
            return f"{user} removed from group {group}"
        return self._apply(fn, f"GROUP {sub.upper()} {group} {user}")

    def default(self, args):
        action = args.strip().lower()
        if action not in ("allow", "deny"):
            raise ValueError("usage: DEFAULT allow|deny")

        def fn(doc):
            doc["default_action"] = action
            return f"default action is now {action}"
        return self._apply(fn, f"DEFAULT {action}")

    def limit(self, args):
        name, _, value = args.partition(" ")
        num = float(value) if name == "window_seconds" else int(value)

        def fn(doc):
            doc.setdefault("limits", {})[name] = num
            return f"limit {name} = {num}"
        return self._apply(fn, f"LIMIT {name} {num}")

    def reload(self, _):
        changed, msg = self.store.reload(source="admin: RELOAD")
        killed = self.proxy.last_revalidation if changed else []
        if killed:
            msg += f"; terminated {len(killed)} live connection(s)"
        return (changed or msg.startswith("policy file unchanged")), msg

    def save(self, _):
        path = self.store.save()
        return True, f"policy v{self.store.policy.version} written to {path}"
