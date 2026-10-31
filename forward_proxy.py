"""AccessWindow real-domain HTTP/HTTPS forward proxy (local demo).

Run: python3 forward_proxy.py --host 127.0.0.1 --port 8080
Configure macOS HTTP and HTTPS proxies to 127.0.0.1:8080.
This filters destination hostnames only; HTTPS payloads remain encrypted.
"""
from __future__ import annotations
import argparse, base64, json, os, socket, socketserver, threading, time, urllib.parse
from pathlib import Path

import blockpage

ROOT = Path(__file__).resolve().parent
POLICY_PATH = ROOT / "config" / "real_website_policy.json"
LOG_PATH = ROOT / "logs" / "real_proxy_access.jsonl"
LOG_LOCK = threading.Lock()
BLOCK_PAGE = None            # set by --block-page: shows a real page for blocked sites (see blockpage.py)
DEFAULT_USERS = {
    os.environ.get("ACCESSWINDOW_BOB_USERNAME", "bob"): os.environ.get("ACCESSWINDOW_BOB_PASSWORD", "bob-demo"),
    os.environ.get("ACCESSWINDOW_CAROL_USERNAME", "carol"): os.environ.get("ACCESSWINDOW_CAROL_PASSWORD", "carol-demo"),
    os.environ.get("ACCESSWINDOW_ADMIN_USERNAME", "admin"): os.environ.get("ACCESSWINDOW_ADMIN_PASSWORD", "admin-demo"),
}

_POLICY_CACHE = {"key": None, "data": None}

def read_policy():
    try:
        st = POLICY_PATH.stat()
        key = (str(POLICY_PATH), st.st_mtime_ns, st.st_size, st.st_ino)
        if _POLICY_CACHE["key"] == key: return _POLICY_CACHE["data"]
        data = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("rules"), list):
            _POLICY_CACHE.update(key=key, data=data)
            return data
    except (OSError, json.JSONDecodeError): pass
    return {"default_action": "allow", "rules": []}

def rule_expired(rule, now=None):
    """Temporary (AccessWindow-approved) rules carry an expires_at epoch and stop applying after it."""
    expires = rule.get("expires_at")
    if expires is None: return False
    try: return float(expires) <= (time.time() if now is None else now)
    except (TypeError, ValueError): return True

# Some sites are really several domains. Blocking (or allowing) the main name covers the rest, otherwise e.g. YouTube
# video (googlevideo.com) keeps playing after youtube.com is blocked.
DOMAIN_FAMILIES = {"youtube.com": ("googlevideo.com", "ytimg.com", "youtu.be", "youtube-nocookie.com")}

def domain_hit(host, rule):
    """The rule domain that covers host (itself, a subdomain, or a related domain of it), else None."""
    for domain in rule.get("domains", []):
        domain = domain.lower().strip().lstrip(".").rstrip(".")
        for d in (domain, *DOMAIN_FAMILIES.get(domain, ())):
            if host == d or host.endswith("." + d):
                return domain
    return None

def match_rule(host, user):
    host = host.lower().rstrip(".")
    policy = read_policy()
    for rule in policy.get("rules", []):
        if not rule.get("enabled", True) or rule_expired(rule): continue
        users = rule.get("users", ["*"])
        if users and "*" not in users and user not in users: continue
        if domain_hit(host, rule):
            return rule.get("action", "deny"), rule
    return policy.get("default_action", "allow"), None

def log_event(user, host, method, action, rule=None, detail=""):
    item = {"time": time.time(), "user": user, "domain": host, "method": method,
            "decision": action, "rule_id": (rule or {}).get("id"),
            "reason": (rule or {}).get("reason") or detail or ("Allowed by default policy" if action == "allow" else "Blocked by policy"),
            "status": 403 if action == "deny" else 200}
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_LOCK, LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, separators=(",", ":")) + "\n")

def send(sock, data):
    try: sock.sendall(data)
    except OSError: pass

class Handler(socketserver.StreamRequestHandler):
    timeout = 15
    def handle(self):
        self.connection.settimeout(15)
        line = self.rfile.readline(65537)
        if not line or len(line) > 65536: return
        try: method, target, version = line.decode("iso-8859-1").strip().split(" ", 2)
        except ValueError: return
        headers = []
        header_map = {}
        total = len(line)
        while True:
            h = self.rfile.readline(65537); total += len(h)
            if not h or h in (b"\r\n", b"\n"): break
            if total > 131072: return
            try: k, v = h.decode("iso-8859-1").split(":", 1)
            except ValueError: continue
            key = k.strip().lower(); val = v.strip()
            header_map[key] = val
            if key not in {"proxy-authorization", "proxy-connection", "connection", "keep-alive"}:
                headers.append((k.strip(), val))
        user = self.authenticate(header_map.get("proxy-authorization", ""))
        if not user:
            send(self.connection, b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"AccessWindow\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        try:
            if method.upper() == "CONNECT":
                host, port = target.rsplit(":", 1); port = int(port)
            else:
                parsed = urllib.parse.urlsplit(target)
                if parsed.scheme not in ("http", "https") or not parsed.hostname:
                    send(self.connection, b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); return
                host = parsed.hostname; port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except (ValueError, TypeError):
            send(self.connection, b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); return
        decision, rule = match_rule(host, user)
        if decision != "allow":
            log_event(user, host, method.upper(), "deny", rule)
            domain = domain_hit(host.lower(), rule or {}) or host
            if BLOCK_PAGE and method.upper() == "CONNECT" and port == 443 and BLOCK_PAGE.serve(self.connection, host, user, rule, domain):
                return
            if BLOCK_PAGE and method.upper() != "CONNECT":
                send(self.connection, BLOCK_PAGE.http_response(host, user, rule, domain)); return
            body = (f"AccessWindow blocked {host}\nReason: {(rule or {}).get('reason', 'Blocked by website policy')}\n"
                    "Need it for a few minutes? Sign in to the AccessWindow dashboard (http://127.0.0.1:5000) and request temporary access.\n").encode()
            send(self.connection, b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            return
        log_event(user, host, method.upper(), "allow", rule)
        try:
            with socket.create_connection((host, port), timeout=8) as upstream:
                upstream.settimeout(15)
                if method.upper() == "CONNECT":
                    send(self.connection, b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: AccessWindow\r\n\r\n")
                    self.tunnel(upstream, (rule or {}).get("expires_at"), host, user)
                else:
                    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                    outgoing = f"{method} {path} {version}\r\n".encode("iso-8859-1")
                    for k, v in headers:
                        outgoing += f"{k}: {v}\r\n".encode("iso-8859-1")
                    outgoing += b"Connection: close\r\n\r\n"
                    upstream.sendall(outgoing)
                    while True:
                        chunk = upstream.recv(65536)
                        if not chunk: break
                        self.connection.sendall(chunk)
        except (OSError, socket.timeout) as exc:
            try: send(self.connection, b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError: pass
            log_event(user, host, method.upper(), "error", rule, str(exc)[:160])

    def authenticate(self, header):
        if not header.lower().startswith("basic "): return None
        try:
            raw = base64.b64decode(header.split(None, 1)[1]).decode("utf-8")
            username, password = raw.split(":", 1)
        except Exception: return None
        expected = DEFAULT_USERS.get(username)
        return username if expected is not None and password == expected else None

    def tunnel(self, upstream, deadline=None, host=None, user=None):
        import select
        sockets = [self.connection, upstream]
        last_data = last_check = time.time()
        while True:
            now = time.time()
            if now - last_data >= 60: break                              # idle
            if deadline is not None and now >= float(deadline): break    # temporary grant ended
            if host is not None and now - last_check >= 1.0:             # rule revoked/changed -> cut the open tunnel
                last_check = now
                if match_rule(host, user)[0] != "allow": break
            wait = 1.0 if deadline is None else max(0.0, min(1.0, float(deadline) - now))
            try: readable, _, _ = select.select(sockets, [], [], wait)
            except (OSError, ValueError): break
            for src in readable:
                dst = upstream if src is self.connection else self.connection
                try: data = src.recv(65536)
                except OSError: return
                if not data: return
                try: dst.sendall(data)
                except OSError: return
                last_data = time.time()

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def main():
    parser = argparse.ArgumentParser(description="AccessWindow real-domain HTTP/HTTPS forward proxy")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--block-page", action="store_true", help="show a real block page for blocked HTTPS sites (needs the block-page CA trusted once)")
    parser.add_argument("--dashboard", default="http://127.0.0.1:5000", help="dashboard URL used by the block page's request button")
    parser.add_argument("--keep-site-data", action="store_true", help="don't tell the browser to clear a blocked site's service worker and stored data")
    args = parser.parse_args()
    global BLOCK_PAGE
    if args.block_page:
        BLOCK_PAGE = blockpage.BlockPage(ROOT, args.dashboard, clear_site_data=not args.keep_site_data)
        BLOCK_PAGE.ensure_ca()
        print(f"Block page ON. Trust this CA once so browsers accept it:  {BLOCK_PAGE.ca_cert}")
        print("  macOS:  security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db \"" + str(BLOCK_PAGE.ca_cert) + "\"")
        print("  remove: security delete-certificate -c \"" + blockpage.CA_COMMON_NAME + "\" ~/Library/Keychains/login.keychain-db")
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not POLICY_PATH.exists(): POLICY_PATH.write_text(json.dumps({"default_action":"allow","rules":[]}, indent=2))
    print(f"AccessWindow forward proxy listening on {args.host}:{args.port}")
    print("Use as HTTP and HTTPS proxy. Demo accounts: bob/bob-demo, carol/carol-demo, admin/admin-demo")
    print("Local demo only: change demo passwords before any shared use. HTTPS is filtered by hostname, not decrypted.")
    with Server((args.host, args.port), Handler) as server: server.serve_forever()

if __name__ == "__main__": main()
