"""AccessWindow block page for blocked HTTPS sites (local demo).

A browser never shows the proxy's reply to a refused CONNECT -- it shows its own "site can't be reached" page (and
YouTube's service worker even serves its cached "You're offline" page). To show a real page for a blocked HTTPS site,
the proxy answers the CONNECT itself and completes the TLS handshake with a certificate it signs for that one host,
using a dedicated local CA (certs/blockpage/ca.crt). The browser must trust that CA once; see README_ACCESSWINDOW.md.

Only BLOCKED hosts are intercepted. Allowed traffic is still tunnelled end to end and never decrypted.
Needs only the `openssl` command-line tool (preinstalled on macOS).
"""
from __future__ import annotations
import html, ipaddress, os, re, shutil, socket, ssl, subprocess, threading, time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

CA_COMMON_NAME = "AccessWindow Block Page CA"
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
LEAF_DAYS, LEAF_REFRESH_DAYS = 30, 20          # leaf certificates are short-lived; macOS also limits their lifetime


class BlockPage:
    def __init__(self, root, dashboard="http://127.0.0.1:5000", clear_site_data=True):
        self.dir = Path(root) / "certs" / "blockpage"
        self.dashboard = dashboard.rstrip("/")
        self.clear_site_data = clear_site_data
        self._ctx = {}
        self._lock = threading.Lock()

    @property
    def ca_cert(self):
        return self.dir / "ca.crt"

    # ------------------------------------------------------------------ certificates (openssl CLI)
    def _openssl(self, *args):
        exe = shutil.which("openssl")
        if not exe:
            raise RuntimeError("the 'openssl' tool is required for the block page")
        subprocess.run([exe, *args], check=True, capture_output=True)

    def ensure_ca(self):
        """Create the dedicated CA and the shared leaf key on first use."""
        with self._lock:
            self.dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.dir, 0o700)
            ca_key, ca_crt, leaf_key = self.dir / "ca.key", self.ca_cert, self.dir / "leaf.key"
            if not (ca_key.exists() and ca_crt.exists()):
                cnf = self.dir / "ca.cnf"
                cnf.write_text(f"[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN={CA_COMMON_NAME}\n"
                               "O=AccessWindow local demo\n[v3]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n"
                               "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
                self._openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key))
                self._openssl("req", "-x509", "-new", "-key", str(ca_key), "-days", "1095", "-config", str(cnf), "-out", str(ca_crt))
                os.chmod(ca_key, 0o600)
            if not leaf_key.exists():
                self._openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(leaf_key))
                os.chmod(leaf_key, 0o600)

    def _issue(self, host):
        leaf_dir = self.dir / "leaf"
        leaf_dir.mkdir(exist_ok=True)
        pem = leaf_dir / f"{host}.pem"
        if pem.exists() and time.time() - pem.stat().st_mtime < LEAF_REFRESH_DAYS * 86400:
            return pem
        ext, csr, crt = leaf_dir / f"{host}.ext", leaf_dir / f"{host}.csr", leaf_dir / f"{host}.crt"
        ext.write_text(f"subjectAltName=DNS:{host}\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=CA:FALSE\n")
        cn = host if len(host) <= 64 else "blocked-site"
        self._openssl("req", "-new", "-key", str(self.dir / "leaf.key"), "-subj", f"/CN={cn}", "-out", str(csr))
        self._openssl("x509", "-req", "-in", str(csr), "-CA", str(self.ca_cert), "-CAkey", str(self.dir / "ca.key"),
                      "-CAcreateserial", "-days", str(LEAF_DAYS), "-extfile", str(ext), "-out", str(crt))
        pem.write_text(crt.read_text() + (self.dir / "leaf.key").read_text())
        for tmp in (ext, csr, crt):
            tmp.unlink(missing_ok=True)
        return pem

    def context_for(self, host):
        """TLS context presenting a CA-signed certificate for host, or None if host can't be intercepted safely."""
        host = host.lower().rstrip(".")
        if not HOST_RE.match(host):
            return None
        try:
            ipaddress.ip_address(host)
            return None                                   # a certificate for a bare IP needs different handling
        except ValueError:
            pass
        with self._lock:
            ctx = self._ctx.get(host)
            if ctx is None:
                try:
                    pem = self._issue(host)
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.load_cert_chain(str(pem))
                except (OSError, ssl.SSLError, subprocess.CalledProcessError, RuntimeError):
                    return None
                self._ctx[host] = ctx
            return ctx

    # ------------------------------------------------------------------ the page
    def link(self, user, domain):
        if user == "admin":
            return f"{self.dashboard}/websites", "Manage this rule"
        return f"{self.dashboard}/requests?domain={quote(domain)}#site-access", "Request temporary access"

    def page(self, host, user, rule, domain=None):
        rule = rule or {}
        e = html.escape
        who = rule.get("created_by")
        since = ""
        if rule.get("created_at"):
            since = " on " + datetime.fromtimestamp(float(rule["created_at"])).strftime("%d %b %Y, %I:%M %p")
        users = rule.get("users") or ["*"]
        applies = "everyone" if "*" in users else ", ".join(users)
        href, label = self.link(user, domain or host)
        cleanup = ""
        if self.clear_site_data:
            cleanup = ("<script>(async()=>{try{"
                       "if('serviceWorker' in navigator){(await navigator.serviceWorker.getRegistrations()).forEach(r=>r.unregister());}"
                       "if(window.caches){(await caches.keys()).forEach(k=>caches.delete(k));}"
                       "if(window.indexedDB&&indexedDB.databases){(await indexedDB.databases()).forEach(d=>d.name&&indexedDB.deleteDatabase(d.name));}"
                       "}catch(e){}})();</script>")
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blocked · {e(host)}</title><style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#1b1f3b;
background:radial-gradient(900px 500px at 90% -10%,#e3e0ff,transparent 60%),radial-gradient(800px 500px at -10% 110%,#d8f3ff,transparent 55%),#f4f6ff}}
.card{{width:min(680px,100%);background:#fff;border:1px solid #ffc2cd;border-radius:24px;padding:36px;box-shadow:0 24px 70px rgba(229,53,77,.16)}}
.icon{{width:72px;height:72px;border-radius:22px;display:grid;place-items:center;background:linear-gradient(135deg,#ff5d78,#e5354d);box-shadow:0 10px 26px rgba(229,53,77,.4);margin-bottom:20px}}
.icon svg{{width:38px;height:38px;stroke:#fff;fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}}
.tag{{font-size:12px;font-weight:800;letter-spacing:1.6px;color:#c4243b}}h1{{margin:6px 0 10px;font-size:28px;letter-spacing:-.6px;word-break:break-word}}
.reason{{font-size:18px;font-style:italic;color:#6a2330;margin:0 0 22px}}
dl{{display:grid;grid-template-columns:auto 1fr;gap:10px 18px;margin:0 0 26px;padding:18px 20px;background:#fff6f7;border:1px solid #ffd6dd;border-radius:16px;font-size:15px}}
dt{{color:#8d5560;font-weight:600}}dd{{margin:0;font-weight:700}}
a.btn{{display:inline-block;text-decoration:none;color:#fff;font-weight:700;padding:13px 22px;border-radius:12px;background:linear-gradient(135deg,#6a5cff,#5a4df5);box-shadow:0 6px 18px rgba(90,77,245,.4)}}
a.btn:hover{{filter:brightness(1.08)}}.foot{{margin-top:22px;font-size:13px;color:#7b82aa}}
</style></head><body><main class="card">
<div class="icon"><svg viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 4.5 3.2 8 8 9 4.8-1 8-4.5 8-9V6z"/><path d="m9 9 6 6M15 9l-6 6"/></svg></div>
<div class="tag">ACCESS BLOCKED</div><h1>{e(host)} is restricted</h1>
<p class="reason">&ldquo;{e(rule.get("reason") or "Blocked by website policy")}&rdquo;</p>
<dl><dt>Restricted by</dt><dd>{e(who) if who else "an administrator"}{e(since)}</dd>
<dt>Applies to</dt><dd>{e(applies)}</dd><dt>Rule</dt><dd>{e(rule.get("id") or "website policy")}</dd><dt>Signed in as</dt><dd>{e(user)}</dd></dl>
<a class="btn" href="{e(href)}">{e(label)} &rarr;</a>
<p class="foot">AccessWindow · access is decided by the proxy before the site is contacted. Access you are granted ends automatically.</p>
</main>{cleanup}</body></html>"""

    # ------------------------------------------------------------------ serving
    def http_response(self, host, user, rule, domain=None):
        """Complete HTTP response for a plain-HTTP blocked request."""
        body = self.page(host, user, rule, domain).encode()
        return (b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n"
                b"Connection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

    def serve(self, conn, host, user, rule, domain=None):
        """Answer a blocked CONNECT with the block page over TLS. False means 'not handled, send a plain 403'."""
        ctx = self.context_for(host)
        if ctx is None:
            return False
        try:
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tls = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            return True                                   # browser rejected the certificate (CA not trusted yet)
        try:
            tls.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 16384:
                chunk = tls.recv(4096)
                if not chunk:
                    return True
                data += chunk
            lines = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1").split("\r\n")
            headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
            method = lines[0].split(" ", 1)[0].upper()
            dest = headers.get("sec-fetch-dest")
            navigation = dest in ("document", "iframe", "frame") if dest else "text/html" in headers.get("accept", "")
            if navigation:
                body = self.page(host, user, rule, domain).encode()
                extra = b'Clear-Site-Data: "cache", "storage"\r\n' if self.clear_site_data else b""
                head = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n"
                        + extra + b"Connection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n")
                tls.sendall(head + (b"" if method == "HEAD" else body))
            else:                                         # images, scripts, the service worker file...: just refuse
                tls.sendall(b"HTTP/1.1 403 Forbidden\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        except (ssl.SSLError, OSError, socket.timeout, ValueError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass
        return True
