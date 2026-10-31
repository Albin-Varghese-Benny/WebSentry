"""
client.py -- reach the simulated services through the proxy.

    python client.py web /news                         # anonymous, GET /news
    python client.py --user bob web /news /admin/panel # as bob (client certificate), two requests, one tunnel
    python client.py --user bob chat                   # interactive chat session
    python client.py --user alice files --send LIST --send "GET memo.txt"
    python client.py --plain echo --send hello          # plaintext listener (proxy started with --plain-port 8080)
    python client.py --forward http://web/billing      # forward-proxy request (like a browser)

Without --send, line services (chat, files, echo) start an interactive session:
type lines, Ctrl+C or Ctrl+D/Ctrl+Z to quit.
"""
from __future__ import annotations

import argparse
import queue
import select
import socket
import ssl
import sys
import threading

from netproxy.clientlib import ProxyClient, ProxyRefused, nb_send_all


def show_response(r, show_headers: bool):
    print(f"<<< HTTP {r.status} {r.reason}")
    for k in ("x-proxy-rule", "x-proxy-reason", "x-proxy-filtered", "content-type"):
        if r.header(k) and (show_headers or k.startswith("x-proxy")):
            print(f"    {k}: {r.header(k)}")
    if show_headers:
        for k, v in r.headers.items():
            if not k.startswith("x-proxy") and k != "content-type":
                print(f"    {k}: {v}")
    ctype = r.header("content-type")
    if ctype.startswith("text/html"):
        print(html_to_text(r.text))
    elif ctype.startswith(("text/", "application/json")):
        print(r.text.rstrip())
    elif r.body:
        print(f"    [{len(r.body)} bytes of {ctype or 'binary data'}]")
    print()


def html_to_text(html: str) -> str:
    """Crude HTML -> text so pages are readable in a terminal."""
    import re
    from html import unescape
    html = re.sub(r"(?is)<(style|script|title).*?</\1>", "", html)
    html = re.sub(r"(?i)<br\s*/?>|</p>|</li>|</h1>|</tr>|<nav>|</nav>", "\n", html)
    html = re.sub(r"(?i)<td>", " ", html)
    text = unescape(re.sub(r"<[^>]+>", "", html)).replace("\u00b7", "-").replace("\u2013", "-")
    return "\n".join("    " + ln.strip() for ln in text.splitlines() if ln.strip())


def interactive(tunnel):
    """Relay stdin lines to the service and print whatever it sends (works on Windows too)."""
    print("--- connected; type lines and press Enter (Ctrl+C to quit) ---")
    lines: "queue.Queue" = queue.Queue()

    def read_stdin():
        try:
            for line in sys.stdin:
                lines.put(line)
        except (OSError, ValueError):
            pass
        lines.put(None)

    threading.Thread(target=read_stdin, daemon=True).start()
    sock = tunnel.sock
    pending = tunnel.reader.take()
    if pending:
        sys.stdout.write(pending.decode("utf-8", "replace"))
        sys.stdout.flush()
    sock.setblocking(False)
    try:
        while True:
            while True:                                  # drain everything the proxy sent
                try:
                    data = sock.recv(65536)
                except (ssl.SSLWantReadError, BlockingIOError):
                    break
                except (OSError, ssl.SSLError):
                    data = b""
                if not data:
                    print("\n--- connection closed by the proxy ---")
                    return
                sys.stdout.write(data.decode("utf-8", "replace"))
                sys.stdout.flush()
            try:
                line = lines.get(timeout=0.05)
            except queue.Empty:
                select.select([sock], [], [], 0.05)
                continue
            if line is None:
                return
            nb_send_all(sock, line.encode("utf-8"))
    except KeyboardInterrupt:
        print("\n--- bye ---")


def main():
    ap = argparse.ArgumentParser(description="Client for the netproxy simulated services")
    ap.add_argument("service", nargs="?", help="service name: web, chat, files, echo, ...")
    ap.add_argument("paths", nargs="*", help="for web: paths to GET (default /)")
    ap.add_argument("--proxy", help="proxy HOST:PORT (default 127.0.0.1:8443, or :8080 with --plain)")
    ap.add_argument("--user", help="identity: uses certs/clients/USER.crt (default: anonymous)")
    ap.add_argument("--plain", action="store_true", help="plaintext connection (proxy must run --plain-port)")
    ap.add_argument("--send", action="append", help="line to send (repeatable); then print replies and exit")
    ap.add_argument("--method", default="GET", help="HTTP method for web requests")
    ap.add_argument("--site", help="simulated website hostname, e.g. github.test (web service only)")
    ap.add_argument("--data", help="request body for POST/PUT")
    ap.add_argument("--forward", metavar="URL", help="send one absolute-URL request instead of CONNECT")
    ap.add_argument("--headers", action="store_true", help="print all response headers")
    args = ap.parse_args()

    if not args.proxy:
        args.proxy = "127.0.0.1:8080" if args.plain else "127.0.0.1:8443"
    host, _, port = args.proxy.rpartition(":")
    who = args.user or "anonymous"
    try:
        client = ProxyClient(host or "127.0.0.1", int(port), tls=not args.plain, user=args.user)
    except FileNotFoundError:
        sys.exit(f"no certificate for '{who}' in certs/clients/ - create one with: python gen_certs.py --add-user {who}")
    try:
        if args.forward:
            print(f">>> {args.method} {args.forward}  (forward-proxy mode, as {who})")
            show_response(client.forward(args.forward, args.method, (args.data or "").encode()), args.headers)
            return
        if not args.service:
            ap.error("give a service name or --forward URL")
        print(f">>> CONNECT {args.service} via {args.proxy} ({'plain TCP' if args.plain else 'TLS'}, as {who})")
        try:
            tunnel = client.connect(args.service)
        except ProxyRefused as e:
            print(f"<<< {e.status} {e.reason}\n    rule:   {e.rule}\n    reason: {e.detail}")
            sys.exit(1)
        print(f"<<< 200 Connection Established  (rule {tunnel.rule}, inspect={tunnel.inspect}, "
              f"user={tunnel.user})\n")
        with tunnel:
            if tunnel.inspect == "http":
                for path in args.paths or ["/"]:
                    body = (args.data or "").encode()
                    print(f">>> {args.method} {path}")
                    try:
                        show_response(tunnel.request(args.method, path, body, ({"Host": args.site} if args.site else None)), args.headers)
                    except (ConnectionError, OSError) as e:
                        print(f"<<< connection closed: {e}")
                        break
            elif args.send:
                out = tunnel.recv_for(0.4)
                if out:
                    sys.stdout.write(out.decode("utf-8", "replace"))
                for line in args.send:
                    print(f">>> {line}")
                    tunnel.send_line(line)
                    out = tunnel.recv_for(0.5)
                    sys.stdout.write(out.decode("utf-8", "replace"))
                    if tunnel.is_closed(0.1):
                        print("--- connection closed by the proxy ---")
                        break
            else:
                interactive(tunnel)
    except (ConnectionRefusedError, socket.timeout) as e:
        sys.exit(f"cannot reach the proxy at {args.proxy}: {e}")
    except ssl.SSLError as e:
        sys.exit(f"TLS error: {e}")
    except FileNotFoundError as e:
        sys.exit(f"missing file: {e.filename}")


if __name__ == "__main__":
    main()
