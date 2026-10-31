"""
adminctl.py -- the admin console client.

    python adminctl.py                      # interactive console
    python adminctl.py STATUS               # one command and exit
    python adminctl.py BLOCK user bob       # bob's open sessions are cut immediately
    python adminctl.py UNBLOCK DYN-1
    python adminctl.py RULE INSERT 1 '{"action":"deny","services":["echo"],"reason":"maintenance"}'

The token is read from config/proxy.json (admin_token) unless --token is given.
"""
from __future__ import annotations

import argparse
import json
import sys

from netproxy.clientlib import AdminClient
from netproxy.config import ROOT


def main():
    ap = argparse.ArgumentParser(description="netproxy admin console")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="command to run (omit for interactive mode)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=None, help="admin port (default from config)")
    ap.add_argument("--token", help="admin token (default from config/proxy.json)")
    args = ap.parse_args()

    try:
        with open(ROOT / "config" / "proxy.json", "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except OSError:
        cfg = {}
    port = args.port or cfg.get("admin_port", 9443)
    token = args.token or cfg.get("admin_token", "")
    try:
        admin = AdminClient(args.host, port, token)
    except PermissionError as e:
        sys.exit(f"authentication failed: {e}")
    except OSError as e:
        sys.exit(f"cannot reach the admin console at {args.host}:{port}: {e}")

    with admin:
        if args.command:
            ok, text = admin.command(" ".join(args.command))
            print(text)
            sys.exit(0 if ok else 1)
        print(f"connected to {args.host}:{port} - type HELP, QUIT to leave")
        while True:
            try:
                line = input("netproxy> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            if line.upper() in ("QUIT", "EXIT"):
                break
            ok, text = admin.command(line)
            print(text if ok else f"ERROR: {text}")


if __name__ == "__main__":
    main()
