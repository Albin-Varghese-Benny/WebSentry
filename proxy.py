"""
proxy.py -- start the filtering proxy.

    python proxy.py                         # TLS on 0.0.0.0:8443, admin on 127.0.0.1:9443
    python proxy.py --plain-port 8080       # also a plaintext listener (Wireshark / browser demo)
    python proxy.py -v                      # log every decision and filter hit

Settings come from config/proxy.json, access rules from config/policy.json.
Edit and save the policy file while the proxy runs -- it is reloaded within a
second, and open connections that the new policy denies are closed.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from netproxy import __version__
from netproxy.config import ROOT, ProxyConfig
from netproxy.policy import PolicyError, PolicyStore
from netproxy.server import ProxyServer
from netproxy.accesswindow import start_expiry_worker


def main():
    ap = argparse.ArgumentParser(description="TLS TCP proxy with dynamic access control and content filtering")
    ap.add_argument("--config", default=str(ROOT / "config" / "proxy.json"), help="proxy settings file")
    ap.add_argument("--policy", help="policy file (overrides the one in the config)")
    ap.add_argument("--host", help="listen address (overrides listen_host)")
    ap.add_argument("--port", type=int, help="TLS port (overrides tls_port)")
    ap.add_argument("--plain-port", type=int, help="also listen for plaintext clients on this port")
    ap.add_argument("--admin-port", type=int, help="admin console port")
    ap.add_argument("--access-log", help="access log path (overrides the config)")
    ap.add_argument("--sdn-socket", help="UNIX socket of the SDN controller; denied requests are reported to it")
    ap.add_argument("--require-client-cert", action="store_true", help="refuse clients without a certificate")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    ap.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors on the console")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(level=level,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    cfg = ProxyConfig.load(args.config)
    if args.policy:
        cfg.policy_file = os.path.abspath(args.policy)
    if args.host:
        cfg.listen_host = args.host
    if args.port is not None:
        cfg.tls_port = args.port
    if args.plain_port is not None:
        cfg.plain_port = args.plain_port
    if args.admin_port is not None:
        cfg.admin_port = args.admin_port
    if args.access_log:
        cfg.access_log = os.path.abspath(args.access_log)
    if args.require_client_cert:
        cfg.require_client_cert = True

    for path in (cfg.cert, cfg.key, cfg.ca):
        if not os.path.exists(path):
            sys.exit(f"missing {path} - run:  python gen_certs.py")

    store = PolicyStore(cfg.policy_file)
    try:
        store.load()
    except (PolicyError, OSError) as e:
        sys.exit(f"cannot load policy {cfg.policy_file}: {e}")

    # AccessWindow grants expire inside the proxy process, even if the dashboard closes.
    server = ProxyServer(cfg, store)
    if args.sdn_socket:
        from netproxy.sdn import SdnNotifier
        server.registry.hook = SdnNotifier(args.sdn_socket).emit
    server.start()
    expiry_stop, expiry_thread = start_expiry_worker(store, ROOT / "config" / "accesswindow_state.json")
    p = store.policy
    print(f"netproxy {__version__}")
    print(f"  TLS listener     {cfg.listen_host}:{server.ports['tls']}")
    if "plain" in server.ports:
        print(f"  plain listener   {cfg.listen_host}:{server.ports['plain']}   (unencrypted - demo only)")
    if "admin" in server.ports:
        print(f"  admin console    {cfg.admin_host}:{server.ports['admin']}   (python adminctl.py)")
    print(f"  policy           {cfg.policy_file}  v{p.version}: {len(p.services)} services, "
          f"{len(p.rules)} rules, {len(p.filters)} filters, default {p.default_action}")
    print(f"  access log       {cfg.access_log}")
    if cfg.admin_token == "change-me":
        print("  WARNING: admin_token is still 'change-me' - set it in config/proxy.json")
    print("Ctrl+C to stop.\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
