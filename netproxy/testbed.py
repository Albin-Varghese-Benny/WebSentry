"""
netproxy.testbed -- start the whole system (services + proxy + admin console)
inside one Python process on free ports. Used by the tests, demo.py and
benchmark.py so they never collide with a copy you are running by hand.
"""
from __future__ import annotations

import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Optional

from .clientlib import AdminClient, ProxyClient
from .config import ROOT, ProxyConfig
from .policy import PolicyStore, atomic_write
from .server import ProxyServer

sys.path.insert(0, str(ROOT))
import services as sim  # noqa: E402  (services.py lives in the project root)


class Stack:
    def __init__(self, policy_doc: Optional[dict] = None, policy_file: Optional[str] = None,
                 workdir: Optional[str] = None, plain: bool = True, quiet: bool = True, **cfg_overrides):
        self.workdir = Path(workdir or tempfile.mkdtemp(prefix="netproxy-"))
        self.workdir.mkdir(parents=True, exist_ok=True)
        if policy_doc is None:
            with open(policy_file or ROOT / "config" / "policy.json", "r", encoding="utf-8") as fh:
                policy_doc = json.load(fh)
        self.policy_doc = policy_doc
        self.plain = plain
        self.quiet = quiet
        self.cfg_overrides = cfg_overrides
        self.services = {}
        self.proxy: Optional[ProxyServer] = None
        self.policy_path = str(self.workdir / "policy.json")
        self.token = "test-token"

    def start(self) -> "Stack":
        if self.quiet:
            logging.getLogger("netproxy").setLevel(logging.ERROR)
        self.services = sim.start_services("127.0.0.1", {name: 0 for name in sim.DEFAULT_PORTS}, quiet=True)
        # point every policy service at the port its simulated back end actually got
        by_port = {sim.DEFAULT_PORTS[n]: s.port for n, s in self.services.items()}
        doc = json.loads(json.dumps(self.policy_doc))
        for spec in doc.get("services", {}).values():
            if isinstance(spec, dict) and spec.get("port") in by_port:
                spec["port"] = by_port[spec["port"]]
        with open(self.policy_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        cfg = ProxyConfig(listen_host="127.0.0.1", tls_port=0, plain_port=0 if self.plain else None, admin_port=0,
                          admin_token=self.token, policy_file=self.policy_path,
                          access_log=str(self.workdir / "access.log"), policy_poll_seconds=0.2)
        for k, v in self.cfg_overrides.items():
            setattr(cfg, k, v)
        cfg.resolve_paths()
        store = PolicyStore(cfg.policy_file)
        store.load()
        self.proxy = ProxyServer(cfg, store).start()
        return self

    # ------------------------------------------------------------------ handles
    @property
    def tls_port(self) -> int:
        return self.proxy.ports["tls"]

    @property
    def plain_port(self) -> int:
        return self.proxy.ports["plain"]

    @property
    def store(self) -> PolicyStore:
        return self.proxy.store

    def client(self, user: Optional[str] = None, plain: bool = False, **kw) -> ProxyClient:
        if plain:
            return ProxyClient("127.0.0.1", self.plain_port, tls=False, **kw)
        return ProxyClient("127.0.0.1", self.tls_port, user=user, **kw)

    def admin(self) -> AdminClient:
        return AdminClient("127.0.0.1", self.proxy.ports["admin"], self.token)

    def write_policy(self, doc: dict):
        """Rewrite the policy file in place (as an editor would) -- the watcher picks it up."""
        atomic_write(self.policy_path, json.dumps(doc, indent=2))

    def read_policy(self) -> dict:
        with open(self.policy_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def stop(self):
        if self.proxy:
            self.proxy.shutdown()
            self.proxy.registry.close()
        for svc in self.services.values():
            svc.stop()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
