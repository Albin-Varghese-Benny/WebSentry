"""netproxy.config -- listener / TLS / limits settings (config/proxy.json).

These are infrastructure settings that need a restart to change. Everything
that decides *what traffic is allowed* lives in the policy file instead, which
is reloaded live.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent          # project directory


@dataclass
class ProxyConfig:
    listen_host: str = "0.0.0.0"
    tls_port: int = 8443
    plain_port: Optional[int] = None                    # plaintext listener, off by default (demo/Wireshark only)
    admin_host: str = "127.0.0.1"
    admin_port: Optional[int] = 9443
    admin_token: str = "change-me"
    cert: str = "certs/proxy.crt"
    key: str = "certs/proxy.key"
    ca: str = "certs/ca.crt"
    require_client_cert: bool = False                   # True = refuse clients without a certificate
    policy_file: str = "config/policy.json"
    policy_poll_seconds: float = 1.0
    access_log: Optional[str] = "logs/access.log"
    max_connections: int = 500
    handshake_timeout: float = 10.0
    idle_timeout: float = 300.0
    backend_timeout: float = 30.0
    connect_timeout: float = 5.0
    max_header_bytes: int = 16384
    max_body_bytes: int = 10 * 1024 * 1024

    PATH_FIELDS = ("cert", "key", "ca", "policy_file", "access_log")

    @classmethod
    def load(cls, path: str) -> "ProxyConfig":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        known = {f.name for f in fields(cls)}
        unknown = [k for k in raw if k not in known and not k.startswith("_")]
        if unknown:
            raise ValueError(f"{path}: unknown setting(s): {', '.join(unknown)}")
        cfg = cls(**{k: v for k, v in raw.items() if k in known})
        cfg.resolve_paths()
        return cfg

    def resolve_paths(self, base: Path = ROOT) -> "ProxyConfig":
        """Relative paths are relative to the project directory, not the current directory."""
        for name in self.PATH_FIELDS:
            value = getattr(self, name)
            if value and not os.path.isabs(value):
                setattr(self, name, str(base / value))
        return self
