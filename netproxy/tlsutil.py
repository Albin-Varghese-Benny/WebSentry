"""netproxy.tlsutil -- TLS contexts for the proxy, its clients and the admin console.

Clients authenticate the proxy with its certificate (signed by the project CA).
The proxy can also authenticate clients: a client that presents a certificate
signed by the same CA is identified by the certificate's Common Name (mutual
TLS). That identity -- not anything the client merely claims -- is what the
policy rules match on. Clients without a certificate are 'anonymous'.
"""
from __future__ import annotations

import re
import ssl
from typing import Optional

_CN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SERVER_NAME = "netproxy"           # name in the proxy certificate; clients verify against it


def server_context(cert: str, key: str, ca: Optional[str] = None, require_client_cert: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    if ca:
        ctx.load_verify_locations(ca)
        ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
    return ctx


def client_context(ca: str, cert: Optional[str] = None, key: Optional[str] = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)           # verifies certificate + hostname by default
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(ca)
    if cert:
        ctx.load_cert_chain(cert, key)
    return ctx


def peer_common_name(sock: ssl.SSLSocket) -> Optional[str]:
    """CN of a verified client certificate, or None if the client sent none."""
    cert = sock.getpeercert()
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName" and _CN_RE.match(value):
                return value
    return None
