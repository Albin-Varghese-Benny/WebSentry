import base64
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path

import blockpage
import forward_proxy

RULE = {"id": "REAL-1", "action": "deny", "users": ["*"], "domains": ["youtube.com"], "reason": "Not during work",
        "enabled": True, "created_by": "admin", "created_at": 1793200000}


class PageTests(unittest.TestCase):
    def setUp(self):
        self.bp = blockpage.BlockPage(tempfile.mkdtemp())

    def test_page_says_why_and_by_whom(self):
        html = self.bp.page("www.youtube.com", "bob", RULE, "youtube.com")
        for text in ("www.youtube.com is restricted", "Not during work", "Restricted by", "admin", "REAL-1", "everyone", "bob"):
            self.assertIn(text, html)
        self.assertIn("http://127.0.0.1:5000/requests?domain=youtube.com#site-access", html)   # the request button
        self.assertIn("Request temporary access", html)

    def test_admin_gets_manage_link_and_unknown_author_is_handled(self):
        html = self.bp.page("youtube.com", "admin", {**RULE, "created_by": None, "created_at": None}, "youtube.com")
        self.assertIn("http://127.0.0.1:5000/websites", html)
        self.assertIn("an administrator", html)

    def test_everything_dynamic_is_escaped(self):
        html = self.bp.page("a.example", "<script>alert(1)</script>", {**RULE, "reason": '"><img src=x onerror=alert(1)>'}, "a.example")
        self.assertNotIn("<script>alert(1)</script>", html.split("<script>(async")[0])
        self.assertNotIn("<img src=x", html)

    def test_hosts_that_cannot_be_certified_are_not_intercepted(self):
        self.bp.ensure_ca()
        for bad in ("127.0.0.1", "a b.example", "x.example\nsubjectAltName=DNS:evil.com", "bad_host.example", ""):
            self.assertIsNone(self.bp.context_for(bad), bad)


class TlsInterceptionTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.bp = blockpage.BlockPage(tmp)
        self.bp.ensure_ca()
        self.saved = (forward_proxy.read_policy, forward_proxy.BLOCK_PAGE, forward_proxy.LOG_PATH)
        forward_proxy.read_policy = lambda: {"default_action": "allow", "rules": [RULE]}
        forward_proxy.BLOCK_PAGE = self.bp
        forward_proxy.LOG_PATH = tmp / "log.jsonl"
        self.server = forward_proxy.Server(("127.0.0.1", 0), forward_proxy.Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        forward_proxy.read_policy, forward_proxy.BLOCK_PAGE, forward_proxy.LOG_PATH = self.saved

    def tunnel(self, host):
        auth = base64.b64encode(b"bob:bob-demo").decode()
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += s.recv(1)
        return s, head.split(b"\r\n")[0].decode()

    def fetch(self, host, extra_headers=""):
        s, status = self.tunnel(host)
        self.assertIn("200", status)
        ctx = ssl.create_default_context(cafile=str(self.bp.ca_cert))       # verifies chain AND host name, like a browser
        tls = ctx.wrap_socket(s, server_hostname=host)
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\n".encode())
        data = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            data += chunk
        tls.close()
        return data.decode("utf-8", "replace")

    def test_blocked_https_site_shows_the_block_page(self):
        resp = self.fetch("www.youtube.com", "Accept: text/html\r\nSec-Fetch-Dest: document\r\n")
        self.assertTrue(resp.startswith("HTTP/1.1 403"))
        self.assertIn('Clear-Site-Data: "cache", "storage"', resp)          # evicts YouTube's service worker / offline page
        self.assertIn("Restricted by", resp)
        self.assertIn("/requests?domain=youtube.com#site-access", resp)

    def test_subresources_get_an_empty_403(self):
        resp = self.fetch("i.ytimg.com", "Sec-Fetch-Dest: image\r\n")
        self.assertTrue(resp.startswith("HTTP/1.1 403"))
        self.assertNotIn("Restricted by", resp)

    def test_browser_that_does_not_trust_the_ca_is_refused_the_handshake(self):
        s, status = self.tunnel("www.youtube.com")
        self.assertIn("200", status)
        with self.assertRaises(ssl.SSLError):
            ssl.create_default_context().wrap_socket(s, server_hostname="www.youtube.com")

    def test_clear_site_data_can_be_switched_off(self):
        self.bp.clear_site_data = False
        resp = self.fetch("www.youtube.com", "Accept: text/html\r\n")
        self.assertNotIn("Clear-Site-Data", resp)
        self.assertNotIn("serviceWorker", resp)


if __name__ == "__main__":
    unittest.main()
