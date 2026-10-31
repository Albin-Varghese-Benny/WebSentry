"""End-to-end tests: real sockets, real TLS, the shipped policy, simulated services."""
import socket
import ssl
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netproxy.clientlib import ProxyClient, ProxyRefused, duplex_exchange  # noqa: E402
from netproxy.testbed import Stack  # noqa: E402


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = Stack().start()
        # this suite opens many connections quickly; the rate limit has its own test below
        cls.stack.store.mutate(lambda d: d["limits"].update(max_new_conns_per_window=0, max_conns_per_user=0), "tests")

    @classmethod
    def tearDownClass(cls):
        cls.stack.stop()

    def setUp(self):
        self.bob = self.stack.client("bob")
        self.alice = self.stack.client("alice")
        self.anon = self.stack.client()

    def refused(self, client, service):
        with self.assertRaises(ProxyRefused) as cm:
            client.connect(service).close()
        return cm.exception

    # ---------------------------------------------------------------- access control
    def test_tls_and_identity(self):
        with self.bob.connect("web") as t:
            self.assertEqual(t.user, "bob")
            self.assertEqual(t.rule, "R06")
            self.assertEqual(t.sock.version(), "TLSv1.3")
            self.assertIn("seen as user: <b>bob</b>", t.get("/").text)   # identity forwarded to the service

    def test_connect_denials(self):
        self.assertEqual(self.refused(self.anon, "files").rule, "R03")
        self.assertEqual(self.refused(self.anon, "echo-inspect").rule, "DEFAULT")
        e = self.refused(self.anon, "example.com:443")
        self.assertEqual((e.status, e.rule), (403, "UNKNOWN_SERVICE"))

    def test_path_rules_inside_tunnel(self):
        with self.bob.connect("web") as t:
            self.assertEqual(t.get("/news").status, 200)
            r = t.get("/admin/panel")
            self.assertEqual((r.status, r.header("x-proxy-rule")), (403, "R04"))
            self.assertIn("staff-only", r.text)
            self.assertEqual(t.get("/x/../admin/panel").header("x-proxy-rule"), "R04")
            self.assertEqual(t.get("/%61dmin/panel").header("x-proxy-rule"), "R04")
            self.assertEqual(t.get("/sports").status, 200)          # keep-alive survives a refusal
        with self.alice.connect("web") as t:
            self.assertEqual(t.get("/admin/panel").status, 200)

    def test_untrusted_client_certificate_rejected(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(Path(__file__).resolve().parent.parent / "certs" / "ca.crt"))
        import tempfile
        from gen_certs import generate
        other = Path(tempfile.mkdtemp())
        generate(other, users=["bob"])                          # same name, different (untrusted) CA
        ctx.load_cert_chain(str(other / "clients" / "bob.crt"), str(other / "clients" / "bob.key"))
        raw = socket.create_connection(("127.0.0.1", self.stack.tls_port), timeout=5)
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            s = ctx.wrap_socket(raw, server_hostname="netproxy")
            s.sendall(b"CONNECT web HTTP/1.1\r\n\r\n")
            if not s.recv(100):
                raise ConnectionError("closed")

    def test_wrong_server_name_detected_by_client(self):
        c = ProxyClient("127.0.0.1", self.stack.tls_port, server_name="not-the-proxy")
        with self.assertRaises(ssl.SSLCertVerificationError):
            c.connect("web")

    # ---------------------------------------------------------------- content filtering
    def test_http_content_filters(self):
        with self.bob.connect("web") as t:
            r = t.get("/billing")
            self.assertEqual(r.status, 200)
            self.assertNotIn("4111", r.text)
            self.assertIn("[CARD REDACTED]", r.text)
            self.assertEqual(r.header("x-proxy-filtered"), "F02:redact")
            self.assertEqual(int(r.header("content-length")), len(r.body))   # length fixed after redaction
            self.assertEqual(t.get("/lucky").header("x-proxy-rule"), "F01")
            self.assertEqual(t.get("/internal/report").header("x-proxy-rule"), "F03")
            self.assertEqual(t.get("/downloads/tool.exe").header("x-proxy-rule"), "F04")
            self.assertEqual(t.get("/downloads/notes.pdf").status, 200)
            self.assertEqual(t.get("/search?q=best+casino").header("x-proxy-rule"), "F01")   # URL inspected
            r = t.request("POST", "/echo", b"I like betting")
            self.assertEqual(r.header("x-proxy-rule"), "F01")                             # request body inspected
        with self.alice.connect("web") as t:
            r = t.get("/internal/report")
            self.assertEqual(r.status, 200)                       # staff exempt from F03 ...
            self.assertIn("[CARD REDACTED]", r.text)              # ... but not from DLP (F02)

    def test_line_filters_and_segmentation(self):
        with self.bob.connect("echo-inspect") as t:
            t.send(b"card 4111 11")
            time.sleep(0.05)
            t.send(b"11 1111 1111 ok\n")
            self.assertEqual(t.recv_until(b"ok\n"), b"card [CARD REDACTED] ok\n")

    def test_partial_line_is_flushed(self):
        with self.bob.connect("echo-inspect") as t:
            t.send(b"prompt> ")
            start = time.monotonic()
            self.assertEqual(t.recv_until(b"> ", timeout=2), b"prompt> ")
            self.assertLess(time.monotonic() - start, 1.0)

    def test_stream_block_terminates_session(self):
        with self.bob.connect("files") as t:
            t.recv_until(b"QUIT\n")
            t.send_line("GET memo.txt")
            out = t.recv_until(b"***\n")
            self.assertIn(b"Subject: ISA-2 question paper", out)       # lines before the match arrive
            self.assertNotIn(b"Room 204", out)                         # nothing after it does
            self.assertIn(b"content filter F03", out)
            self.assertTrue(t.is_closed())

    def test_chat_profanity_redacted_for_other_users(self):
        with self.bob.connect("chat") as tb, self.stack.client("carol").connect("chat") as tc:
            tb.recv_until(b"/quit\n")
            tc.recv_until(b"/quit\n")
            tb.send_line("you are an idiot")
            self.assertIn(b"you are an ***", tc.recv_until(b"***\n"))

    def test_echo_raw_tunnel_is_byte_exact(self):
        payload = bytes(range(256)) * 4000                        # 1 MB of every byte value
        with self.anon.connect("echo") as t:
            got = duplex_exchange(t.sock, payload, len(payload), t.reader.take())
            self.assertEqual(got, payload)

    def test_half_close_through_tunnel(self):
        with self.bob.connect("bulk") as t:
            t.send(b"UPLOAD 300000\n" + b"x" * 300000)
            self.assertEqual(t.recv_until(b"\n"), b"OK 300000\n")
        with self.bob.connect("bulk") as t:
            t.send(b"DOWNLOAD 250000\n")
            t.sock.settimeout(5)
            data = t.reader.take()
            while True:
                chunk = t.sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            self.assertEqual(len(data), 250000)                   # service EOF propagates to the client

    # ---------------------------------------------------------------- forward-proxy mode
    def test_forward_proxy_mode(self):
        r = self.stack.client(plain=True).forward("http://web.sim/news")
        self.assertEqual((r.status, r.header("via")), (200, "1.1 netproxy"))
        r = self.stack.client(plain=True).forward("http://web/admin/panel")
        self.assertEqual(r.header("x-proxy-rule"), "R04")
        r = self.stack.client(plain=True).forward("http://chat/")
        self.assertEqual(r.status, 400)

    def test_malformed_requests(self):
        s = socket.create_connection(("127.0.0.1", self.stack.plain_port), timeout=5)
        s.sendall(b"HELLO THERE\r\n\r\n")
        self.assertTrue(s.recv(100).startswith(b"HTTP/1.1 400"))
        s.close()
        s = socket.create_connection(("127.0.0.1", self.stack.plain_port), timeout=5)
        s.sendall(b"GET http://web/ HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n")
        self.assertTrue(s.recv(100).startswith(b"HTTP/1.1 400"))              # smuggling-style framing
        s.close()

    # ---------------------------------------------------------------- dynamic policy
    def test_admin_block_cuts_live_session(self):
        t = self.stack.client("carol").connect("echo")
        t.send(b"ping\n")
        self.assertEqual(t.recv_until(b"\n"), b"ping\n")
        with self.stack.admin() as admin:
            ok, msg = admin.command("BLOCK user carol")
            self.assertTrue(ok, msg)
            self.assertIn("terminated 1 live connection", msg)
            start = time.monotonic()
            self.assertTrue(t.is_closed(2))
            self.assertLess(time.monotonic() - start, 1.0)
            rule = msg.split()[3]
            self.assertEqual(self.refused(self.stack.client("carol"), "echo").rule, rule)
            ok, msg = admin.command(f"UNBLOCK {rule}")
            self.assertTrue(ok, msg)
        self.stack.client("carol").connect("echo").close()

    def test_policy_file_hot_reload(self):
        doc = self.stack.read_policy()
        live = self.anon.connect("echo")
        doc["rules"].insert(0, {"id": "HOT", "action": "deny", "services": ["echo"], "reason": "maintenance"})
        self.stack.write_policy(doc)
        self.assertTrue(live.is_closed(3))
        self.assertEqual(self.refused(self.anon, "echo").rule, "HOT")
        doc["rules"].pop(0)
        self.stack.write_policy(doc)
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                self.anon.connect("echo").close()
                break
            except ProxyRefused:
                time.sleep(0.1)
        else:
            self.fail("rule was not removed by the reload")

    def test_admin_validation_and_auth(self):
        with self.stack.admin() as admin:
            v = self.stack.store.policy.version
            ok, msg = admin.command('RULE ADD {"action":"deny","services":["nosuch"]}')
            self.assertFalse(ok)
            self.assertIn("unknown service", msg)
            self.assertEqual(self.stack.store.policy.version, v)            # bad edit changed nothing
            ok, msg = admin.command("FROBNICATE")
            self.assertFalse(ok)
        with self.assertRaises(PermissionError):
            from netproxy.clientlib import AdminClient
            AdminClient("127.0.0.1", self.stack.proxy.ports["admin"], "wrong-token")


class RequiredClientCertificate(unittest.TestCase):
    def test_anonymous_refused_during_handshake(self):
        with Stack(require_client_cert=True) as st:
            st.client("bob").connect("web").close()
            with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
                t = st.client().connect("web")             # no certificate: TLS fails (TLS 1.3 reports it on first read)
                t.close()


class Limits(unittest.TestCase):
    def test_concurrent_and_rate_limits(self):
        with Stack() as st:
            st.store.mutate(lambda d: d["limits"].update(max_conns_per_user=2, max_new_conns_per_window=4,
                                                         window_seconds=30), "test")
            bob = st.client("bob")
            a, b = bob.connect("echo"), bob.connect("echo")
            with self.assertRaises(ProxyRefused) as cm:
                bob.connect("echo")
            self.assertEqual((cm.exception.status, cm.exception.rule), (429, "LIMIT"))
            a.close()
            b.close()
            time.sleep(0.3)                                  # proxy notices the closes
            bob.connect("echo").close()                      # 3rd and 4th admitted connections
            time.sleep(0.3)
            bob.connect("echo").close()
            time.sleep(0.3)
            with self.assertRaises(ProxyRefused) as cm:      # 5th in 30 s: over the rate limit
                bob.connect("echo")
            self.assertIn("rate limit", cm.exception.detail)
            st.client("alice").connect("echo").close()       # limits are per identity


if __name__ == "__main__":
    unittest.main()
