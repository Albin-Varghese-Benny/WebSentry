import json
import re
import tempfile
import unittest
from pathlib import Path

import app as aw
import forward_proxy


class FakeHeaders(dict):
    def get_content_charset(self):
        return "utf-8"


class BrowseTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.saved = (aw.REAL_POLICY_PATH, aw.REQUESTS_PATH, forward_proxy.POLICY_PATH, forward_proxy.LOG_PATH,
                      aw._http_get, aw._public_host)
        aw.REAL_POLICY_PATH = forward_proxy.POLICY_PATH = tmp / "real.json"
        aw.REQUESTS_PATH = tmp / "req.json"
        forward_proxy.LOG_PATH = tmp / "log.jsonl"
        aw.REAL_POLICY_PATH.write_text(json.dumps({"default_action": "allow", "rules": [
            {"id": "REAL-00000001", "action": "deny", "users": ["*"], "domains": ["youtube.com"],
             "reason": "Not during work", "enabled": True}]}))
        self.pages = {}
        self.fetched = []

        def fake_get(url):
            self.fetched.append(url)
            status, headers, body = self.pages[url]
            return status, FakeHeaders({k: v for k, v in headers.items()}), body
        aw._http_get = fake_get
        aw._public_host = lambda host: host not in ("localhost", "127.0.0.1", "intranet.lan")
        aw.app.config["TESTING"] = True

    def tearDown(self):
        (aw.REAL_POLICY_PATH, aw.REQUESTS_PATH, forward_proxy.POLICY_PATH, forward_proxy.LOG_PATH,
         aw._http_get, aw._public_host) = self.saved

    def login(self, user):
        c = aw.app.test_client()
        tok = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
        with c.session_transaction() as s:
            s["csrf_token"] = tok
        c.post("/login", data={"csrf_token": tok, "username": user, "password": f"{user}-demo"})
        return c

    def test_blocked_site_shows_block_page_and_request_form(self):
        html = self.login("bob").get("/browse?url=www.youtube.com").get_data(as_text=True)
        self.assertIn("ACCESS BLOCKED", html)
        self.assertIn("Not during work", html)
        self.assertIn("REAL-00000001", html)
        self.assertIn('name="domain" value="youtube.com"', html)      # request form targets the rule's domain
        self.assertEqual(self.fetched, [])                           # never contacted the site
        log = forward_proxy.LOG_PATH.read_text()
        self.assertIn('"decision":"deny"', log)

    def test_admin_sees_manage_button_not_request_form(self):
        html = self.login("admin").get("/browse?url=youtube.com").get_data(as_text=True)
        self.assertIn("Manage this rule", html)
        self.assertNotIn("Request access", html)

    def test_allowed_page_is_previewed_sandboxed_with_links_rewritten(self):
        self.pages["https://example.com"] = (200, {"Content-Type": "text/html; charset=utf-8"},
            b'<html><head><title>x</title></head><body><a href="/about">About</a><script>alert(1)</script></body></html>')
        html = self.login("bob").get("/browse?url=example.com").get_data(as_text=True)
        self.assertIn("Allowed", html)
        self.assertIn('sandbox="allow-top-navigation-by-user-activation"', html)   # no allow-scripts / same-origin
        self.assertNotIn("allow-scripts", html)
        self.assertIn("/browse?url=https%3A%2F%2Fexample.com%2Fabout", html)

    def test_redirect_into_blocked_site_is_blocked(self):
        self.pages["https://short.example"] = (302, {"Location": "https://www.youtube.com/watch?v=1"}, b"")
        html = self.login("bob").get("/browse?url=short.example").get_data(as_text=True)
        self.assertIn("ACCESS BLOCKED", html)
        self.assertEqual(self.fetched, ["https://short.example"])    # the blocked hop was never fetched

    def test_private_addresses_and_odd_schemes_refused(self):
        bob = self.login("bob")
        self.assertIn("private", bob.get("/browse?url=http://127.0.0.1:5000/").get_data(as_text=True))
        self.assertIn("private", bob.get("/browse?url=intranet.lan").get_data(as_text=True))
        self.assertIn("Only http", bob.get("/browse?url=file:///etc/passwd").get_data(as_text=True))
        self.assertEqual(self.fetched, [])

    def test_requires_login_and_non_html_has_no_preview(self):
        self.assertEqual(aw.app.test_client().get("/browse?url=example.com").status_code, 302)
        self.pages["https://files.example/a.zip"] = (200, {"Content-Type": "application/zip"}, b"PK")
        html = self.login("bob").get("/browse?url=files.example/a.zip").get_data(as_text=True)
        self.assertIn("No preview", html)


if __name__ == "__main__":
    unittest.main()
