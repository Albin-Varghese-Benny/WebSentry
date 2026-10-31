import json
import re
import tempfile
import unittest
from pathlib import Path

import app as aw
import forward_proxy


class BlockLinkTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.saved = (aw.REAL_POLICY_PATH, aw.REQUESTS_PATH, forward_proxy.POLICY_PATH)
        aw.REAL_POLICY_PATH = forward_proxy.POLICY_PATH = tmp / "real.json"
        aw.REQUESTS_PATH = tmp / "req.json"
        aw.REAL_POLICY_PATH.write_text(json.dumps({"default_action": "allow", "rules": [
            {"id": "REAL-00000001", "action": "deny", "users": ["*"], "domains": ["youtube.com"], "reason": "x", "enabled": True}]}))
        aw.app.config["TESTING"] = True

    def tearDown(self):
        aw.REAL_POLICY_PATH, aw.REQUESTS_PATH, forward_proxy.POLICY_PATH = self.saved

    def token(self, c):
        tok = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
        with c.session_transaction() as s:
            s["csrf_token"] = tok
        return tok

    def test_logged_out_visitor_is_sent_to_login_then_back_to_the_request_page(self):
        c = aw.app.test_client()
        r = c.get("/requests?domain=youtube.com")
        self.assertEqual(r.status_code, 302)
        login_url = r.headers["Location"]                      # whatever form Flask encodes it in, the browser follows it
        self.assertTrue(login_url.startswith("/login?next="))
        tok = self.token(c)
        r = c.post(login_url, data={"csrf_token": tok, "username": "bob", "password": "bob-demo"})
        self.assertEqual(r.headers["Location"].split("localhost")[-1], "/requests?domain=youtube.com")

    def test_login_does_not_redirect_to_other_sites(self):
        for evil in ("//evil.example/x", "https://evil.example", "/\\evil.example"):
            c = aw.app.test_client()
            tok = self.token(c)
            r = c.post("/login?next=" + evil, data={"csrf_token": tok, "username": "bob", "password": "bob-demo"})
            self.assertNotIn("evil", r.headers["Location"])

    def test_request_page_preselects_the_site_and_focuses_the_reason(self):
        c = aw.app.test_client()
        tok = self.token(c)
        c.post("/login", data={"csrf_token": tok, "username": "bob", "password": "bob-demo"})
        html = c.get("/requests?domain=youtube.com").get_data(as_text=True)
        self.assertIn('value="youtube.com" selected', html)
        self.assertIn("autofocus", html)
        html = c.get("/requests?domain=example.com").get_data(as_text=True)      # not blocked for bob -> ignored
        self.assertNotIn("selected", html.split('id="domain"')[1].split("</select>")[0])

    def test_rules_added_by_admin_record_who_and_when(self):
        c = aw.app.test_client()
        tok = self.token(c)
        c.post("/login", data={"csrf_token": tok, "username": "admin", "password": "admin-demo"})
        with c.session_transaction() as s:
            tok = s["csrf_token"]
        c.post("/real-websites/add", data={"csrf_token": tok, "domain": "reddit.com", "user": "*", "action": "deny", "reason": "focus"})
        rule = json.loads(aw.REAL_POLICY_PATH.read_text())["rules"][0]
        self.assertEqual(rule["created_by"], "admin")
        self.assertIn("created_at", rule)


if __name__ == "__main__":
    unittest.main()
