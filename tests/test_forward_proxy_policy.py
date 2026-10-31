import json
import socket
import threading
import time
import unittest
from pathlib import Path
import forward_proxy

class ForwardProxyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.original = forward_proxy.read_policy
        self.policy = {"default_action": "allow", "rules": [
            {"id": "REAL-BLOCK", "action": "deny", "users": ["bob"], "domains": ["youtube.com"], "reason": "blocked for demo"},
            {"id": "REAL-ALL", "action": "deny", "users": ["*"], "domains": ["reddit.com"], "reason": "restricted"},
        ]}
        forward_proxy.read_policy = lambda: self.policy

    def tearDown(self):
        forward_proxy.read_policy = self.original

    def test_domain_and_subdomains_blocked_for_user(self):
        action, rule = forward_proxy.match_rule("www.youtube.com", "bob")
        self.assertEqual(action, "deny")
        self.assertEqual(rule["id"], "REAL-BLOCK")

    def test_other_user_not_blocked_by_user_rule(self):
        action, rule = forward_proxy.match_rule("youtube.com", "carol")
        self.assertEqual(action, "allow")
        self.assertIsNone(rule)

    def test_global_rule(self):
        action, rule = forward_proxy.match_rule("old.reddit.com", "carol")
        self.assertEqual(action, "deny")
        self.assertEqual(rule["id"], "REAL-ALL")

    def test_suffix_attack_does_not_match(self):
        action, rule = forward_proxy.match_rule("notyoutube.com", "bob")
        self.assertEqual(action, "allow")
        self.assertIsNone(rule)

    def test_related_domains_follow_the_main_domain(self):
        self.policy["rules"].insert(0, {"id": "R-YT", "action": "deny", "users": ["*"], "domains": ["youtube.com"]})
        for host in ("www.youtube.com", "rr1---sn-x.googlevideo.com", "i.ytimg.com", "youtu.be"):
            self.assertEqual(forward_proxy.match_rule(host, "carol")[0], "deny", host)
        self.assertEqual(forward_proxy.match_rule("notgooglevideo.com", "carol")[0], "allow")

    def test_temporary_allow_also_opens_related_domains(self):
        self.policy["rules"] = [
            {"id": "TMP", "action": "allow", "users": ["bob"], "domains": ["youtube.com"], "expires_at": time.time() + 60},
            {"id": "R-YT", "action": "deny", "users": ["*"], "domains": ["youtube.com"]}]
        self.assertEqual(forward_proxy.match_rule("rr1---sn-x.googlevideo.com", "bob")[0], "allow")
        self.assertEqual(forward_proxy.match_rule("rr1---sn-x.googlevideo.com", "carol")[0], "deny")

    def test_open_tunnel_is_cut_when_its_rule_is_revoked(self):
        self.policy["rules"] = []                                   # youtube.com currently allowed
        client, _client_peer = socket.socketpair()
        upstream, _upstream_peer = socket.socketpair()
        handler = forward_proxy.Handler.__new__(forward_proxy.Handler)
        handler.connection = client
        t = threading.Thread(target=handler.tunnel, args=(upstream, None, "www.youtube.com", "bob"), daemon=True)
        t.start()
        time.sleep(1.4)
        self.assertTrue(t.is_alive())                               # still open while allowed
        self.policy["rules"] = [{"id": "R-YT", "action": "deny", "users": ["*"], "domains": ["youtube.com"]}]
        t.join(3.5)
        self.assertFalse(t.is_alive())                              # revoked -> tunnel closed within about a second


if __name__ == "__main__":
    unittest.main()
