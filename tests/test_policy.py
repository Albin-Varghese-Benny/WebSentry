"""Unit tests for the policy engine (no network)."""
import copy
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netproxy.config import ROOT  # noqa: E402
from netproxy.policy import Context, Policy, PolicyError, PolicyStore, normalize_path  # noqa: E402

with open(ROOT / "config" / "policy.json", encoding="utf-8") as fh:
    SHIPPED = json.load(fh)

MONDAY_10AM = datetime(2026, 10, 12, 10, 0)     # a Monday, inside working hours
MONDAY_8PM = datetime(2026, 10, 12, 20, 0)
SATURDAY_10AM = datetime(2026, 10, 17, 10, 0)


def ctx(user, service, path=None, src="127.0.0.1", method="GET"):
    return Context(user, src, service, method if path else None, path)


class RuleEvaluation(unittest.TestCase):
    def setUp(self):
        self.p = Policy(SHIPPED)

    def check(self, user, service, path=None, stage="request", now=MONDAY_8PM, src="127.0.0.1"):
        return self.p.evaluate(ctx(user, service, path, src), stage=stage, now=now)

    def test_first_match_wins_staff_bypass_admin_path(self):
        d = self.check("alice", "web", "/admin/panel")
        self.assertTrue(d.allowed)
        self.assertEqual(d.rule_id, "R01")

    def test_path_rule_denies_student(self):
        d = self.check("bob", "web", "/admin/panel")
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule_id, "R04")
        self.assertEqual(self.check("bob", "web", "/admin").rule_id, "R04")
        self.assertTrue(self.check("bob", "web", "/administrator").allowed)   # glob, not prefix

    def test_connect_stage_skips_path_rules(self):
        d = self.check("bob", "web", stage="connect")
        self.assertTrue(d.allowed)
        self.assertEqual(d.rule_id, "R06")

    def test_anonymous(self):
        self.assertEqual(self.check("anonymous", "files", stage="connect").rule_id, "R03")
        self.assertEqual(self.check("anonymous", "web", stage="connect").rule_id, "R07")
        d = self.check("anonymous", "echo-inspect", stage="connect")
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule_id, "DEFAULT")

    def test_unknown_user_falls_to_default(self):
        d = self.check("mallory", "web", stage="connect")
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule_id, "DEFAULT")

    def test_source_network(self):
        d = self.check("bob", "web", stage="connect", src="10.66.4.20")
        self.assertEqual(d.rule_id, "R02")
        self.assertTrue(self.check("bob", "web", stage="connect", src="10.67.0.1").allowed)
        self.assertTrue(self.check("bob", "web", stage="connect", src="::1").allowed)   # v6 never matches a v4 net

    def test_schedule(self):
        self.assertEqual(self.check("bob", "web", "/social/feed", now=MONDAY_10AM).rule_id, "R05")
        self.assertTrue(self.check("bob", "web", "/social/feed", now=MONDAY_8PM).allowed)
        self.assertTrue(self.check("bob", "web", "/social/feed", now=SATURDAY_10AM).allowed)

    def test_overnight_schedule(self):
        doc = copy.deepcopy(SHIPPED)
        doc["rules"].insert(0, {"id": "NIGHT", "action": "deny", "services": ["chat"],
                                "schedule": {"days": "fri", "from": "22:00", "to": "06:00"}})
        p = Policy(doc)
        friday_23 = datetime(2026, 10, 16, 23, 0)
        saturday_03 = datetime(2026, 10, 17, 3, 0)
        saturday_23 = datetime(2026, 10, 17, 23, 0)
        self.assertEqual(p.evaluate(ctx("bob", "chat"), "connect", friday_23).rule_id, "NIGHT")
        self.assertEqual(p.evaluate(ctx("bob", "chat"), "connect", saturday_03).rule_id, "NIGHT")
        self.assertEqual(p.evaluate(ctx("bob", "chat"), "connect", saturday_23).rule_id, "R06")

    def test_unknown_service(self):
        d = self.check("alice", "nosuch", stage="connect")
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule_id, "UNKNOWN_SERVICE")

    def test_path_scoped_allow_admits_connection_provisionally(self):
        doc = copy.deepcopy(SHIPPED)
        doc["rules"].insert(0, {"id": "PUB", "action": "allow", "users": ["mallory"], "services": ["web"],
                                "paths": ["/news"]})
        p = Policy(doc)
        d = p.evaluate(ctx("mallory", "web"), "connect", MONDAY_8PM)
        self.assertTrue(d.allowed and d.provisional)
        self.assertTrue(p.evaluate(ctx("mallory", "web", "/news"), "request", MONDAY_8PM).allowed)
        self.assertFalse(p.evaluate(ctx("mallory", "web", "/sports"), "request", MONDAY_8PM).allowed)
        # a path rule can never open a non-HTTP service
        doc["rules"][0]["services"] = ["*"]
        self.assertFalse(Policy(doc).evaluate(ctx("mallory", "chat"), "connect", MONDAY_8PM).allowed)

    def test_except_users_and_groups(self):
        f03 = next(f for f in self.p.filters if f.id == "F03")
        self.assertFalse(f03.applies("alice", "web", "response", self.p.groups))
        self.assertTrue(f03.applies("bob", "web", "response", self.p.groups))
        self.assertFalse(f03.applies("bob", "chat", "response", self.p.groups))
        self.assertFalse(f03.applies("bob", "web", "request", self.p.groups))

    def test_resolve_service(self):
        self.assertEqual(self.p.resolve_service("web").name, "web")
        self.assertEqual(self.p.resolve_service("WEB.SIM:80").name, "web")
        self.assertIsNone(self.p.resolve_service("example.com:443"))


class Validation(unittest.TestCase):
    def bad(self, mutate, fragment):
        doc = copy.deepcopy(SHIPPED)
        mutate(doc)
        with self.assertRaises(PolicyError) as cm:
            Policy(doc)
        self.assertIn(fragment, str(cm.exception))

    def test_rejects_bad_documents(self):
        self.bad(lambda d: d.update(default_action="maybe"), "default_action")
        self.bad(lambda d: d["rules"].append({"id": "X", "action": "permit"}), "action")
        self.bad(lambda d: d["rules"].append({"id": "R01", "action": "deny"}), "duplicate")
        self.bad(lambda d: d["rules"].append({"action": "deny", "services": ["nope"]}), "unknown service")
        self.bad(lambda d: d["rules"].append({"action": "deny", "users": ["@nogroup"]}), "unknown group")
        self.bad(lambda d: d["rules"].append({"action": "deny", "src": ["300.1.1.1"]}), "CIDR")
        self.bad(lambda d: d["rules"].append({"action": "deny", "paths": ["admin"]}), "must start with '/'")
        self.bad(lambda d: d["rules"].append({"action": "deny", "servcies": ["web"]}), "unknown key")
        self.bad(lambda d: d["rules"].append({"action": "deny", "schedule": {"days": "funday"}}), "unknown day")
        self.bad(lambda d: d["rules"].append({"action": "deny", "schedule": {"from": "25:00"}}), "HH:MM")
        self.bad(lambda d: d["content_filters"].append({"type": "regex", "patterns": ["(unclosed"]}), "regular expression")
        self.bad(lambda d: d["content_filters"].append({"type": "mime", "patterns": ["x/y"], "action": "redact"}), "action")
        self.bad(lambda d: d["services"]["web"].update(port=70000), "port")
        self.bad(lambda d: d["services"]["web"].update(inspect="deep"), "inspect")
        self.bad(lambda d: d["limits"].update(max_conns_per_user=-1), "limits")

    def test_auto_ids(self):
        doc = copy.deepcopy(SHIPPED)
        doc["rules"].append({"action": "deny", "services": ["echo"]})
        p = Policy(doc)
        self.assertEqual(p.rules[-1].id, "R08")
        self.assertEqual(p.doc["rules"][-1]["id"], "R08")

    def test_comment_keys_ignored(self):
        doc = copy.deepcopy(SHIPPED)
        doc["rules"][0]["_note"] = "documentation"
        Policy(doc)


class PathNormalisation(unittest.TestCase):
    def test_evasion_attempts_are_canonicalised(self):
        for raw in ("/x/../admin/panel", "//admin/panel", "/%61dmin/panel", "/./admin/./panel", "/admin//panel"):
            self.assertEqual(normalize_path(raw)[0], "/admin/panel", raw)

    def test_query_preserved_and_root(self):
        self.assertEqual(normalize_path("/search?q=a%20b"), ("/search", "/search?q=a%20b"))
        self.assertEqual(normalize_path("/../../")[0], "/")

    def test_rejects(self):
        for raw in ("admin", "/a%00b", "/a\\b"):
            with self.assertRaises(ValueError):
                normalize_path(raw)


class Store(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "policy.json")
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(SHIPPED, fh)
        self.store = PolicyStore(self.path)
        self.events = []
        self.store.subscribe(lambda old, new, src: self.events.append((new.version, src)))
        self.store.load()

    def tearDown(self):
        self.store.stop()

    def test_mutate_bumps_version_and_notifies(self):
        new, res = self.store.mutate(lambda d: d.update(default_action="allow") or "ok", "test")
        self.assertEqual(new.version, 2)
        self.assertEqual(res, "ok")
        self.assertEqual(self.events[-1], (2, "test"))

    def test_invalid_mutation_keeps_old_policy(self):
        with self.assertRaises(PolicyError):
            self.store.mutate(lambda d: d.update(default_action="nope"), "bad")
        self.assertEqual(self.store.policy.version, 1)

    def test_file_reload_and_rejection(self):
        doc = copy.deepcopy(SHIPPED)
        doc["default_action"] = "allow"
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        changed, _ = self.store.reload()
        self.assertTrue(changed)
        self.assertEqual(self.store.policy.default_action, "allow")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write('{"default_action": ')
        changed, msg = self.store.reload()
        self.assertFalse(changed)
        self.assertIn("rejected", msg)
        self.assertEqual(self.store.policy.default_action, "allow")

    def test_watcher_picks_up_edits(self):
        self.store.start_watcher(0.05)
        doc = copy.deepcopy(SHIPPED)
        doc["name"] = "edited"
        time.sleep(0.05)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        deadline = time.time() + 3
        while self.store.policy.name != "edited" and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.store.policy.name, "edited")

    def test_notepad_bom_is_accepted(self):
        doc = copy.deepcopy(SHIPPED)
        doc["name"] = "with-bom"
        with open(self.path, "w", encoding="utf-8-sig") as fh:      # Windows Notepad "UTF-8 with BOM"
            json.dump(doc, fh)
        changed, msg = self.store.reload()
        self.assertTrue(changed, msg)
        self.assertEqual(self.store.policy.name, "with-bom")

    def test_save_round_trip(self):
        self.store.mutate(lambda d: d["rules"].insert(0, {"id": "S1", "action": "deny", "users": ["bob"]}), "t")
        self.store.save()
        again = PolicyStore(self.path)
        again.load()
        self.assertEqual(again.policy.rules[0].id, "S1")


if __name__ == "__main__":
    unittest.main()
