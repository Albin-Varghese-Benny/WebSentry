"""Smoke test: skipped unless Mininet, Ryu and root are available.   sudo python3 -m unittest sdn_lab.test_smoke"""
import os
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import mininet  # noqa: F401
    HAVE = (os.environ.get("RYU_MANAGER") or shutil.which("ryu-manager")) is not None and os.geteuid() == 0
except ImportError:
    HAVE = False


@unittest.skipUnless(HAVE, "needs root, mininet and ryu-manager")
class Smoke(unittest.TestCase):
    def test_policy_acl_and_quarantine(self):
        from lab import IPS, Lab, controller_cmd
        with Lab(mode="sdn", threshold=3) as lab:
            self.assertIn("HTTP 200", lab.client("h1", "web /news"))
            self.assertFalse(lab.reachable("h2", IPS["svc"], 9001, timeout=2), "clients must not reach services directly")
            lab.loadgen("h3", "flood --duration 3 --workers 1")
            self.assertIn(IPS["h3"], controller_cmd("STATUS")["blocked"])


if __name__ == "__main__":
    unittest.main()
