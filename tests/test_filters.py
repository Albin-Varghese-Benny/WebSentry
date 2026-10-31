"""Unit tests for content inspection (no network)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netproxy.config import ROOT  # noqa: E402
from netproxy.filters import StreamInspector, check_mime, inspect_bytes  # noqa: E402
from netproxy.policy import Policy  # noqa: E402

with open(ROOT / "config" / "policy.json", encoding="utf-8") as fh:
    POLICY = Policy(json.load(fh))


def filters(user, service, direction):
    return POLICY.filters_for(user, service, direction)


class MessageInspection(unittest.TestCase):
    def test_redaction(self):
        out = inspect_bytes(b"cards: 4111 1111 1111 1111 and 5500-0000-0000-0004.", filters("bob", "web", "response"))
        self.assertIsNone(out.blocked)
        self.assertEqual(out.data, b"cards: [CARD REDACTED] and [CARD REDACTED].")
        self.assertIn(("F02", "redact", 2), out.hits)

    def test_block_beats_redact(self):
        out = inspect_bytes(b"CONFIDENTIAL card 4111111111111111", filters("bob", "web", "response"))
        self.assertEqual(out.blocked.id, "F03")
        self.assertEqual(out.data, b"")

    def test_staff_exempt(self):
        out = inspect_bytes(b"CONFIDENTIAL", filters("alice", "web", "response"))
        self.assertIsNone(out.blocked)

    def test_whole_word(self):
        f = filters("bob", "chat", "request")
        self.assertEqual(inspect_bytes(b"you idiot", f).data, b"you ***")
        self.assertEqual(inspect_bytes(b"idiotic plan", f).data, b"idiotic plan")      # not a whole word

    def test_case_insensitive_keyword(self):
        self.assertEqual(inspect_bytes(b"Online CaSiNo", filters("bob", "web", "request")).blocked.id, "F01")

    def test_log_only(self):
        out = inspect_bytes(b"my password is hunter2", filters("bob", "files", "request"))
        self.assertIsNone(out.blocked)
        self.assertEqual(out.data, b"my password is hunter2")
        self.assertIn(("F06", "log", 1), out.hits)

    def test_mime(self):
        f = filters("bob", "web", "response")
        self.assertEqual(check_mime("application/x-msdownload", f).blocked.id, "F04")
        self.assertEqual(check_mime("Application/X-MSDownload; name=a.exe", f).blocked.id, "F04")
        self.assertIsNone(check_mime("application/pdf", f).blocked)
        self.assertIsNone(check_mime("application/x-msdownload", filters("alice", "web", "response")).blocked)


class StreamReassembly(unittest.TestCase):
    """TCP has no message boundaries: filters must not depend on how bytes were segmented."""

    def inspector(self, user="bob", service="chat", direction="request"):
        return StreamInspector(lambda: filters(user, service, direction))

    def test_keyword_split_across_segments(self):
        s = self.inspector()
        out = s.feed(b"you are an id")
        self.assertEqual(out.data, b"")                     # incomplete line is held
        out = s.feed(b"iot, carol\n")
        self.assertEqual(out.data, b"you are an ***, carol\n")

    def test_block_split_across_segments(self):
        s = self.inspector()
        self.assertIsNone(s.feed(b"lets go to the cas").blocked)
        self.assertEqual(s.feed(b"ino tonight\n").blocked.id, "F01")

    def test_every_segmentation_gives_same_result(self):
        msg = b"hello there\nyou idiot\nbye loser\n"
        expected = b"hello there\nyou ***\nbye ***\n"
        for size in range(1, len(msg) + 1):
            s, got = self.inspector(), b""
            for i in range(0, len(msg), size):
                got += s.feed(msg[i:i + size]).data
            got += s.finish().data
            self.assertEqual(got, expected, f"segment size {size}")

    def test_block_stops_at_offending_line(self):
        s = self.inspector("bob", "files", "response")
        out = s.feed(b"+OK\nline one\nCONFIDENTIAL stuff\nline three\n")
        self.assertEqual(out.blocked.id, "F03")
        self.assertEqual(out.data, b"+OK\nline one\n")       # earlier lines were already safe to send

    def test_idle_flush_holds_back_keyword_prefix(self):
        s = self.inspector("bob", "web", "request")
        s.feed(b"what about cas")
        out = s.flush_partial()
        self.assertEqual(out.data, b"what about ")            # 'cas' could be the start of 'casino'
        self.assertEqual(s.feed(b"ino?\n").blocked.id, "F01")

    def test_idle_flush_sends_harmless_prompt(self):
        s = self.inspector("bob", "files", "response")
        s.feed(b"Enter name: ")
        self.assertEqual(s.flush_partial().data, b"Enter name: ")

    def test_policy_change_applies_mid_stream(self):
        current = {"f": []}
        s = StreamInspector(lambda: current["f"])
        self.assertEqual(s.feed(b"idiot\n").data, b"idiot\n")
        current["f"] = filters("bob", "chat", "request")
        self.assertEqual(s.feed(b"idiot\n").data, b"***\n")


if __name__ == "__main__":
    unittest.main()
