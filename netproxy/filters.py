"""
netproxy.filters -- content inspection.

Two inspection styles:

* Message inspection (HTTP): the proxy has the complete body of a request or
  response, so keyword/regex filters see all of it and mime filters check the
  Content-Type header.

* Stream inspection (line services): TCP is a byte stream with no message
  boundaries -- one recv() may return half a line or ten lines. StreamInspector
  reassembles the stream into lines first, so a keyword split across two TCP
  segments ("confi" + "dential\\n") is still caught. Partial lines are flushed
  after a short idle delay so interactive prompts are not held back, except for
  a trailing fragment that could be the start of a blocked keyword.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

from .policy import ContentFilter


@dataclass
class FilterOutcome:
    data: bytes = b""                                   # what may be forwarded
    blocked: Optional[ContentFilter] = None              # set when a block filter fired
    hits: List[Tuple[str, str, int]] = field(default_factory=list)   # (filter id, action, matches)

    def merge(self, other: "FilterOutcome") -> "FilterOutcome":
        self.data += other.data
        self.hits.extend(other.hits)
        self.blocked = self.blocked or other.blocked
        return self


def inspect_bytes(data: bytes, filters: Sequence[ContentFilter]) -> FilterOutcome:
    """Apply keyword/regex filters to one complete unit of data.

    Order: any block filter wins outright; then redactions are applied in
    policy order; log filters only record that they matched.
    """
    text_filters = [f for f in filters if f.regex is not None]
    for f in text_filters:
        if f.action == "block" and f.regex.search(data):
            return FilterOutcome(b"", f, [(f.id, "block", 1)])
    out, hits = data, []
    for f in text_filters:
        if f.action == "redact":
            out, n = f.regex.subn(f.replacement, out)
            if n:
                hits.append((f.id, "redact", n))
        elif f.action == "log":
            n = len(f.regex.findall(data))
            if n:
                hits.append((f.id, "log", n))
    return FilterOutcome(out, None, hits)


def check_mime(content_type: str, filters: Sequence[ContentFilter]) -> FilterOutcome:
    """Content-Type check for HTTP responses (mime filters)."""
    hits = []
    for f in filters:
        if f.kind != "mime" or not f.mime_matches(content_type):
            continue
        if f.action == "block":
            return FilterOutcome(b"", f, [(f.id, "block", 1)])
        hits.append((f.id, "log", 1))
    return FilterOutcome(b"", None, hits)


class StreamInspector:
    """Line-reassembling inspector for one direction of a byte stream.

    get_filters is called for every unit inspected, so a policy change takes
    effect in the middle of an open session.
    """

    def __init__(self, get_filters: Callable[[], Sequence[ContentFilter]], max_line: int = 16384):
        self.get_filters = get_filters
        self.max_line = max_line
        self.buf = bytearray()
        self.last_feed = time.monotonic()

    @property
    def has_partial(self) -> bool:
        return bool(self.buf)

    def feed(self, data: bytes) -> FilterOutcome:
        """Add received bytes; inspect and return every complete line."""
        self.buf += data
        self.last_feed = time.monotonic()
        cut = self.buf.rfind(b"\n")
        if cut >= 0:
            return self._process(cut + 1)
        if len(self.buf) >= self.max_line:                # very long line: inspect what we have
            return self._process(len(self.buf) - self._holdback())
        return FilterOutcome()

    def flush_partial(self) -> FilterOutcome:
        """Called when the stream goes idle with an unterminated line buffered."""
        return self._process(len(self.buf) - self._holdback())

    def finish(self) -> FilterOutcome:
        """End of stream: inspect everything that is left."""
        return self._process(len(self.buf))

    # ------------------------------------------------------------------ internals
    def _holdback(self) -> int:
        """Bytes at the end of the buffer that could be the start of a keyword."""
        tail = bytes(self.buf[-64:]).lower()
        keep = 0
        for f in self.get_filters():
            if f.action == "log":
                continue
            for kw in f.keywords_lower:
                for k in range(min(len(kw) - 1, len(tail)), keep, -1):
                    if tail.endswith(kw[:k]):
                        keep = k
                        break
        return keep

    def _process(self, n: int) -> FilterOutcome:
        if n <= 0:
            return FilterOutcome()
        chunk = bytes(self.buf[:n])
        del self.buf[:n]
        filters = [f for f in self.get_filters() if f.regex is not None]
        # fast path: one C-level regex scan over the whole chunk. Patterns are compiled
        # with re.MULTILINE, so anything that matches inside a line also matches here --
        # no hit means no line can hit, and the chunk is forwarded untouched.
        if not any(f.regex.search(chunk) for f in filters):
            return FilterOutcome(chunk)
        result = FilterOutcome()
        # inspect line by line so the outcome never depends on how TCP segmented the data
        for line in chunk.splitlines(keepends=True):
            r = inspect_bytes(line, filters)
            result.merge(r)
            if r.blocked:                                  # stop at the offending line
                self.buf.clear()
                break
        return result
