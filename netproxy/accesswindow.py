"""Expiry worker for AccessWindow temporary grants."""
from __future__ import annotations
import json
import threading
import time
from pathlib import Path


def start_expiry_worker(store, state_path: Path, interval: float = 1.0):
    """Remove expired temporary allow rules even when the web dashboard is closed."""
    stop = threading.Event()
    state_path = Path(state_path)

    def loop():
        while not stop.wait(interval):
            try:
                if not state_path.exists():
                    continue
                state = json.loads(state_path.read_text(encoding="utf-8"))
                grants = state.get("grants", [])
                now = time.time()
                expired = [g for g in grants if float(g.get("expires_at", 0)) <= now]
                if not expired:
                    continue
                ids = {g.get("rule_id") for g in expired}
                def remove_expired(doc):
                    before = len(doc.get("rules", []))
                    doc["rules"] = [r for r in doc.get("rules", []) if r.get("id") not in ids]
                    return before - len(doc["rules"])
                store.mutate(remove_expired, source="AccessWindow: temporary grant expired")
                state["grants"] = [g for g in grants if g.get("rule_id") not in ids]
                tmp = state_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
                tmp.replace(state_path)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                # Keep the proxy running; the next poll retries state cleanup.
                continue

    thread = threading.Thread(target=loop, name="accesswindow-expiry", daemon=True)
    thread.start()
    return stop, thread
