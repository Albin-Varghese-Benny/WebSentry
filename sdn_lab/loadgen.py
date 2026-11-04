"""
loadgen.py -- traffic generators that run INSIDE a Mininet host (stdlib + netproxy.clientlib only).

  python3 sdn_lab/loadgen.py latency --proxy 10.0.0.10:8443 --user alice -n 30
  python3 sdn_lab/loadgen.py bulk    --proxy 10.0.0.10:8443 --user alice --bytes 2000000
  python3 sdn_lab/loadgen.py flood   --proxy 10.0.0.10:8443 --duration 12 --workers 4     (anonymous; every request is denied)

Prints one JSON object on the last line.
"""
import argparse
import json
import statistics
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from netproxy.clientlib import ProxyClient, ProxyRefused  # noqa: E402


def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))] if v else None


def client_for(a, timeout=10.0):
    host, _, port = a.proxy.rpartition(":")
    return ProxyClient(host, int(port), user=None if a.user in (None, "anonymous") else a.user, timeout=timeout)


def latency(a):
    c, ms, errors = client_for(a, a.timeout), [], 0
    for _ in range(a.n):
        t0 = time.perf_counter()
        try:
            with c.connect(a.service) as t:
                t.get("/")
            ms.append((time.perf_counter() - t0) * 1000)
        except (OSError, ProxyRefused):
            errors += 1
        time.sleep(a.gap)
    return {"mode": "latency", "ok": len(ms), "errors": errors, "p50_ms": pct(ms, 50), "p95_ms": pct(ms, 95),
            "mean_ms": statistics.mean(ms) if ms else None}


def bulk(a):
    c = client_for(a, 30.0)
    t0 = time.perf_counter()
    got = 0
    try:
        with c.connect("bulk") as t:
            t.send_line(f"DOWNLOAD {a.bytes}")
            got = len(t.reader.take())
            while got < a.bytes:
                d = t.sock.recv(65536)
                if not d:
                    break
                got += len(d)
    except (OSError, ProxyRefused):
        pass
    dt = time.perf_counter() - t0
    return {"mode": "bulk", "bytes": got, "seconds": dt, "mbit_s": got * 8 / dt / 1e6 if got else 0.0}


def flood(a):
    stats = {"denied": 0, "errors": 0}
    first_error = []
    lock = threading.Lock()
    t_start = time.time()
    end = t_start + a.duration

    def worker():
        c = client_for(a, 1.0)                  # anonymous: chat is refused by R03 every time
        while time.time() < end:
            try:
                c.connect("chat").close()
                key = "allowed"
            except ProxyRefused:
                key = "denied"
            except OSError:
                key = "errors"
                time.sleep(0.05)
            with lock:
                stats[key] = stats.get(key, 0) + 1
                if key == "errors" and not first_error:
                    first_error.append(time.time() - t_start)

    ths = [threading.Thread(target=worker) for _ in range(a.workers)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    return {"mode": "flood", **stats, "first_error_after_s": first_error[0] if first_error else None,
            "started": t_start, "duration": a.duration}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["latency", "bulk", "flood"])
    ap.add_argument("--proxy", default="10.0.0.10:8443")
    ap.add_argument("--user", default="anonymous")
    ap.add_argument("--service", default="web")
    ap.add_argument("-n", type=int, default=30)
    ap.add_argument("--gap", type=float, default=0.05)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--bytes", type=int, default=2_000_000)
    ap.add_argument("--duration", type=float, default=10)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    print(json.dumps({"latency": latency, "bulk": bulk, "flood": flood}[a.mode](a)))


if __name__ == "__main__":
    main()
