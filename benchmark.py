"""
benchmark.py -- performance evaluation of the proxy.

    python benchmark.py             # full run, about 2-3 minutes
    python benchmark.py --quick     # smaller run, about 1 minute

The services and the proxy run as separate processes (as in real use) on free
ports, with a copy of the shipped policy whose rate limits are switched off.
Everything is measured from the client side:

  1. connection setup latency  direct TCP vs proxy (plain) vs proxy (TLS) vs proxy (mutual TLS)
  2. request latency           HTTP request on an open keep-alive connection, direct vs through the proxy
  3. throughput                bulk download/upload: direct, proxy relay (no inspection), proxy line inspection
  4. concurrency               requests/s and p95 latency with 1..N concurrent clients, direct vs proxy
  5. policy evaluation cost    microseconds per decision as the rule list grows (first-match scan)
  6. reaction time             admin BLOCK -> live session cut; policy file edit -> live session cut

Results: bench/results.json, bench/summary.md and, if matplotlib is installed,
charts bench/*.png.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import copy
import json
import os
import platform
import random
import socket
import ssl
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from netproxy.clientlib import AdminClient, HttpResponse, ProxyClient, ProxyRefused, Reader, Tunnel
from netproxy.config import ROOT
from netproxy.policy import Context, Policy, atomic_write

BENCH = ROOT / "bench"
SERVICE_NAMES = ["web", "chat", "echo", "files", "bulk"]           # same order as services.py
DEFAULT_PORTS = {"web": 9001, "chat": 9002, "echo": 9003, "files": 9004, "bulk": 9005}


# =========================================================================== helpers
def pct(values, p):
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def summarize_ms(samples):
    ms = [x * 1000 for x in samples]
    return {"n": len(ms), "mean": statistics.fmean(ms), "p50": pct(ms, 50), "p95": pct(ms, 95), "p99": pct(ms, 99)}


def port_free(port):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def free_block(n):
    for _ in range(200):
        base = random.randint(20000, 50000)
        if all(port_free(base + i) for i in range(n)):
            return base
    raise RuntimeError("no free port range found")


def wait_port(port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on port {port}")


def log(msg):
    print(msg, flush=True)


# =========================================================================== system under test
class Bench:
    def __init__(self):
        BENCH.mkdir(exist_ok=True)
        base = free_block(5 + 3)
        self.ports = {name: base + i for i, name in enumerate(SERVICE_NAMES)}
        self.tls, self.plain, self.admin_port = base + 5, base + 6, base + 7
        with open(ROOT / "config" / "proxy.json", encoding="utf-8") as fh:
            self.token = json.load(fh)["admin_token"]
        with open(ROOT / "config" / "policy.json", encoding="utf-8") as fh:
            doc = json.load(fh)
        for spec in doc["services"].values():
            for name, default in DEFAULT_PORTS.items():
                if spec.get("port") == default:
                    spec["port"] = self.ports[name]
                    break
        doc["limits"] = {"max_conns_per_user": 0, "max_new_conns_per_window": 0, "window_seconds": 10}
        self.policy_doc = doc
        self.policy_path = BENCH / "bench_policy.json"
        self.write_policy(doc)
        self.procs = []

    def write_policy(self, doc):
        atomic_write(str(self.policy_path), json.dumps(doc, indent=2))

    def start(self):
        py = sys.executable
        self.procs.append(subprocess.Popen([py, str(ROOT / "services.py"), "--base-port", str(self.ports["web"])],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT))
        self.procs.append(subprocess.Popen(
            [py, str(ROOT / "proxy.py"), "--quiet", "--policy", str(self.policy_path), "--port", str(self.tls),
             "--plain-port", str(self.plain), "--admin-port", str(self.admin_port), "--host", "127.0.0.1",
             "--access-log", str(BENCH / "bench_access.log")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT))
        for port in list(self.ports.values()) + [self.tls, self.plain, self.admin_port]:
            wait_port(port)
        return self

    def stop(self):
        for p in reversed(self.procs):
            p.terminate()
        for p in self.procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()

    def client(self, user=None, plain=False):
        if plain:
            return ProxyClient("127.0.0.1", self.plain, tls=False)
        return ProxyClient("127.0.0.1", self.tls, user=user)

    def admin(self):
        return AdminClient("127.0.0.1", self.admin_port, self.token)


# =========================================================================== 1. connection setup
def bench_setup(b: Bench, n: int):
    clients = {"proxy, plain TCP": b.client(plain=True), "proxy, TLS": b.client(),
               "proxy, mutual TLS": b.client("bob")}
    results = {}

    def direct():
        s = socket.create_connection(("127.0.0.1", b.ports["echo"]))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(b"x\n")
        s.recv(16)
        s.close()

    def via(client):
        t = client.connect("echo")
        t.send(b"x\n")
        if not t.reader.take():
            t.sock.recv(16)
        t.close()

    paths = [("direct TCP", direct)] + [(name, (lambda c=c: via(c))) for name, c in clients.items()]
    for name, fn in paths:
        for _ in range(5):
            fn()                                          # warm-up
        samples = []
        for _ in range(n):
            t0 = time.perf_counter()
            fn()
            samples.append(time.perf_counter() - t0)
        results[name] = summarize_ms(samples)
        log(f"  {name:<20} p50 {results[name]['p50']:6.2f} ms   p95 {results[name]['p95']:6.2f} ms")
    return results


# =========================================================================== 2. request latency
def _http_direct(port):
    s = socket.create_connection(("127.0.0.1", port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return Tunnel(s, Reader(s), HttpResponse(200, "OK", {}, b""), "web")


def bench_request_latency(b: Bench, n: int):
    results = {}
    for name, opener in (("direct", lambda: _http_direct(b.ports["web"])),
                         ("through proxy (TLS, inspected)", lambda: b.client("bob").connect("web"))):
        t = opener()
        for _ in range(20):
            t.get("/news")
        samples = []
        for _ in range(n):
            t0 = time.perf_counter()
            r = t.get("/news")
            samples.append(time.perf_counter() - t0)
            assert r.status == 200
        t.close()
        results[name] = summarize_ms(samples)
        log(f"  {name:<32} p50 {results[name]['p50']:6.3f} ms   p95 {results[name]['p95']:6.3f} ms")
    return results


# =========================================================================== 3. throughput
def _download(sock, reader, nbytes):
    sock.sendall(f"DOWNLOAD {nbytes}\n".encode())
    got = len(reader.take()) if reader else 0
    while got < nbytes:
        data = sock.recv(1 << 17)
        if not data:
            break
        got += len(data)
    return got


def _upload(sock, nbytes):
    sock.sendall(f"UPLOAD {nbytes}\n".encode())
    chunk = (b"netproxy upload payload line for throughput testing, constant text 0123456789\n" * 820)[:65536]
    sent = 0
    while sent < nbytes:
        part = chunk[: nbytes - sent]
        sock.sendall(part)
        sent += len(part)
    reply = b""
    while not reply.endswith(b"\n"):
        data = sock.recv(64)
        if not data:
            break
        reply += data
    return int(reply.split()[1]) if reply.startswith(b"OK") else 0


def bench_throughput(b: Bench, nbytes: int, reps: int):
    paths = {"direct": None, "proxy relay (no inspection)": "bulk", "proxy line inspection": "bulk-inspect"}
    results = {}
    bob = b.client("bob")
    for name, service in paths.items():
        row = {}
        for direction in ("download", "upload"):
            rates = []
            for _ in range(reps):
                if service is None:
                    sock = socket.create_connection(("127.0.0.1", b.ports["bulk"]))
                    reader = None
                else:
                    t = bob.connect(service)
                    sock, reader = t.sock, t.reader
                sock.settimeout(60)
                t0 = time.perf_counter()
                got = _download(sock, reader, nbytes) if direction == "download" else _upload(sock, nbytes)
                dt = time.perf_counter() - t0
                sock.close()
                if got < nbytes:
                    raise RuntimeError(f"{name} {direction}: only {got} of {nbytes} bytes")
                rates.append(nbytes / dt / 1e6)
            row[direction] = statistics.median(rates)
        results[name] = row
        log(f"  {name:<30} download {row['download']:7.1f} MB/s   upload {row['upload']:7.1f} MB/s")
    return results


# =========================================================================== 4. concurrency
def _load_worker(args):
    """Runs in a separate process: n_threads clients, each with one keep-alive connection."""
    mode, port, web_port, n_threads, start_at, duration, cert_dir = args
    from netproxy.clientlib import ProxyClient as PC
    lat, errors, lock = [], [0], threading.Lock()

    def run():
        try:
            if mode == "direct":
                t = _http_direct(web_port)
            else:
                t = PC("127.0.0.1", port, user="bob", cert_dir=Path(cert_dir)).connect("web")
        except Exception:
            with lock:
                errors[0] += 1
            return
        mine = []
        while time.time() < start_at:
            time.sleep(0.005)
        end = start_at + duration
        try:
            while True:
                t0 = time.perf_counter()
                if time.time() >= end:
                    break
                r = t.get("/news")
                if r.status != 200:
                    raise RuntimeError(r.status)
                mine.append(time.perf_counter() - t0)
        except Exception:
            with lock:
                errors[0] += 1
        finally:
            t.close()
        with lock:
            lat.extend(mine)

    threads = [threading.Thread(target=run) for _ in range(n_threads)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    return lat, errors[0]


def bench_concurrency(b: Bench, levels, duration):
    cpus = os.cpu_count() or 2
    results = {"direct": {}, "through proxy": {}}
    for n in levels:
        for name, mode in (("direct", "direct"), ("through proxy", "proxy")):
            procs = min(n, max(1, cpus // 2))
            split = [n // procs + (1 if i < n % procs else 0) for i in range(procs)]
            start_at = time.time() + 1.5 + 0.02 * n
            jobs = [(mode, b.tls, b.ports["web"], k, start_at, duration, str(ROOT / "certs")) for k in split]
            lat, errors = [], 0
            with cf.ProcessPoolExecutor(max_workers=procs) as ex:
                for part, err in ex.map(_load_worker, jobs):
                    lat += part
                    errors += err
            rps = len(lat) / duration
            s = summarize_ms(lat)
            results[name][n] = {"rps": rps, "p50": s["p50"], "p95": s["p95"], "errors": errors}
            log(f"  {n:>3} clients  {name:<14} {rps:8.0f} req/s   p50 {s['p50']:6.2f} ms   "
                f"p95 {s['p95']:6.2f} ms   errors {errors}")
    return results


# =========================================================================== 5. policy evaluation cost
def bench_policy_eval(sizes, iters):
    with open(ROOT / "config" / "policy.json", encoding="utf-8") as fh:
        base = json.load(fh)
    results = {}
    for n in sizes:
        doc = copy.deepcopy(base)
        filler = [{"id": f"X{i}", "action": "deny", "users": [f"user{i}"], "services": ["web"]} for i in range(n)]
        doc["rules"] = filler + doc["rules"]                   # bob's allow rule now sits after n non-matching rules
        p = Policy(doc)
        ctx = Context("bob", "127.0.0.1", "web", "GET", "/news")
        now = datetime.now()
        for _ in range(50):
            p.evaluate(ctx, "request", now)
        t0 = time.perf_counter()
        for _ in range(iters):
            d = p.evaluate(ctx, "request", now)
        us = (time.perf_counter() - t0) / iters * 1e6
        assert d.allowed and d.rule_id == "R06"
        results[n + len(base["rules"])] = us
        log(f"  {n + len(base['rules']):>5} rules   {us:8.2f} us per decision")
    return results


# =========================================================================== 6. reaction time
def bench_reaction(b: Bench, reps):
    carol = b.client("carol")
    kill_ms = []
    with b.admin() as admin:
        for _ in range(reps):
            t = carol.connect("chat")
            t.recv_until(b"/quit\n")
            t0 = time.perf_counter()
            ok, msg = admin.command("BLOCK user carol")
            closed = t.is_closed(3)
            kill_ms.append((time.perf_counter() - t0) * 1000)
            t.close()
            admin.command(f"UNBLOCK {msg.split()[3]}")
            assert ok and closed
    reload_ms = []
    anon = b.client()
    for _ in range(max(3, reps // 2)):
        t = anon.connect("echo")
        doc = copy.deepcopy(b.policy_doc)
        doc["rules"].insert(0, {"id": "BENCH", "action": "deny", "services": ["echo"]})
        time.sleep(random.uniform(0, 1))                       # random phase against the 1 s poll
        t0 = time.perf_counter()
        b.write_policy(doc)
        closed = t.is_closed(5)
        reload_ms.append((time.perf_counter() - t0) * 1000)
        t.close()
        b.write_policy(b.policy_doc)
        deadline = time.time() + 5
        while time.time() < deadline:                          # wait until the revert is live
            try:
                anon.connect("echo").close()
                break
            except ProxyRefused:
                time.sleep(0.1)
        assert closed
    res = {"admin_block": summarize_ms([x / 1000 for x in kill_ms]),
           "file_edit": summarize_ms([x / 1000 for x in reload_ms])}
    log(f"  admin BLOCK -> session cut     mean {res['admin_block']['mean']:6.1f} ms   "
        f"max {max(kill_ms):6.1f} ms")
    log(f"  policy file edit -> session cut mean {res['file_edit']['mean']:6.1f} ms   "
        f"max {max(reload_ms):6.1f} ms  (file polled every 1 s)")
    return res


# =========================================================================== report
def write_summary(r: dict):
    env = r["environment"]
    L = ["# netproxy performance evaluation", "",
         f"Run {env['date']} on {env['os']}, Python {env['python']}, {env['openssl']}, {env['cpus']} CPU cores"
         f"{' (quick mode)' if env['quick'] else ''}. Everything on one machine over loopback, so the numbers show "
         "the proxy's own processing cost rather than network delay.", ""]

    s = r["setup"]
    L += ["## 1. Connection setup latency", "",
          "Time from `connect()` until the first echoed byte arrives (sequential connections).", "",
          "| Path | mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) |", "|---|---:|---:|---:|---:|"]
    for k, v in s.items():
        L.append(f"| {k} | {v['mean']:.2f} | {v['p50']:.2f} | {v['p95']:.2f} | {v['p99']:.2f} |")
    hop = s["proxy, plain TCP"]["p50"] - s["direct TCP"]["p50"]
    tls = s["proxy, TLS"]["p50"] - s["proxy, plain TCP"]["p50"]
    mtls = s["proxy, mutual TLS"]["p50"] - s["proxy, TLS"]["p50"]
    L += ["", f"The extra proxy hop (second TCP connection, CONNECT exchange, policy check) adds about "
              f"**{hop:.2f} ms**; the TLS handshake adds **{tls:.2f} ms** more and verifying a client "
              f"certificate **{mtls:.2f} ms** on top. These are one-off costs per connection, which is why "
              f"keep-alive matters.", ""]

    q = r["request_latency"]
    d, p = q["direct"], q["through proxy (TLS, inspected)"]
    L += ["## 2. Request latency on an open connection", "",
          "| Path | p50 (ms) | p95 (ms) | p99 (ms) |", "|---|---:|---:|---:|",
          f"| direct | {d['p50']:.3f} | {d['p95']:.3f} | {d['p99']:.3f} |",
          f"| through proxy (TLS, HTTP inspection) | {p['p50']:.3f} | {p['p95']:.3f} | {p['p99']:.3f} |", "",
          f"Per request the proxy adds about **{p['p50'] - d['p50']:.2f} ms** at the median: parse the request, "
          "evaluate the rules, forward, read the full response, run the content filters, re-frame and encrypt.", ""]

    t = r["throughput"]
    MB = r["environment"]["transfer_mb"]
    L += ["## 3. Throughput", "", f"Single connection, {MB} MB transfer, median of the runs.", "",
          "| Path | download (MB/s) | upload (MB/s) |", "|---|---:|---:|"]
    for k, v in t.items():
        L.append(f"| {k} | {v['download']:.1f} | {v['upload']:.1f} |")
    relay, line = t["proxy relay (no inspection)"], t["proxy line inspection"]
    L += ["", f"Line inspection keeps **{100 * line['download'] / relay['download']:.0f}%** of the plain relay's "
              "download throughput: every byte is reassembled into lines and scanned by the filters. Services "
              "that do not need inspection should use `inspect: none`.", ""]

    c = r["concurrency"]
    L += ["## 4. Concurrent clients", "",
          f"Each client holds one keep-alive connection and sends `GET /news` back-to-back for "
          f"{env['load_seconds']} s.", "",
          "| Clients | direct req/s | proxy req/s | direct p95 (ms) | proxy p95 (ms) | errors |",
          "|---:|---:|---:|---:|---:|---:|"]
    for n in c["direct"]:
        dd, pp = c["direct"][n], c["through proxy"][n]
        L.append(f"| {n} | {dd['rps']:.0f} | {pp['rps']:.0f} | {dd['p95']:.2f} | {pp['p95']:.2f} | "
                 f"{dd['errors'] + pp['errors']} |")
    peak = max(v["rps"] for v in c["through proxy"].values())
    L += ["", f"The proxy peaks around **{peak:.0f} requests/s**. It uses one thread per connection; CPython's "
              "global interpreter lock means only one thread runs Python code at a time, so throughput "
              "levels off once a core is saturated and extra clients mostly add queueing delay (rising p95).",
          ""]

    e = r["policy_eval"]
    L += ["## 5. Policy evaluation cost", "",
          "Rules are scanned top to bottom until one matches; here the matching rule is last.", "",
          "| Rules | us per decision |", "|---:|---:|"]
    for n, us in e.items():
        L.append(f"| {n} | {us:.2f} |")
    sizes = list(e)
    small, big = e[sizes[0]], e[sizes[-1]]
    overhead_us = (p["p50"] - d["p50"]) * 1000
    L += ["", f"Cost grows linearly with the number of rules scanned: {small:.0f} us with the shipped "
              f"{sizes[0]} rules, {big:.0f} us with {sizes[-1]}. For comparison the whole per-request proxy "
              f"overhead measured in section 2 is about {overhead_us:.0f} us: {sizes[1]} rules add "
              f"{100 * e[sizes[1]] / overhead_us:.0f}% to it, {sizes[-1]} rules would dominate it. A large rule "
              "set would need an index (for example by service), and frequently matched rules belong near the "
              "top.", ""]

    x = r["reaction"]
    L += ["## 6. Reaction time of dynamic policy changes", "",
          "Time from the change until an already-open session is closed by the proxy.", "",
          "| Change | mean (ms) | p95 (ms) |", "|---|---:|---:|",
          f"| admin console `BLOCK user ...` | {x['admin_block']['mean']:.0f} | {x['admin_block']['p95']:.0f} |",
          f"| edit of the policy file | {x['file_edit']['mean']:.0f} | {x['file_edit']['p95']:.0f} |", "",
          f"Admin changes are applied at once and each open session notices within one 100 ms select() "
          f"tick (measured mean {x['admin_block']['mean']:.0f} ms). File edits first wait for the next poll "
          f"of the file (every 1 s), so they took {x['file_edit']['mean']:.0f} ms on average and at most about "
          "one poll interval plus one tick.", ""]
    if r.get("charts"):
        L += ["## Charts", ""] + [f"![{name}]({name})" for name in r["charts"]] + [""]
    (BENCH / "summary.md").write_text("\n".join(L), encoding="utf-8")


def make_charts(r: dict):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        log("  matplotlib not installed - skipping charts (pip install matplotlib)")
        return []

    SURF, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
    S1, S2 = "#2a78d6", "#eb6834"          # categorical slots 1-2 (validated pair)
    plt.rcParams.update({
        "font.family": "sans-serif", "font.sans-serif": ["Segoe UI", "Helvetica", "Arial", "DejaVu Sans"],
        "font.size": 10, "axes.edgecolor": AXIS, "axes.labelcolor": INK2, "axes.titlecolor": INK,
        "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
        "xtick.color": MUTED, "ytick.color": MUTED, "axes.facecolor": SURF, "figure.facecolor": SURF,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
        "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
        "legend.labelcolor": INK2,
    })
    files = []

    def save(fig, name):
        fig.tight_layout()
        fig.savefig(BENCH / name, dpi=150)
        plt.close(fig)
        files.append(name)

    # 1. setup latency: two series (p50, p95), grouped horizontal bars
    s = r["setup"]
    names = list(s)
    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    y = range(len(names))
    h = 0.34
    b1 = ax.barh([i - h / 2 for i in y], [s[n]["p50"] for n in names], h, color=S1, label="p50",
                 edgecolor=SURF, linewidth=2)
    b2 = ax.barh([i + h / 2 for i in y], [s[n]["p95"] for n in names], h, color=S2, label="p95",
                 edgecolor=SURF, linewidth=2)
    ax.set_yticks(list(y), names)
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("milliseconds")
    ax.set_title("Connection setup latency")
    for bars in (b1, b2):
        ax.bar_label(bars, fmt="%.2f", padding=3, color=INK2, fontsize=8)
    ax.legend(loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=2, borderaxespad=0.2)
    ax.margins(x=0.15)
    save(fig, "setup_latency.png")

    # 3. throughput: two series (download, upload)
    t = r["throughput"]
    names = list(t)
    fig, ax = plt.subplots(figsize=(7.5, 3.4))
    b1 = ax.barh([i - h / 2 for i in range(len(names))], [t[n]["download"] for n in names], h, color=S1,
                 label="download", edgecolor=SURF, linewidth=2)
    b2 = ax.barh([i + h / 2 for i in range(len(names))], [t[n]["upload"] for n in names], h, color=S2,
                 label="upload", edgecolor=SURF, linewidth=2)
    ax.set_yticks(range(len(names)), names)
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("MB/s (single connection)")
    ax.set_title("Throughput")
    for bars in (b1, b2):
        ax.bar_label(bars, fmt="%.0f", padding=3, color=INK2, fontsize=8)
    ax.legend(loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=2, borderaxespad=0.2)
    ax.margins(x=0.15)
    save(fig, "throughput.png")

    # 4. concurrency: requests/s and p95 as two separate charts (never a dual axis)
    c = r["concurrency"]
    levels = sorted(int(k) for k in c["direct"])
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.5, 3.6))
    for ax, key, title, unit in ((a1, "rps", "Requests per second", "req/s"),
                                 (a2, "p95", "p95 latency", "ms")):
        for name, color in (("direct", S1), ("through proxy", S2)):
            ys = [c[name][n][key] for n in levels]
            ax.plot(levels, ys, color=color, linewidth=2, marker="o", markersize=6,
                    markeredgecolor=SURF, markeredgewidth=2, label=name, solid_capstyle="round")
            ax.annotate(f"{ys[-1]:.0f}" if key == "rps" else f"{ys[-1]:.1f}", (levels[-1], ys[-1]),
                        textcoords="offset points", xytext=(6, 0), va="center", color=INK2, fontsize=8)
        ax.set_xscale("log", base=2)
        ax.set_xticks(levels, [str(n) for n in levels])
        ax.minorticks_off()
        ax.set_xlabel("concurrent clients")
        ax.set_ylabel(unit)
        ax.set_title(title)
        ax.set_ylim(bottom=0)
        ax.margins(x=0.12)
    a2.legend(loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=2, borderaxespad=0.2)
    save(fig, "concurrency.png")

    # 5. policy evaluation: single series
    e = r["policy_eval"]
    ns = [int(k) for k in e]
    fig, ax = plt.subplots(figsize=(6.5, 3.4))
    ax.plot(ns, list(e.values()), color=S1, linewidth=2, marker="o", markersize=6, markeredgecolor=SURF,
            markeredgewidth=2)
    ax.set_xscale("log")
    ax.set_yscale("log")
    from matplotlib.ticker import FuncFormatter, NullFormatter
    plain = FuncFormatter(lambda v, _: f"{v:,.0f}")
    ax.set_xticks(ns)
    ax.xaxis.set_major_formatter(plain)
    ax.yaxis.set_major_formatter(plain)
    for axis in (ax.xaxis, ax.yaxis):
        axis.set_minor_formatter(NullFormatter())
    ax.set_xlabel("rules scanned before the match")
    ax.set_ylabel("microseconds per decision")
    ax.set_title("Policy evaluation cost (first-match scan)")
    ax.annotate(f"{list(e.values())[-1]:.0f} us", (ns[-1], list(e.values())[-1]), textcoords="offset points",
                xytext=(-8, 8), ha="right", color=INK2, fontsize=8)
    save(fig, "policy_eval.png")
    return files


# =========================================================================== main
def main():
    ap = argparse.ArgumentParser(description="Performance evaluation of netproxy")
    ap.add_argument("--quick", action="store_true", help="smaller, faster run")
    args = ap.parse_args()
    q = args.quick
    cfg = {"setup_n": 60 if q else 200, "req_n": 200 if q else 1000, "transfer_mb": 30 if q else 100,
           "reps": 2 if q else 3, "levels": [1, 4, 16, 32] if q else [1, 4, 16, 32, 64],
           "load_seconds": 3 if q else 5, "eval_sizes": [0, 93, 993, 4993], "eval_iters": 2000,
           "reaction_reps": 6 if q else 10}

    b = Bench().start()
    results = {"environment": {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"), "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION, "cpus": os.cpu_count(),
        "quick": q, "transfer_mb": cfg["transfer_mb"], "load_seconds": cfg["load_seconds"]}}
    try:
        log("1. connection setup latency")
        results["setup"] = bench_setup(b, cfg["setup_n"])
        log("2. request latency on an open connection")
        results["request_latency"] = bench_request_latency(b, cfg["req_n"])
        log("3. throughput")
        results["throughput"] = bench_throughput(b, cfg["transfer_mb"] * 1_000_000, cfg["reps"])
        log("4. concurrent clients")
        results["concurrency"] = bench_concurrency(b, cfg["levels"], cfg["load_seconds"])
        log("5. policy evaluation cost")
        results["policy_eval"] = bench_policy_eval(cfg["eval_sizes"], cfg["eval_iters"])
        log("6. reaction time of dynamic changes")
        results["reaction"] = bench_reaction(b, cfg["reaction_reps"])
    finally:
        b.stop()
    log("charts")
    results["charts"] = make_charts(results)
    with open(BENCH / "results.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    write_summary(results)
    log(f"\nwrote {BENCH / 'results.json'}, {BENCH / 'summary.md'}"
        + (f" and {len(results['charts'])} charts" if results["charts"] else ""))


if __name__ == "__main__":
    main()
