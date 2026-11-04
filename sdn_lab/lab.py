"""
lab.py -- start / stop the whole emulated system:  Mininet + Ryu controller + services + proxy.

    with Lab(mode="sdn") as lab:
        print(lab.client("h1", "web /news"))

mode="sdn"     the controller enforces the ACL and quarantines misbehaving hosts
mode="static"  the controller is a plain learning switch (the baseline for the evaluation)
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.log import setLogLevel

sys.path.insert(0, str(Path(__file__).resolve().parent))
from topo import CLIENTS, IPS, USERS, WebSentryTopo  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "logs" / "mininet"
GEN = Path(__file__).resolve().parent / "generated"
SOCK = "/tmp/websentry_sdn.sock"
OF_PORT = 6653
PROXY = f"{IPS['proxy']}:8443"


def make_policy() -> Path:
    """Copy config/policy.json, point every service at the svc host and lift the per-user rate limits."""
    GEN.mkdir(exist_ok=True)
    doc = json.loads((ROOT / "config" / "policy.json").read_text())
    for spec in doc["services"].values():
        spec["host"] = IPS["svc"]
    doc["limits"] = {"max_conns_per_user": 500, "max_new_conns_per_window": 100000, "window_seconds": 10}
    path = GEN / "policy.json"
    path.write_text(json.dumps(doc, indent=2))
    return path


def write_policy(doc: dict, path: Path):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2))
    os.replace(tmp, path)                              # atomic, so the proxy never reads half a file


def controller_cmd(line: str, timeout: float = 3.0) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    s.sendall((line + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return json.loads(data or b"{}")


class Lab:
    def __init__(self, mode="sdn", threshold=5, window=10, block_seconds=60, client_bw=20, client_delay="2ms",
                 client_loss=0, quiet=True):
        self.mode, self.threshold, self.window, self.block_seconds = mode, threshold, window, block_seconds
        self.topo_args = dict(client_bw=client_bw, client_delay=client_delay, client_loss=client_loss)
        self.quiet = quiet
        self.net = None
        self.procs = []
        self.policy_path = make_policy()

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        if os.geteuid() != 0:
            sys.exit("Mininet needs root:  sudo python3 ...")
        self.ryu = os.environ.get("RYU_MANAGER") or shutil.which("ryu-manager")
        if not self.ryu:
            sys.exit("ryu-manager not found - set RYU_MANAGER=/path/to/ryu-manager (see sdn_lab/README.md)")
        OUT.mkdir(parents=True, exist_ok=True)
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        setLogLevel("warning" if self.quiet else "info")
        for p in (OUT / f"sdn_{self.mode}.jsonl",):
            p.unlink(missing_ok=True)
        env = dict(os.environ, SDN_MODE=self.mode, SDN_SOCK=SOCK, SDN_LOG=str(OUT / f"sdn_{self.mode}.jsonl"),
                   PROXY_IP=IPS["proxy"], VIOL_THRESHOLD=str(self.threshold), VIOL_WINDOW=str(self.window),
                   BLOCK_SECONDS=str(self.block_seconds))
        ctl_log = open(OUT / f"ryu_{self.mode}.log", "w")
        self.procs.append(subprocess.Popen([self.ryu, "--ofp-tcp-listen-port", str(OF_PORT),
                                            str(Path(__file__).resolve().parent / "sdn_controller.py")],
                                           env=env, stdout=ctl_log, stderr=subprocess.STDOUT))
        self._wait(lambda: os.path.exists(SOCK) and self._tcp_ok("127.0.0.1", OF_PORT), 20, "Ryu controller")
        self.net = Mininet(topo=WebSentryTopo(**self.topo_args), switch=OVSKernelSwitch, link=TCLink,
                           controller=None, autoSetMacs=False, waitConnected=False)
        self.net.addController(RemoteController("c0", ip="127.0.0.1", port=OF_PORT))
        self.net.start()
        if not self.net.waitConnected(timeout=20):
            raise RuntimeError("switches did not connect to the controller")
        self._start_apps()
        return self

    def _kill_stale_dashboard(self, port):
        """Leftovers of a previous run (dashboard app.py, or a socat forwarding into a dead namespace) would keep
        127.0.0.1:<port> busy, so the new forwarder could not bind and the dashboard stayed unreachable."""
        me = os.getpid()
        for d in Path("/proc").iterdir():
            if not d.name.isdigit() or int(d.name) == me:
                continue
            try:
                cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
                stale = (cmd.rstrip().endswith("app.py") and os.readlink(d / "cwd") == str(ROOT)) or \
                        f"TCP-LISTEN:{port}," in cmd
                if stale:
                    os.kill(int(d.name), 9)
                    print(f"killed stale dashboard process {d.name}: {cmd.strip()[:70]}")
            except (OSError, ValueError):
                continue
        time.sleep(0.3)

    def _popen(self, node, args, logname):
        f = open(OUT / logname, "w")
        p = node.popen([sys.executable, "-u", *args], cwd=str(ROOT), stdout=f, stderr=subprocess.STDOUT)
        self.procs.append(p)
        return p

    def _start_apps(self):
        net = self.net
        self.svc_proc = self._popen(net["svc"], ["services.py", "--host", IPS["svc"]], f"svc_{self.mode}.log")
        self._wait(lambda: self.reachable("proxy", IPS["svc"], 9001), 15, "services")
        self.proxy_proc = self._popen(
            net["proxy"], ["proxy.py", "--policy", str(self.policy_path), "--plain-port", "8080",
                           "--access-log", str(OUT / f"access_{self.mode}.log"), "--sdn-socket", SOCK, "-q"],
            f"proxy_{self.mode}.log")
        self._wait(lambda: self.reachable("h1", IPS["proxy"], 8443), 15, "proxy")

    def start_dashboard(self, port=5000):
        """Run app.py on the proxy host (so it sees the proxy admin console on its 127.0.0.1:9443 and the
        controller's UNIX socket) and forward 127.0.0.1:<port> of the VM into that host's namespace."""
        py = os.environ.get("DASH_PYTHON", sys.executable)
        env = dict(os.environ, SDN_SOCK=SOCK, ACCESSWINDOW_HOST="127.0.0.1")
        node = self.net["proxy"]
        self._kill_stale_dashboard(port)
        log = open(OUT / "dashboard.log", "w")
        self.procs.append(node.popen([py, "-u", "app.py"], cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT))
        self._wait(lambda: self.reachable("proxy", "127.0.0.1", port), 20, f"dashboard (see {OUT / 'dashboard.log'})")
        if not shutil.which("socat"):
            print("socat missing (sudo apt install socat): the dashboard runs, but is only reachable inside the proxy host")
            return
        fwd_log = open(OUT / "dashboard_forward.log", "w")
        fwd = subprocess.Popen(
            ["socat", f"TCP-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork",
             f"EXEC:nsenter -t {node.pid} -n socat STDIO TCP\\:127.0.0.1\\:{port}"],
            stdout=fwd_log, stderr=subprocess.STDOUT)
        self.procs.append(fwd)
        time.sleep(0.5)
        if fwd.poll() is not None:
            raise RuntimeError(f"dashboard forwarder exited (port {port} busy?) - see {OUT / 'dashboard_forward.log'}")
        self._wait(lambda: self._tcp_ok("127.0.0.1", port), 10, f"dashboard forwarder (see {OUT / 'dashboard_forward.log'})")

    def stop(self):
        for p in reversed(self.procs):
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                p.kill()
        self.procs.clear()
        if self.net:
            self.net.stop()
            self.net = None
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _tcp_ok(host, port):
        try:
            socket.create_connection((host, port), 1).close()
            return True
        except OSError:
            return False

    @staticmethod
    def _wait(cond, timeout, what):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return
            time.sleep(0.3)
        raise RuntimeError(f"timed out waiting for {what}")

    def reachable(self, frm, ip, port, timeout=2) -> bool:
        out = self.net[frm].cmd(f"{sys.executable} -c \"import socket;socket.create_connection(('{ip}',{port}),{timeout}).close()\" "
                                f">/dev/null 2>&1; echo RC=$?")
        return "RC=0" in out

    def client(self, host, args, timeout=20) -> str:
        """Run client.py on a Mininet host as that host's user; returns stdout+stderr and exit code."""
        user = USERS[host]
        who = f"--user {user}" if user else ""
        out = self.net[host].cmd(f"cd {ROOT} && timeout {timeout} {sys.executable} client.py {who} --proxy {PROXY} {args} 2>&1; echo __rc=$?")
        return out

    def loadgen(self, host, args, timeout=120) -> dict:
        user = USERS.get(host) or "anonymous"
        out = self.net[host].cmd(f"cd {ROOT} && timeout {timeout} {sys.executable} sdn_lab/loadgen.py {args.replace('{user}', user)} 2>&1")
        for line in reversed(out.strip().splitlines()):
            if line.startswith("{"):
                return json.loads(line)
        raise RuntimeError(f"loadgen on {host} failed:\n{out}")

    def loadgen_bg(self, host, args):
        user = USERS.get(host) or "anonymous"
        return self.net[host].popen([sys.executable, "-u", str(ROOT / "sdn_lab" / "loadgen.py"), *args.replace("{user}", user).split()],
                                    cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def set_client_link(self, host, delay="2ms", loss=0, bw=20):
        """Re-shape host<->s1 live (both directions)."""
        for link in self.net.linksBetween(self.net[host], self.net["s1"]):
            for intf in (link.intf1, link.intf2):
                intf.config(bw=bw, delay=delay, loss=loss)

    def flows(self, switch="s1") -> str:
        return subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch], capture_output=True, text=True).stdout

    def sdn_events(self):
        p = OUT / f"sdn_{self.mode}.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []

    def policy_edit(self, fn):
        doc = json.loads(self.policy_path.read_text())
        fn(doc)
        write_policy(doc, self.policy_path)
