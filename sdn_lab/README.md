# WebSentry on Mininet + SDN

Course rubric: *SDN-Socket Programming - Jackfruit Mini Project* (TCP sockets + Mininet + SDN controller).
This folder adds the network side of WebSentry: the proxy and services of the main project run on emulated
hosts, behind OpenFlow switches controlled by a Ryu application that reacts to what the proxy sees.

## Architecture

```
 h1 alice 10.0.0.1 --\                                         +-- proxy 10.0.0.10  proxy.py  (TLS :8443, plain :8080)
 h2 bob   10.0.0.2 ---+-- s1 (OVS) ====== s2 (OVS) ------------+
 h3 anon  10.0.0.3 --/       \              /                  +-- svc   10.0.0.20  services.py (web/chat/echo/files/bulk)
   TCLink: bw/delay/loss      \  OpenFlow 1.3 (tcp 6653)
                               +-----> Ryu controller (sdn_controller.py)  <---- UNIX socket ---- proxy (violation events)
```

| Rubric item | Where |
|---|---|
| TCP socket application | the main project: `netproxy/server.py` (accept/select/TLS relay), `services.py`, `client.py` |
| Mininet topology | `topo.py` - 3 clients, 2 switches, proxy host, service host, TCLinks |
| SDN controller + flow rules | `sdn_controller.py` - ACL drop flows, reactive forwarding flows, quarantine flows, flow-stats monitor |
| Socket <-> SDN integration | `netproxy/sdn.py` sends every denied request to the controller; the controller turns repeated violations into a network-level DROP |
| Operator view | `templates/network.html` + `/network` routes in `app.py` - live quarantine table, flows, events, block/release |
| Dynamic SDN behaviour | quarantine after N violations in W seconds, timed release, manual `BLOCK/UNBLOCK/STATUS` |
| Challenging scenarios | flood by a misbehaving host, direct bypass attempt, back-end failure, packet loss (`run_demo.py`) |
| Performance vs baseline | `bench.py` - SDN controller vs plain learning switch, writes `RESULTS.md` |

### What the controller enforces
1. **No bypass** - only `client <-> proxy` and `proxy <-> services` traffic is allowed. A client packet to the service
   host (or to another client) triggers a packet-in; the controller installs a DROP flow (priority 150, 20 s idle).
2. **Forwarding** - allowed flows are learned (L2) and installed as exact flows `(eth_type, ipv4_src, ipv4_dst)`, idle 30 s.
3. **Quarantine** - the proxy reports each denied request / blocked content with the client's IP. At `VIOL_THRESHOLD`
   (5) violations within `VIOL_WINDOW` (10 s) the controller installs a priority-300 DROP flow for that source on every
   switch for `BLOCK_SECONDS` (60). The proxy never sees that host again.
4. **Monitoring** - flow counters polled every 5 s into `logs/mininet/sdn_<mode>.jsonl`.

Why a UNIX socket for the proxy->controller channel: Mininet hosts have private network namespaces but share the
filesystem, so it acts as an out-of-band management network and keeps control traffic out of the emulated data plane.

## Install (Ubuntu 22.04 VM, ARM or x86)

```bash
sudo apt update && sudo apt install -y mininet openvswitch-switch python3-pip tcpdump iperf3
sudo service openvswitch-switch start
# Ryu needs an old Python (eventlet 0.30.2); newer distros (Python 3.12+, PEP 668) need a separate env:
curl -LsSf https://astral.sh/uv/install.sh | sh && source ~/.local/bin/env
uv venv --python 3.9 ~/ryuenv
sudo apt install -y git
uv pip install --python ~/ryuenv/bin/python "setuptools==57.5.0" wheel
uv pip install --python ~/ryuenv/bin/python --no-build-isolation --no-deps "git+https://github.com/faucetsdn/ryu.git"
uv pip install --python ~/ryuenv/bin/python "eventlet==0.30.2" msgpack tinyrpc packaging ovs six routes webob netaddr oslo.config
$HOME/ryuenv/bin/ryu-manager --version                 # expect: ryu-manager 4.34
# (the PyPI ryu 4.34 sdist fails to build with new setuptools and uv then silently installs the unrelated ryu 2.2)
export RYU_MANAGER=$HOME/ryuenv/bin/ryu-manager      # pass it through sudo explicitly (see Run)
sudo apt install -y python3-matplotlib                # optional, for charts
```
Copy this project into the VM (see the Multipass/UTM notes you were given), then from the project root:

## Run

Tested on Ubuntu 26.04 ARM64 (VMware Fusion), Python 3.14 system / 3.9 for Ryu, Mininet from apt. First full demo run: 22/22 checks.

```bash
sudo RYU_MANAGER=$RYU_MANAGER python3 sdn_lab/run_demo.py            # 6 scenarios with PASS/FAIL, then the Mininet CLI
sudo RYU_MANAGER=$RYU_MANAGER python3 sdn_lab/run_demo.py --no-cli   # for scripts
sudo RYU_MANAGER=$RYU_MANAGER python3 sdn_lab/run_demo.py --only 4   # one scenario
sudo RYU_MANAGER=$RYU_MANAGER python3 sdn_lab/bench.py [--quick]     # SDN vs static baseline -> sdn_lab/RESULTS.md, sdn_lab/charts/
sudo python3 -m unittest sdn_lab.test_smoke
```
Logs: `logs/mininet/` (proxy access log, service logs, `ryu_*.log`, `sdn_*.jsonl`, `demo_*.json`, `bench.json`).

Useful in the Mininet CLI:
```
h2 python3 client.py --user bob --proxy 10.0.0.10:8443 web /news
h2 ping -c1 10.0.0.20                       # dropped: clients cannot reach services directly
sh ovs-ofctl -O OpenFlow13 dump-flows s1     # watch the flows appear
h3 python3 sdn_lab/loadgen.py flood --duration 6   # then dump-flows again: priority=300 drop for 10.0.0.3
```
Talk to the controller by hand: `echo STATUS | sudo socat - UNIX-CONNECT:/tmp/websentry_sdn.sock` (also `BLOCK <ip> [s]`, `UNBLOCK <ip>`).
Packet capture for Wireshark: `proxy tcpdump -i proxy-eth0 -w logs/mininet/proxy.pcap`.

## Dashboard inside the lab (Network (SDN) page)

`app.py` (the AccessWindow dashboard) can run on the Mininet proxy host. Its new admin-only **Network (SDN)** page
shows the controller's state live and lets the administrator block or release a host:
quarantined hosts with the reason and time left, the watch list (violations so far), the busiest flows, the
controller's event log, and a "Block a host" form.

```bash
sudo apt install -y socat python3-venv
python3 -m venv ~/appenv && ~/appenv/bin/pip install "Flask>=3,<4"
export DASH_PYTHON=$HOME/appenv/bin/python
sudo RYU_MANAGER=$RYU_MANAGER DASH_PYTHON=$DASH_PYTHON python3 sdn_lab/run_demo.py --dashboard --no-scenarios
```
Open `http://127.0.0.1:5000` in the VM (login `admin` / `admin-demo`), or from the Mac:
`ssh -L 5000:127.0.0.1:5000 <vm-user>@<vm-ip>` and then `http://127.0.0.1:5000`. Open **Network (SDN)** in the sidebar,
then at the `mininet>` prompt run `h3 python3 sdn_lab/loadgen.py flood --duration 6` and watch h3 appear in
"Quarantined hosts" (the page refreshes every 5 s). **Release** it from the page, or **Block** `10.0.0.2` (bob) and
run `h2 python3 client.py --user bob --proxy 10.0.0.10:8443 web /news` to see the connection time out.

How it is wired: `app.py` runs inside the proxy host's namespace, so `127.0.0.1:9443` is the proxy's admin console
and `/tmp/websentry_sdn.sock` (shared filesystem) is the controller. A `socat` + `nsenter` forwarder makes port 5000
reachable from the VM. Outside the lab the page simply reports that the controller is not reachable.

## Scenarios (`run_demo.py`)
1. normal operation - identity from client certificates, rules R01-R07 from three hosts
2. bypass attempt - bob connects straight to the service host: dropped by the switch (baseline: succeeds)
3. source-IP rule - a deny rule on `10.0.0.2/32` hot-reloads and matches bob's real address
4. dynamic quarantine - flood from h3 -> controller installs a DROP flow -> h3 cut off, alice unaffected -> UNBLOCK
5. service failure - services killed: proxy answers 502 instead of hanging; recovers on restart
6. packet loss - 5 % loss on a client link, requests still complete

## Why Mininet (viva)
Real network behaviour on one machine: separate hosts with real IP addresses, switches with flow tables, links with
configurable bandwidth/delay/loss, and a real OpenFlow controller. On loopback, source-IP rules, bypass attempts,
quarantine and loss cannot be shown at all.

## Known limits
* ACL is IP-pair based (any port); the proxy only listens on 8443/8080 on its host (admin console is 127.0.0.1 only).
* The controller blocks by source IP; hosts behind one IP (NAT) would be blocked together.
* Single controller, no failover.
