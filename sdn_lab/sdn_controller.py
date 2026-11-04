"""
sdn_controller.py -- Ryu (OpenFlow 1.3) controller for the WebSentry network.

Run by sdn_lab/run_demo.py:   ryu-manager --ofp-tcp-listen-port 6653 sdn_lab/sdn_controller.py

What it does
  1. Access control in the network. The only allowed paths are  client <-> proxy  and  proxy <-> services.
     A client that tries to reach a service (or another client) directly gets a DROP flow installed, so the
     proxy cannot be bypassed.
  2. Reactive forwarding. First packet of a flow -> packet-in -> L2 learning -> exact flow installed
     (match eth_type, ipv4_src, ipv4_dst; idle timeout 30 s).
  3. Dynamic quarantine, driven by the application. The proxy reports every denied request / blocked content
     to the control socket. When one source IP produces VIOL_THRESHOLD violations within VIOL_WINDOW seconds,
     the controller installs a high-priority DROP flow for that IP on every switch, for BLOCK_SECONDS.
     The proxy then never sees that host again (no sockets, no TLS handshakes, no CPU spent on it).
  4. Monitoring. Flow statistics are polled every 5 s and written to the event log.
  5. Manual control. Text commands on the same socket:  BLOCK <ip> [seconds] | UNBLOCK <ip> | STATUS

SDN_MODE=static turns 2-4 into a plain learning switch (no ACL, no quarantine). That is the baseline the
performance evaluation compares against.

Settings (environment): SDN_MODE (sdn|static), SDN_SOCK, SDN_LOG, PROXY_IP, VIOL_THRESHOLD, VIOL_WINDOW, BLOCK_SECONDS.
"""
import collections
import json
import os
import socket
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import arp, ether_types, ethernet, ipv4, packet
from ryu.ofproto import ofproto_v1_3

MODE = os.environ.get("SDN_MODE", "sdn")
SOCK_PATH = os.environ.get("SDN_SOCK", "/tmp/websentry_sdn.sock")
LOG_PATH = os.environ.get("SDN_LOG", "logs/sdn_events.jsonl")
PROXY_IP = os.environ.get("PROXY_IP", "10.0.0.10")
VIOL_THRESHOLD = int(os.environ.get("VIOL_THRESHOLD", "5"))
VIOL_WINDOW = float(os.environ.get("VIOL_WINDOW", "10"))
BLOCK_SECONDS = int(os.environ.get("BLOCK_SECONDS", "60"))

PRIO_FORWARD, PRIO_DENY, PRIO_QUARANTINE = 100, 150, 300
ETH_IP = ether_types.ETH_TYPE_IP


class WebSentryController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = collections.defaultdict(dict)
        self.blocked = {}                                    # ip -> (until, reason)
        self.violations = collections.defaultdict(collections.deque)
        self.counters = collections.Counter()
        self.recent = collections.deque(maxlen=40)           # shown in the dashboard
        self.last_flows = {}                                 # (src, dst) -> row from the latest stats poll
        os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
        self._log_fh = open(LOG_PATH, "a", buffering=1)
        self._event("start", mode=MODE, proxy=PROXY_IP, threshold=VIOL_THRESHOLD, window=VIOL_WINDOW,
                    block_seconds=BLOCK_SECONDS)
        hub.spawn(self._control_server)
        hub.spawn(self._monitor)
        hub.spawn(self._expire_blocks)

    # ------------------------------------------------------------------ helpers
    def _event(self, kind, **fields):
        rec = {"ts": round(time.time(), 3), "event": kind, **fields}
        self._log_fh.write(json.dumps(rec) + "\n")
        if kind != "flow_stats":
            self.recent.appendleft(rec)
        self.logger.info("%s %s", kind, fields)

    def _add_flow(self, dp, prio, match, actions=None, idle=0, hard=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []   # no actions = drop
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=prio, match=match, instructions=inst,
                                      idle_timeout=idle, hard_timeout=hard))

    def _del_flows(self, dp, match):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY,
                                      out_group=ofp.OFPG_ANY, match=match))

    @staticmethod
    def _allowed(src, dst):
        """Network ACL: everything must go through the proxy."""
        return src == PROXY_IP or dst == PROXY_IP

    # ------------------------------------------------------------------ OpenFlow events
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        self._add_flow(dp, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self._event("switch_connected", dpid=dp.id)
        for ip in self.blocked:                              # a switch that reconnects gets the quarantine again
            self._install_quarantine(dp, ip, 0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        self.mac_to_port[dp.id][eth.src] = in_port
        ip = pkt.get_protocol(ipv4.ipv4)
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if ip is not None and MODE == "sdn":
            if ip.src in self.blocked:
                self._add_flow(dp, PRIO_QUARANTINE, parser.OFPMatch(eth_type=ETH_IP, ipv4_src=ip.src), hard=BLOCK_SECONDS)
                self.counters["dropped_blocked"] += 1
                return
            if not self._allowed(ip.src, ip.dst):
                self._add_flow(dp, PRIO_DENY, parser.OFPMatch(eth_type=ETH_IP, ipv4_src=ip.src, ipv4_dst=ip.dst), idle=20)
                self.counters["denied_unauthorized"] += 1
                self._event("unauthorized", dpid=dp.id, src=ip.src, dst=ip.dst, proto=ip.proto)
                return
        if ip is not None and out_port != ofp.OFPP_FLOOD:
            self._add_flow(dp, PRIO_FORWARD, parser.OFPMatch(eth_type=ETH_IP, ipv4_src=ip.src, ipv4_dst=ip.dst),
                           actions, idle=30)
            self.counters["flows_installed"] += 1
        # ARP and unknown destinations are flooded; forwarded packets that triggered packet-in are re-sent
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port,
                                        actions=actions, data=msg.data))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats(self, ev):
        rows = []
        for st in ev.msg.body:
            if st.priority >= PRIO_FORWARD and "ipv4_src" in st.match:
                rows.append({"src": st.match["ipv4_src"], "dst": st.match.get("ipv4_dst"), "prio": st.priority,
                             "packets": st.packet_count, "bytes": st.byte_count})
        if rows:
            for r in rows:
                key = (r["src"], r["dst"])
                self.last_flows[key] = {**r, "dpid": ev.msg.datapath.id}
            self._event("flow_stats", dpid=ev.msg.datapath.id, flows=rows)

    # ------------------------------------------------------------------ quarantine
    def _install_quarantine(self, dp, ip, seconds):
        self._add_flow(dp, PRIO_QUARANTINE, dp.ofproto_parser.OFPMatch(eth_type=ETH_IP, ipv4_src=ip), hard=seconds)

    def block(self, ip, seconds=BLOCK_SECONDS, reason="manual"):
        if ip == PROXY_IP:
            return False, "refusing to block the proxy"
        first = ip not in self.blocked
        self.blocked[ip] = (time.time() + seconds, reason)
        for dp in self.datapaths.values():
            self._install_quarantine(dp, ip, seconds)
        if first:
            self.counters["quarantines"] += 1
        self._event("block", ip=ip, seconds=seconds, reason=reason)
        return True, f"blocked {ip} for {seconds}s"

    def unblock(self, ip):
        if self.blocked.pop(ip, None) is None:
            return False, f"{ip} is not blocked"
        for dp in self.datapaths.values():
            self._del_flows(dp, dp.ofproto_parser.OFPMatch(eth_type=ETH_IP, ipv4_src=ip))
        self.violations.pop(ip, None)
        self._event("unblock", ip=ip)
        return True, f"unblocked {ip}"

    def _violation(self, msg):
        src = msg.get("src")
        if MODE != "sdn" or not src or src == PROXY_IP or src in self.blocked:
            return
        now = time.time()
        q = self.violations[src]
        q.append(now)
        while q and now - q[0] > VIOL_WINDOW:
            q.popleft()
        self.counters["violations"] += 1
        if len(q) >= VIOL_THRESHOLD:
            self.block(src, BLOCK_SECONDS, f"{len(q)} violations in {VIOL_WINDOW:g}s "
                                           f"(last: {msg.get('rule')} {msg.get('reason')})")
            q.clear()

    def _expire_blocks(self):
        while True:
            hub.sleep(1)
            now = time.time()
            for ip in [i for i, (until, _) in self.blocked.items() if until <= now]:
                self.blocked.pop(ip, None)
                self._event("block_expired", ip=ip)

    def _monitor(self):
        while True:
            hub.sleep(5)
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    # ------------------------------------------------------------------ control socket (proxy + operator)
    def _control_server(self):
        try:
            os.unlink(SOCK_PATH)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(SOCK_PATH)
        os.chmod(SOCK_PATH, 0o777)
        srv.listen(16)
        while True:
            conn, _ = srv.accept()
            hub.spawn(self._serve_conn, conn)

    def _serve_conn(self, conn):
        buf = b""
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    reply = self._handle_line(line.decode("utf-8", "replace").strip())
                    if reply is not None:
                        conn.sendall((json.dumps(reply) + "\n").encode())
        except OSError:
            pass
        finally:
            conn.close()

    def _handle_line(self, line):
        if not line:
            return None
        if line.startswith("{"):                               # event from the proxy
            try:
                msg = json.loads(line)
            except ValueError:
                return None
            if msg.get("type") == "violation":
                self._violation(msg)
            return None
        parts = line.split()
        cmd = parts[0].upper()
        if cmd == "BLOCK" and len(parts) >= 2:
            ok, text = self.block(parts[1], int(parts[2]) if len(parts) > 2 else BLOCK_SECONDS)
            return {"ok": ok, "msg": text}
        if cmd == "UNBLOCK" and len(parts) == 2:
            ok, text = self.unblock(parts[1])
            return {"ok": ok, "msg": text}
        if cmd == "STATUS":
            now = time.time()
            flows = sorted(self.last_flows.values(), key=lambda r: -r["bytes"])[:12]
            return {"ok": True, "mode": MODE, "switches": sorted(self.datapaths), "proxy": PROXY_IP,
                    "threshold": VIOL_THRESHOLD, "window": VIOL_WINDOW,
                    "blocked": {ip: {"seconds_left": max(0, round(until - now)), "reason": why}
                                for ip, (until, why) in self.blocked.items()},
                    "violations": {ip: sum(1 for t in q if now - t <= VIOL_WINDOW)
                                   for ip, q in self.violations.items() if q},
                    "flows": flows, "recent": list(self.recent)[:15], "counters": dict(self.counters)}
        return {"ok": False, "msg": "commands: BLOCK <ip> [s] | UNBLOCK <ip> | STATUS"}
