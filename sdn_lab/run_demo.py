"""
run_demo.py -- functional demo / test of WebSentry on Mininet + Ryu.

    sudo python3 sdn_lab/run_demo.py            # run every scenario, print PASS/FAIL, then drop into the Mininet CLI
    sudo python3 sdn_lab/run_demo.py --no-cli   # same, exit afterwards (exit code 1 if anything failed)
    sudo python3 sdn_lab/run_demo.py --only 4   # a single scenario
    sudo python3 sdn_lab/run_demo.py --dashboard --no-scenarios   # network + web dashboard, then the CLI

Scenarios
  1  normal operation       identity + policy through the proxy, from three hosts
  2  bypass attempt         a client talks to the service host directly -> dropped by the switch
  3  source-IP rule         the proxy policy matches the clients' real IPs (hot reload)
  4  dynamic quarantine     repeated violations -> controller installs a DROP flow for that host -> released later
  5  service failure        back end dies -> clean 502, recovers when it returns
  6  packet loss            5 % loss on a client link; request still succeeds (TCP retransmits)
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lab import IPS, OUT, Lab, controller_cmd  # noqa: E402

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append({"check": name, "pass": bool(ok), "detail": detail})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  - {detail}" if detail and not ok else ""))
    return ok


def s1_normal(lab):
    out = lab.client("h1", "web /news")
    check("alice (staff) GET /news -> 200", "HTTP 200" in out, out[-200:])
    out = lab.client("h1", "web /admin/panel")
    check("alice GET /admin/panel -> 200 (R01 staff)", "HTTP 200" in out, out[-200:])
    out = lab.client("h2", "web /admin/panel")
    check("bob (student) GET /admin/panel -> refused by R04", "R04" in out, out[-200:])
    out = lab.client("h2", "chat --send 'hello from bob'")
    check("bob connects to chat", "Connection Established" in out, out[-200:])
    out = lab.client("h3", "chat")
    check("anonymous refused chat by R03", "R03" in out and "403" in out, out[-200:])
    out = lab.client("h3", "web /news")
    check("anonymous may browse web (R07)", "HTTP 200" in out, out[-200:])


def s2_bypass(lab):
    check("proxy host reaches services", lab.reachable("proxy", IPS["svc"], 9001))
    reach = lab.reachable("h2", IPS["svc"], 9001, timeout=3)
    if lab.mode == "sdn":
        check("bob -> services directly is DROPPED", not reach)
        ping = lab.net["h2"].cmd(f"ping -c 2 -W 1 {IPS['svc']}")
        check("bob cannot even ping the services host", " 100% packet loss" in ping, ping[-120:])
        drops = [l for l in lab.flows("s1").splitlines() if "actions=drop" in l or "priority=150" in l]
        check("switch s1 holds a DROP flow for it", any(IPS["h2"] in l and IPS["svc"] in l for l in drops), "\n".join(drops))
    else:
        check("(baseline) direct access is NOT prevented", reach)


def s3_source_ip(lab):
    rule = {"id": "R-IP", "action": "deny", "src": [f"{IPS['h2']}/32"], "reason": "host h2 quarantined by IP"}
    lab.policy_edit(lambda d: d["rules"].insert(0, rule))
    time.sleep(2.5)                                   # policy poll is 1 s
    out = lab.client("h2", "web /news")
    check("deny rule on 10.0.0.2/32 matches bob's real source IP", "R-IP" in out, out[-200:])
    check("alice (10.0.0.1) unaffected", "HTTP 200" in lab.client("h1", "web /news"))
    lab.policy_edit(lambda d: d["rules"].remove(next(r for r in d["rules"] if r["id"] == "R-IP")))
    time.sleep(2.5)
    check("rule removed -> bob allowed again", "HTTP 200" in lab.client("h2", "web /news"))


def s4_quarantine(lab):
    if lab.mode != "sdn":
        print("  (skipped: needs the SDN controller)")
        return
    before = lab.flows("s1")
    t0 = time.time()
    res = lab.loadgen("h3", "flood --duration 6 --workers 2")
    check("flood generated denied requests", res.get("denied", 0) >= lab.threshold, str(res))
    time.sleep(1)
    st = controller_cmd("STATUS")
    check("controller quarantined 10.0.0.3", IPS["h3"] in st.get("blocked", {}), json.dumps(st))
    quarantine = [l for l in lab.flows("s1").splitlines() if "priority=300" in l and IPS["h3"] in l]
    check("DROP flow (priority 300, nw_src=10.0.0.3) installed on s1", bool(quarantine), "\n".join(quarantine))
    ev = [e for e in lab.sdn_events() if e["event"] == "block" and e["ip"] == IPS["h3"]]
    if ev:
        print(f"      reaction: block installed {ev[0]['ts'] - t0:.2f}s after the flood began ({ev[0]['reason']})")
    check("h3 can no longer reach the proxy at all", not lab.reachable("h3", IPS["proxy"], 8443, timeout=2))
    check("alice still works", "HTTP 200" in lab.client("h1", "web /news"))
    controller_cmd(f"UNBLOCK {IPS['h3']}")
    time.sleep(1)
    check("after UNBLOCK h3 is served again", "HTTP 200" in lab.client("h3", "web /news"))


def s5_service_failure(lab):
    lab.svc_proc.terminate()
    lab.svc_proc.wait()
    time.sleep(0.5)
    out = lab.client("h1", "web /news")
    check("back end down -> proxy answers 502 (no hang)", "502" in out, out[-200:])
    lab.svc_proc = lab._popen(lab.net["svc"], ["services.py", "--host", IPS["svc"]], f"svc_{lab.mode}_2.log")
    lab._wait(lambda: lab.reachable("proxy", IPS["svc"], 9001), 15, "services restart")
    check("back end restored -> 200 again", "HTTP 200" in lab.client("h1", "web /news"))


def s6_loss(lab):
    lab.set_client_link("h1", delay="10ms", loss=5)
    try:
        r = lab.loadgen("h1", "latency --user {user} -n 15 --timeout 20")
        check("5 % loss on h1's link: all requests still complete", r["ok"] == 15, str(r))
        print(f"      p50 {r['p50_ms']:.0f} ms, p95 {r['p95_ms']:.0f} ms")
    finally:
        lab.set_client_link("h1")


SCENARIOS = {1: s1_normal, 2: s2_bypass, 3: s3_source_ip, 4: s4_quarantine, 5: s5_service_failure, 6: s6_loss}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["sdn", "static"], default="sdn")
    ap.add_argument("--only", type=int, nargs="*")
    ap.add_argument("--no-cli", action="store_true")
    ap.add_argument("--dashboard", action="store_true", help="also run the web dashboard (app.py) on the proxy host, http://127.0.0.1:5000")
    ap.add_argument("--no-scenarios", action="store_true", help="skip the scripted scenarios (just bring the network up)")
    a = ap.parse_args()
    with Lab(mode=a.mode, threshold=5, window=10, block_seconds=60) as lab:
        print(f"\nWebSentry on Mininet - controller mode: {a.mode}\n")
        for n, fn in SCENARIOS.items():
            if a.no_scenarios or (a.only and n not in a.only):
                continue
            print(f"Scenario {n}: {fn.__doc__ or fn.__name__}")
            try:
                fn(lab)
            except Exception as e:                               # a crashed scenario is a failed scenario
                check(f"scenario {n} ran without error", False, repr(e))
        failed = [r for r in RESULTS if not r["pass"]]
        print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
        (OUT / f"demo_{a.mode}.json").write_text(json.dumps(RESULTS, indent=2))
        if a.dashboard:
            lab.start_dashboard()
            print("\nDashboard running on the proxy host. In the VM open http://127.0.0.1:5000 (admin / admin-demo),\n"
                  "from your Mac:  ssh -L 5000:127.0.0.1:5000 <vm-user>@<vm-ip>   then http://127.0.0.1:5000\n"
                  "Open 'Network (SDN)' in the sidebar, then run the flood from the CLI below and watch it update.")
        if not a.no_cli:
            from mininet.cli import CLI
            from mininet.log import setLogLevel
            setLogLevel("output")                          # the CLI prints command output at this level
            print("\nMininet CLI - try:  h2 python3 client.py --user bob --proxy 10.0.0.10:8443 web /news\n"
                  "                    sh ovs-ofctl -O OpenFlow13 dump-flows s1\n")
            CLI(lab.net)
        sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
