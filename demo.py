"""
demo.py -- a scripted walk-through of every feature, with pass/fail checks.

    python demo.py

Starts the simulated services, the proxy and the admin console on free ports
(so it never clashes with a copy you run by hand), uses the shipped
config/policy.json, and narrates each scenario. The transcript is also
written to logs/demo_transcript.txt and the proxy's access log to
logs/demo/access.log.
"""
from __future__ import annotations

import io
import sys
import time
from datetime import datetime

from netproxy.clientlib import ProxyRefused
from netproxy.config import ROOT
from netproxy.policy import Context
from netproxy.testbed import Stack

OUT = io.StringIO()
RESULTS = []


def say(text: str = ""):
    print(text)
    OUT.write(text + "\n")


def section(title: str):
    say()
    say(f"--- {title} " + "-" * max(4, 74 - len(title)))


def check(ok: bool, label: str):
    RESULTS.append((ok, label))
    say(f"  [{'PASS' if ok else 'FAIL'}] {label}")


def rq(who: str, what: str, status: int, note: str) -> str:
    return f"{who:<5} {what:<28} -> {status} {note}"


def try_connect(client, service):
    try:
        return client.connect(service), None
    except ProxyRefused as e:
        return None, e


def connect_line(who, client, service, expect_rule, expect_ok):
    t, err = try_connect(client, service)
    if t:
        t.close()
        got = f"200 allowed by {t.rule}"
        check(expect_ok and t.rule == expect_rule, f"{who:<22} CONNECT {service:<13} -> {got}")
    else:
        got = f"{err.status} denied by {err.rule}: {err.detail}"
        check(not expect_ok and err.rule == expect_rule, f"{who:<22} CONNECT {service:<13} -> {got}")


def main():
    workdir = ROOT / "logs" / "demo"
    st = Stack(workdir=str(workdir)).start()
    say("=" * 80)
    say(" netproxy demo - Proxy and Content Filtering System")
    say(f" {datetime.now():%Y-%m-%d %H:%M:%S}")
    say("=" * 80)
    say("services : " + ", ".join(f"{n}:{s.port}" for n, s in st.services.items()))
    say(f"proxy    : TLS 127.0.0.1:{st.tls_port}   plain 127.0.0.1:{st.plain_port}   "
        f"admin 127.0.0.1:{st.proxy.ports['admin']}")
    p = st.store.policy
    say(f"policy   : '{p.name}' v{p.version}, {len(p.rules)} rules, {len(p.filters)} filters, "
        f"default {p.default_action}")
    alice, bob, carol, anon = st.client("alice"), st.client("bob"), st.client("carol"), st.client()

    try:
        # ------------------------------------------------------------------ 1
        section("1. TLS, and identity from the client certificate")
        with bob.connect("web") as t:
            version, cipher = t.sock.version(), t.sock.cipher()[0]
            say(f"  bob's tunnel: {version}, cipher {cipher}, proxy says user={t.user}, rule={t.rule}")
            page = t.get("/").text
            check(version in ("TLSv1.3", "TLSv1.2"), f"connection encrypted with {version}")
            check(t.user == "bob", "proxy identified the client as 'bob' from its certificate (CN)")
            check("seen as user: <b>bob</b>" in page, "identity forwarded to the service (X-Authenticated-User)")
        with anon.connect("web") as t:
            check(t.user == "anonymous", "a client without a certificate is 'anonymous'")

        # ------------------------------------------------------------------ 2
        section("2. Connection-level access rules (first match wins)")
        connect_line("alice (staff)", alice, "files", "R01", True)
        connect_line("bob (student)", bob, "chat", "R06", True)
        connect_line("anonymous", anon, "web", "R07", True)
        connect_line("anonymous", anon, "files", "R03", False)
        connect_line("anonymous", anon, "echo-inspect", "DEFAULT", False)
        connect_line("bob", bob, "smtp.gmail.com:25", "UNKNOWN_SERVICE", False)

        # ------------------------------------------------------------------ 3
        section("3. Request-level rules inside an HTTP session")
        with bob.connect("web") as t:
            for path, rule, status in (("/news", None, 200), ("/admin/panel", "R04", 403),
                                       ("/x/../admin/panel", "R04", 403), ("/%61dmin/panel", "R04", 403)):
                r = t.get(path)
                note = f"blocked by {r.header('x-proxy-rule')}" if r.status != 200 else "allowed"
                check(r.status == status and (rule is None or r.header("x-proxy-rule") == rule),
                      rq("bob", f"GET {path}", r.status, note))
            now = datetime.now()
            expect_block = not st.store.policy.evaluate(
                Context("bob", "127.0.0.1", "web", "GET", "/social/feed"), "request", now).allowed
            r = t.get("/social/feed")
            when = f"({now:%a %H:%M} is {'inside' if expect_block else 'outside'} Mon-Fri 09:00-17:00)"
            check((r.status == 403) == expect_block, rq("bob", "GET /social/feed", r.status, when))
        with alice.connect("web") as t:
            r = t.get("/admin/panel")
            check(r.status == 200, rq("alice", "GET /admin/panel", r.status, "allowed (staff rule R01 matches first)"))

        # ------------------------------------------------------------------ 4
        section("4. HTTP content filtering (bodies, URLs, content types)")
        with bob.connect("web") as t:
            r = t.get("/lucky")
            check(r.header("x-proxy-rule") == "F01", rq("bob", "GET /lucky", r.status, "keyword in the page, F01"))
            r = t.get("/search?q=online+casino")
            check(r.header("x-proxy-rule") == "F01", rq("bob", "GET /search?q=online+casino", r.status, "keyword in the URL, F01"))
            r = t.get("/billing")
            line = next((ln for ln in r.text.split("<p>") if "Card on file" in ln), "").split("</p>")[0]
            check(r.status == 200 and "[CARD REDACTED]" in r.text and "4111" not in r.text,
                  rq("bob", "GET /billing", r.status, f"{r.header('x-proxy-filtered')}: '{line}'"))
            r = t.get("/internal/report")
            check(r.header("x-proxy-rule") == "F03", rq("bob", "GET /internal/report", r.status, "confidential, F03"))
            r = t.get("/downloads/tool.exe")
            check(r.header("x-proxy-rule") == "F04", rq("bob", "GET /downloads/tool.exe", r.status, "executable content type, F04"))
            r = t.request("POST", "/echo", b"place my betting slip")
            check(r.header("x-proxy-rule") == "F01", rq("bob", "POST /echo  (body: betting)", r.status, "keyword in the request body, F01"))
        with alice.connect("web") as t:
            r = t.get("/internal/report")
            check(r.status == 200 and "[CARD REDACTED]" in r.text,
                  rq("alice", "GET /internal/report", r.status, "staff exempt from F03; card still masked by F02"))

        # ------------------------------------------------------------------ 5
        section("5. Stream filtering on line protocols (TCP has no message boundaries)")
        with bob.connect("echo-inspect") as t:
            t.send(b"pay with 4111 11")
            time.sleep(0.05)                                     # second TCP segment arrives later
            t.send(b"11 1111 1111 please\n")
            got = t.recv_until(b"please\n")
            say("  sent in 2 segments: 'pay with 4111 11' + '11 1111 1111 please'")
            check(got == b"pay with [CARD REDACTED] please\n", f"echo came back as {got.decode().strip()!r}")
        with bob.connect("chat") as tb, carol.connect("chat") as tc:
            tb.recv_until(b"/quit\n")
            tc.recv_until(b"/quit\n")
            tb.send_line("/nick bob")
            tc.send_line("/nick carol")
            time.sleep(0.2)
            tc.recv_for(0.2)
            tb.send_line("carol you absolute idiot")
            seen = tc.recv_until(b"idiot", 1).decode()
            seen = seen if "***" in seen else tc.recv_until(b"***\n").decode()
            check("idiot" not in seen and "***" in seen, f"carol's chat window shows: {seen.strip().splitlines()[-1]!r}")
        with bob.connect("files") as t:
            t.recv_until(b"QUIT\n")
            t.send_line("GET memo.txt")
            out = t.recv_until(b"***\n").decode()
            say("  bob> GET memo.txt")
            for ln in out.strip().splitlines():
                say(f"       | {ln}")
            check("Room 204" not in out and t.is_closed(), "session cut at the CONFIDENTIAL line; later lines never sent")

        # ------------------------------------------------------------------ 6
        section("6. Dynamic policy: admin console blocks a user mid-session")
        with st.admin() as admin, bob.connect("chat") as t:
            t.recv_until(b"/quit\n")
            say("  bob is chatting...   admin> BLOCK user bob")
            start = time.monotonic()
            ok, msg = admin.command("BLOCK user bob")
            say(f"  console: {msg}")
            closed = t.is_closed(2)
            ms = (time.monotonic() - start) * 1000
            check(ok and closed, f"bob's open chat session terminated {ms:.0f} ms after the command")
            _, err = try_connect(bob, "web")
            rule = msg.split()[3]
            check(err is not None and err.rule == rule, f"bob reconnects -> {err.status if err else 200} denied by {rule}")
            ok, msg = admin.command(f"UNBLOCK {rule}")
            say(f"  admin> UNBLOCK {rule}   console: {msg}")
            t2, err = try_connect(bob, "web")
            check(t2 is not None, "bob can connect again")
            if t2:
                t2.close()

        # ------------------------------------------------------------------ 7
        section("7. Dynamic policy: edit the policy file while the proxy runs")
        live = anon.connect("echo")
        live.send(b"still here\n")
        live.recv_until(b"\n")
        doc = st.read_policy()
        doc["rules"].insert(0, {"id": "MAINT", "action": "deny", "services": ["echo"],
                                "reason": "echo is down for maintenance"})
        say(f"  inserting rule MAINT (deny echo) into {st.policy_path}")
        v_before = st.store.policy.version
        start = time.monotonic()
        st.write_policy(doc)
        closed = live.is_closed(3)
        ms = (time.monotonic() - start) * 1000
        check(closed, f"policy v{v_before} -> v{st.store.policy.version}: open echo session closed after {ms:.0f} ms")
        _, err = try_connect(anon, "echo")
        check(err is not None and err.rule == "MAINT", f"new echo connection -> {err.status if err else 200} "
                                                        f"denied by {err.rule if err else '-'}")
        with open(st.policy_path, "w", encoding="utf-8") as fh:
            fh.write('{"rules": [ oops')
        time.sleep(0.6)
        check(st.store.policy.version == v_before + 1 and "invalid JSON" in st.store.last_error,
              "a broken policy file is rejected; the last good policy stays active")
        doc["rules"].pop(0)
        st.write_policy(doc)
        time.sleep(0.6)
        t, _ = try_connect(anon, "echo")
        check(t is not None, "rule removed again by editing the file")
        if t:
            t.close()

        # ------------------------------------------------------------------ 8
        section("8. Per-identity rate limiting")
        with st.admin() as admin:
            admin.command("LIMIT window_seconds 3")
            admin.command("LIMIT max_new_conns_per_window 5")
            say("  admin> LIMIT window_seconds 3 ; LIMIT max_new_conns_per_window 5")
            time.sleep(3.1)                                     # start with an empty window
            guest = st.client()
            results = []
            for _ in range(8):
                t, err = try_connect(guest, "web")
                results.append("200" if t else str(err.status))
                if t:
                    t.close()
            say(f"  anonymous opens 8 connections at once: {' '.join(results)}")
            check(results == ["200"] * 5 + ["429"] * 3, "the 6th connection inside the window gets 429 Too Many Requests")
            admin.command("LIMIT window_seconds 10")
            admin.command("LIMIT max_new_conns_per_window 30")

        # ------------------------------------------------------------------ 9
        section("9. Admin console: STATUS and STATS")
        with st.admin() as admin:
            for cmd in ("STATUS", "STATS"):
                say(f"  admin> {cmd}")
                for ln in admin.command(cmd)[1].splitlines():
                    say(f"    {ln}")
    finally:
        st.stop()

    passed = sum(ok for ok, _ in RESULTS)
    say()
    say("=" * 80)
    say(f" {passed}/{len(RESULTS)} checks passed.   access log: {workdir / 'access.log'}")
    say("=" * 80)
    (ROOT / "logs").mkdir(exist_ok=True)
    with open(ROOT / "logs" / "demo_transcript.txt", "w", encoding="utf-8") as fh:
        fh.write(OUT.getvalue())
    sys.exit(0 if passed == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
