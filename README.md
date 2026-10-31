# WebSentry

> **Dashboard, real-website proxy and block page:** see [`README_ACCESSWINDOW.md`](README_ACCESSWINDOW.md) for setup and run instructions.

**Computer Networks (UE25CS243A) - socket programming mini project**

> *Develop a TCP proxy through which clients access simulated services. The system should dynamically
> allow or block traffic according to configurable policies.*

`netproxy` is a TLS-terminating TCP proxy written directly on the socket API (Python standard library
only). Clients open a tunnel to a named service with an HTTP `CONNECT` request; the proxy identifies
the client from its TLS certificate, checks an ordered rule list, connects to the service and relays
the traffic, inspecting it on the way. Rules and filters live in a JSON policy that can be changed
while the proxy runs - from an admin console or by editing the file - and open connections that the
new policy forbids are cut within about 100 ms.

| Requirement | Where it is met |
|---|---|
| TCP proxy | `netproxy/server.py` - `socket`, `bind`, `listen`, `accept`, `connect`, non-blocking relay with `select()` |
| Simulated services | `services.py` - HTTP website, chat room, echo, file server, bulk-transfer service |
| Allow / block by policy | `config/policy.json` + `netproxy/policy.py` - identity, group, source IP/CIDR, service, URL path, method, time-of-day rules; first match wins |
| Content filtering | `netproxy/filters.py` - keyword / regex / MIME filters that block, redact or log, on HTTP bodies, URLs and raw line streams |
| *Dynamically* | hot reload of the policy file, admin console (`BLOCK user bob`, `RULE ADD ...`), live re-check of open sessions |
| Configurable | two JSON files, validated on load; a bad edit is rejected and the last good policy stays |
| Secure communication | TLS 1.2+/1.3 between clients and proxy, optional mutual TLS (client certificates = identities), TLS admin console with a token |
| Multiple concurrent clients | one thread per connection, per-identity connection caps and rate limits |
| Performance evaluation | `benchmark.py` - latency, throughput, concurrency, policy cost, reaction time; charts + report |

---

## 1. Architecture

```
                         TLS (or plain TCP for demos)                plain TCP (loopback)
 +-----------+   CONNECT web HTTP/1.1    +-------------------------+   GET /news HTTP/1.1   +-------------+
 |  client   | ------------------------> |         netproxy         | ---------------------> | web   :9001 |
 |  alice    |   200 / 403 / 429 / 502   |                          |                        | chat  :9002 |
 |  (cert)   | <------------------------ |  1 accept + TLS          | <--------------------- | echo  :9003 |
 +-----------+                           |  2 identity = cert CN    |                        | files :9004 |
 +-----------+                           |  3 limits (429)          |                        | bulk  :9005 |
 |  bob      | ------------------------> |  4 connect-stage rules   |                        +-------------+
 +-----------+                           |  5 relay + inspection:   |                          simulated
 +-----------+   GET http://web/ HTTP/1.1|     none | line | http   |                          services
 |  browser  | ------------------------> |  6 access log            |
 +-----------+   (forward-proxy mode)    +-------------------------+
                                              ^           |  watches
                         admin console (TLS)  |           v
 +-----------+  BLOCK user bob, RULE ADD ...  |   config/policy.json  (hot reload)
 | adminctl  | -------------------------------+
 +-----------+
```

**Life of a connection** (`ClientSession.run` in `netproxy/server.py`):

1. `accept()` - new TCP connection; `TCP_NODELAY` on so small interactive writes are not delayed by Nagle.
2. TLS handshake - the proxy shows its certificate; if the client sends one signed by the project CA, its
   Common Name becomes the client's **identity** (`alice`, `bob`, ...). No certificate = `anonymous`.
3. Admission - per-identity limits: at most *N* open connections and *M* new connections per window (`429`).
4. Request head - `CONNECT <service> HTTP/1.1` (tunnel mode) or `GET http://<service>/path HTTP/1.1`
   (forward-proxy mode, what browsers and `curl -x` send).
5. Connect-stage policy check - `403 Forbidden` with the rule id and reason, or `200 Connection Established`.
6. `connect()` to the service, then relay according to the service's `inspect` mode:
   * `none` - byte-for-byte relay, the fast path;
   * `line` - the byte stream is re-assembled into lines and every line is filtered;
   * `http` - every request and response is parsed: per-path rules, URL/body/MIME filters, HTML block pages.
7. Close - one JSON line per event in `logs/access.log` (decision, rule, bytes, duration, reason).

All I/O after the handshake is non-blocking and multiplexed with `select()` with a 100 ms tick, so a session
reacts to cancellation (admin `KILL`, a policy change) even while it is idle.

### Project layout

```
proxy.py            start the proxy                       netproxy/server.py    accept loop, sessions, relay, HTTP inspection
services.py         start the simulated services          netproxy/policy.py    policy model, validation, evaluation, hot reload
client.py           client for every service              netproxy/filters.py   keyword/regex/MIME filters, stream reassembly
adminctl.py         admin console client                  netproxy/httpmsg.py   strict HTTP/1.1 parsing and framing
gen_certs.py        CA + proxy + client certificates      netproxy/control.py   admin console server
demo.py             scripted walk-through, 34 checks      netproxy/registry.py  live connections, limits, counters, access log
benchmark.py        performance evaluation                netproxy/tlsutil.py   TLS contexts, identity from certificates
config/proxy.json   listeners, TLS, timeouts              netproxy/clientlib.py client side (used by the scripts and tests)
config/policy.json  services, groups, rules, filters      netproxy/testbed.py   whole system in one process on free ports
certs/              CA, proxy and client certificates      tests/                unit + end-to-end tests
```

---

## 2. Running it

Requirements: **Python 3.9 or newer**. Nothing else is needed - certificates are already in `certs/`.
Optional: `pip install cryptography` (to regenerate certificates) and `pip install matplotlib` (benchmark charts).
On Windows use `python`; on macOS/Linux it may be `python3`.

Open four terminals in the project folder:

```powershell
# terminal 1 - the simulated services (127.0.0.1:9001-9005)
python services.py

# terminal 2 - the proxy (TLS :8443, admin console :9443; --plain-port adds an unencrypted listener)
python proxy.py --plain-port 8080

# terminal 3 - clients
python client.py --user bob web /news /admin/panel /billing
python client.py --user bob chat

# terminal 4 - the admin console
python adminctl.py
```

Windows may ask to allow Python through the firewall the first time the proxy listens - allow it on
private networks.

### Things to try

| Command | What happens |
|---|---|
| `python client.py web /news` | anonymous, allowed by **R07** |
| `python client.py --user bob web /admin/panel` | page refused by **R04** (admin area is staff-only) |
| `python client.py --user alice web /admin/panel` | allowed - **R01** (staff) matches first |
| `python client.py --user bob web /x/../admin/panel` | still **R04**: paths are normalised before matching |
| `python client.py --user bob web /social/feed` | blocked by **R05** Mon-Fri 09:00-17:00, allowed otherwise |
| `python client.py --user bob web /billing` | card numbers replaced by `[CARD REDACTED]` (**F02**) |
| `python client.py --user bob web /lucky "/search?q=casino"` | gambling keywords in a page or URL - **F01** |
| `python client.py --user bob web /internal/report` | confidential page, **F03**; `--user alice` gets it (staff exempt) |
| `python client.py --user bob web /downloads/tool.exe` | executable content type, **F04** |
| `python client.py files` | `403` - files needs a certificate (**R03**) |
| `python client.py --user carol files --send LIST --send "GET memo.txt"` | session cut at the line containing CONFIDENTIAL |
| `python client.py --user bob chat` in two terminals (bob, carol) | profanity redacted (**F05**), gambling talk ends the session (**F01**) |
| `python client.py echo --send hello` | pure byte tunnel, no inspection |
| `python client.py --forward http://web/billing` | forward-proxy mode, like a browser |

Dynamic changes - while bob is in the chat:

```
netproxy> BLOCK user bob          -> bob's chat session is cut immediately, new connections get 403 DYN-1
netproxy> CONNS                   -> open connections with user, service, bytes, age
netproxy> UNBLOCK DYN-1
netproxy> FILTER ADD {"type":"keyword","patterns":["exam"],"action":"block","services":["chat"]}
netproxy> DEFAULT allow
netproxy> SAVE                    -> write the running policy back to config/policy.json
```

Or edit `config/policy.json` in any editor and save: the proxy reloads it within a second (a file with a
mistake is rejected with a message in the proxy window, and the previous policy stays active).

> In PowerShell, JSON arguments on the command line need extra quoting - type JSON commands in the
> interactive console (`python adminctl.py`) instead.

### Automated demo, tests and benchmark

```powershell
python demo.py                          # every feature, narrated, 34 pass/fail checks; transcript in logs/
python -m unittest discover -s tests -v # 57 unit + end-to-end tests
python benchmark.py --quick             # ~1 min; full run without --quick. Report in bench/summary.md
```

`demo.py`, the tests and the benchmark start their own copy of the system on free ports, so they work
even while you have the proxy running in another terminal.

### Standard tools work too

The handshake is ordinary HTTP `CONNECT`, so standard clients interoperate:

```bash
# curl through the TLS listener, as bob (mutual TLS), forward-proxy mode
curl -x https://127.0.0.1:8443 --proxy-cacert certs/ca.crt \
     --proxy-cert certs/clients/bob.crt --proxy-key certs/clients/bob.key http://web/admin/panel
# curl through a CONNECT tunnel (-p) as alice
curl -p -x https://127.0.0.1:8443 --proxy-cacert certs/ca.crt \
     --proxy-cert certs/clients/alice.crt --proxy-key certs/clients/alice.key http://web/admin/panel
# plain listener
curl -x http://127.0.0.1:8080 http://web.sim/billing
```

A **browser** can use the plain listener as its HTTP proxy (Firefox: Settings > Network Settings > Manual
proxy configuration, HTTP proxy `127.0.0.1`, port `8080`, leave "Also use this proxy for HTTPS" unticked).
Then open `http://web/` - pages and the proxy's block pages render as HTML. Use a separate Firefox
profile, since every other site will be refused as an unregistered service. (The curl HTTPS-proxy options need curl 7.52+ built with OpenSSL; the
Windows built-in curl may not support them - the Python client always does.)

### Across three laptops

On the proxy machine run `python services.py` and `python proxy.py` (the proxy listens on `0.0.0.0`; the
services stay on `127.0.0.1`, so the proxy is the only way in). Copy the project folder to the other
laptops and run `python client.py --proxy <proxy-ip>:8443 --user bob web /news`. The client checks the
proxy certificate against the name `netproxy`, which is always in the certificate, so it works with any
IP address without regenerating certificates.

### Certificates and identities

`certs/` ships with a private CA, the proxy certificate and client certificates for `alice` (group
`staff`) and `bob`, `carol` (group `students`). A client certificate's Common Name *is* the identity the
rules see.

```powershell
python gen_certs.py --add-user dave          # new identity, signed by the existing CA
python adminctl.py GROUP ADD students dave   # or add "dave" to a group in policy.json
python client.py --user dave web /news
python gen_certs.py                          # start over: new CA + all certificates
```

After a full regeneration, copy the whole `certs/` folder to every machine that runs a client - all of
them must trust the same CA. `ca.key` can issue identities, so in a real deployment it would never leave
the administrator's machine.

### Watching it in Wireshark

Capture on the loopback interface (Windows: install Npcap with loopback support, choose
"Adapter for loopback traffic capture"):

* `tcp.port == 8443` - client to proxy: the TLS handshake (Client Hello with SNI `netproxy`, the
  certificate exchange) and then only *Application Data* records - nothing readable.
* `tcp.port == 8080` - the same request through the plain listener: the CONNECT line, the HTTP request and
  the page are all readable. That contrast is why the proxy uses TLS.
* `tcp.port == 9001` - proxy to service: plaintext. For `/billing` the service sends the real card numbers
  here, while the client (see the 8080 capture) receives `[CARD REDACTED]` - the filtering happens in the
  proxy. A request blocked by a path rule never appears on this port at all.
* Follow a TCP stream to see the three-way handshake, keep-alive reuse (several requests, one connection)
  and `FIN` / half-close at the end of an echo transfer.

---

## 3. The policy file

`config/policy.json` has five sections. Keys starting with `_` are comments. Unknown keys are errors (so a
typo such as `servcies` is reported, not silently ignored).

### services

```json
"web":  {"host": "127.0.0.1", "port": 9001, "inspect": "http", "aliases": ["web.sim"]}
```

Only registered services can be reached (an unknown name gets `403 UNKNOWN_SERVICE`, so the proxy is never
an open relay). `inspect` is `http`, `line` or `none`. The same back end can be registered twice with
different inspection (`echo` and `echo-inspect`).

### groups

```json
"groups": {"staff": ["alice"], "students": ["bob", "carol"]}
```

### rules - ordered, first match wins

| Field | Meaning | Example |
|---|---|---|
| `id` | name shown in logs and 403 responses (auto-numbered if missing) | `"R04"` |
| `action` | `allow` or `deny` | `"deny"` |
| `users` | identities, `@group`, `anonymous`, `*`; omitted = everyone | `["@students", "dave"]` |
| `except_users` | exclusions | `["@staff"]` |
| `src` | client IP addresses / CIDR blocks (IPv4 or IPv6) | `["10.66.0.0/16"]` |
| `services` | service names; omitted or `*` = all | `["web"]` |
| `paths` | URL path globs, HTTP services only | `["/admin", "/admin/*"]` |
| `methods` | HTTP methods | `["POST", "PUT"]` |
| `schedule` | active window; can cross midnight | `{"days": "mon-fri", "from": "09:00", "to": "17:00"}` |
| `reason` | text shown to the client | |
| `enabled` | `false` keeps the rule but skips it | |

`default_action` (`allow` or `deny`) applies when no rule matches. The shipped policy is default-deny.

**Two-stage evaluation.** At `CONNECT` time the path is not known yet, so rules with `paths`/`methods`
are skipped if they deny (they are enforced on every request later) and admit the connection
provisionally if they allow. Inside an `http` session every request is evaluated again with the full
context. For `line`/`none` services path rules never apply.

**Path normalisation.** Before matching, `/x/../admin`, `//admin`, `/%61dmin` all become `/admin`, and the
normalised path is what the proxy forwards - so what was checked is exactly what the service serves.

### content_filters

| Field | Meaning |
|---|---|
| `type` | `keyword` (literal words), `regex`, or `mime` (response Content-Type, e.g. `application/x-msdownload`, wildcards allowed) |
| `patterns` | list of words / expressions / types |
| `action` | `block` (403 page for HTTP, session ends for line services), `redact` (replace the match), `log` (record only) |
| `direction` | `request`, `response` or `both` |
| `services`, `users`, `except_users` | scope, as for rules |
| `replacement` | text for `redact` (default `[REDACTED]`) |
| `whole_word`, `case_sensitive` | keyword matching options (default: substring, case-insensitive) |

For HTTP the proxy inspects the URL (request filters), the request body and the complete response body,
then recomputes `Content-Length`. It removes `Accept-Encoding` from requests so services answer
uncompressed - compressed bodies could not be inspected. Responses that were changed carry an
`X-Proxy-Filtered: F02:redact` header.

For line services the proxy **re-assembles the TCP byte stream into lines** before filtering: a keyword
split across two segments (`"confi"` + `"dential\n"`) is still caught. A partial line (a prompt without a
newline) is flushed after 150 ms of silence, except for a trailing fragment that could be the start of a
blocked keyword. A block ends the session at the offending line; earlier lines have already been delivered.

### limits

```json
"limits": {"max_conns_per_user": 10, "max_new_conns_per_window": 30, "window_seconds": 10}
```

Counted per identity (anonymous clients per source IP). `0` = unlimited. Over the limit: `429 Too Many Requests`.

---

## 4. Protocol reference

**Tunnel request** (client to proxy, after TLS):

```
CONNECT web HTTP/1.1
Host: web

HTTP/1.1 200 Connection Established          HTTP/1.1 403 Forbidden
X-Proxy-Rule: R06                            X-Proxy-Rule: R03
X-Proxy-User: bob                            X-Proxy-Reason: Chat and files need a client certificate (sign in)
X-Proxy-Inspect: http                        Content-Type: text/plain; charset=utf-8
                                             Content-Length: ...
(from here on: the service's own protocol)   Connection: close
```

| Status | When |
|---|---|
| `200 Connection Established` | allowed; the tunnel is open |
| `400 Bad Request` | malformed request line or headers, ambiguous body framing, nested CONNECT |
| `403 Forbidden` | a rule or filter denied it (`X-Proxy-Rule` names it), or an unregistered service |
| `429 Too Many Requests` | per-identity limit (`X-Proxy-Rule: LIMIT`) |
| `431` / `413` | header block / body larger than the configured limit |
| `502 Bad Gateway` | the service is down or sent an invalid response |

Requests forwarded to HTTP services carry `X-Forwarded-For`, `X-Authenticated-User` and `Via: 1.1 netproxy`.

**Admin console** (TLS, `127.0.0.1:9443`): line-based. First command `AUTH <token>` (token in
`config/proxy.json`). Every reply begins with `OK` or `ERR` and ends with a line containing `.`.
`HELP` lists the commands: `STATUS`, `CONNS`, `KILL`, `RULES`, `FILTERS`, `SERVICES`, `SHOW`, `BLOCK`,
`UNBLOCK`, `RULE ADD|INSERT|DEL|ENABLE|DISABLE`, `FILTER ADD|DEL|ENABLE|DISABLE`, `GROUP ADD|DEL`,
`DEFAULT`, `LIMIT`, `RELOAD`, `SAVE`, `STATS`, `LOG`.

**Access log** (`logs/access.log`) - one JSON object per line, events `connect`, `request`, `filter`,
`close`, `policy`, `admin`:

```json
{"ts": "2026-10-12T10:41:07.311", "event": "request", "conn": 12, "user": "bob", "service": "web",
 "method": "GET", "path": "/admin/panel", "status": 403, "decision": "deny", "rule": "R04", "filters": []}
```

---

## 5. Design decisions

* **TLS termination at the proxy.** Content can only be inspected in plaintext, so the client-proxy leg
  is encrypted and the proxy-service leg is plaintext on loopback (the services are not reachable from
  outside). This is how corporate filtering proxies work, and it is why the client must trust the proxy's CA.
* **Identity from certificates, not claims.** A client cannot type its way into the staff group - the
  identity is the CN of a certificate signed by the CA, verified during the handshake.
* **CONNECT as the handshake.** An existing standard (RFC 9110 §9.3.6) instead of an invented one, so curl
  and browsers work unchanged and the status codes mean what HTTP says they mean.
* **First-match ordered rules** like firewall ACLs: predictable, easy to explain (`X-Proxy-Rule` tells the
  user which rule fired), and an emergency `BLOCK` simply goes on top.
* **Immutable policy objects, atomic swap.** Every change builds a new validated `Policy` (version + 1)
  and swaps one reference; a session never sees half an update. Invalid changes are rejected and the old
  policy stays - the proxy never runs with a broken policy.
* **Re-checking open sessions.** On every swap all live connections are evaluated against the new policy and
  the ones now denied are cancelled. Without this, "blocking" would only affect future connections.
* **Thread per connection + non-blocking `select()` relay.** Simple to reason about, and one thread owns
  both sockets of a session, so a TLS socket is never read and written by two threads at once (which
  OpenSSL does not allow). The 100 ms `select()` timeout bounds how long a cancelled session can linger.
* **Strict HTTP parsing.** Requests with both `Content-Length` and `Transfer-Encoding`, conflicting lengths
  or folded headers are refused - those ambiguities are what request-smuggling attacks use to get a
  request past a filter.
* **Defaults that fail closed.** Default-deny policy, only registered services reachable, admin console on
  localhost with TLS and a token, limits on header size, body size, idle time and connection count.

### Limitations and possible extensions

* CPython's global interpreter lock means one process uses one core for Python code; throughput levels
  off around a few thousand HTTP requests/s (see `bench/summary.md`). A multi-process or `asyncio`
  design would scale further.
* The proxy-to-service leg is plaintext; TLS to the services (re-encryption) would be needed if they ran on
  other machines.
* Rule evaluation is a linear scan; indexing rules by service would help with thousands of rules.
* HTTP inspection buffers whole bodies (bounded by `max_body_bytes`); streaming inspection of very large
  downloads, chunked request bodies with trailers and `Upgrade`/WebSocket are not handled.
* The policy file is polled once a second (portable across Windows and Linux) rather than watched with
  OS file-change notifications.

---

## 6. Suggested split for a team of three

| Member | Owns | Files |
|---|---|---|
| 1 | proxy core: sockets, TLS, CONNECT, relay, HTTP inspection | `server.py`, `httpmsg.py`, `tlsutil.py`, `gen_certs.py` |
| 2 | policy engine and dynamic control: rules, filters, hot reload, admin console | `policy.py`, `filters.py`, `control.py`, `adminctl.py`, `config/` |
| 3 | services, clients and evaluation: simulated services, client, tests, demo, benchmark | `services.py`, `client.py`, `clientlib.py`, `tests/`, `demo.py`, `benchmark.py` |

## 7. Networking concepts you can point to in the code

| Concept | Where |
|---|---|
| Socket API: `socket/bind/listen/accept/connect/send/recv/shutdown/close` | `services.py` `TCPService`, `server.py` `ProxyServer._listen`, `_open_backend` |
| TCP is a byte stream - message framing | `filters.py` `StreamInspector`; `services.py` `LineReader`; HTTP `Content-Length` vs chunked in `httpmsg.read_body` |
| Half-close (`FIN` in one direction) | `server.py` `_relay` (client EOF -> `shutdown(SHUT_WR)` toward the service) |
| Nagle's algorithm / `TCP_NODELAY` | `server.py` accept loop, `_open_backend` |
| I/O multiplexing with `select()` | `server.py` `Channel`, `_relay` |
| Persistent connections (HTTP keep-alive) | `server.py` `_http_session`, `_exchange_with_backend` |
| TLS handshake, certificates, PKI, SNI, mutual authentication | `tlsutil.py`, `gen_certs.py`, `server.py` `_handshake` |
| Application-layer proxying (HTTP `CONNECT`, absolute-form requests, hop-by-hop headers, `Via`) | `server.py`, `httpmsg.py` |
| Access control by IP / CIDR | `policy.py` `Rule.matches_base` |
| Flow/abuse control: rate limiting, connection caps, timeouts | `registry.py` `admit`, `config.py` |
