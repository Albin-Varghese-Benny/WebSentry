# AccessWindow — role-separated website & service access control

AccessWindow extends the `netproxy` project with a web dashboard, a real-website proxy and a block page.

- **Dashboard** (`app.py`, port 5000) — administrator and requester roles. The administrator manages rules and approves requests; a requester can ask for a service or a blocked website for a few minutes. Approved access **ends automatically**.
- **Real-website proxy** (`forward_proxy.py`, port 8080) — an HTTP/HTTPS proxy that your browser can use. It blocks or allows real domains such as `youtube.com`, per user.
- **Block page** (`blockpage.py`, optional) — when a blocked HTTPS site is opened, a real page explains **why** it is restricted and **who** restricted it, with a button to request access.
- **Browse** (dashboard page) — open a site inside the dashboard and watch the policy decide.
- **Lab proxy** (`proxy.py` + `netproxy/`) — the original TLS proxy for the simulated services, with content filters.

## Demo accounts

| User | Password | Role |
|---|---|---|
| `admin` | `admin-demo` | Administrator |
| `bob` | `bob-demo` | Requester |
| `carol` | `carol-demo` | Requester |

These are classroom demo credentials. Override them before starting if you like:

```bash
export ACCESSWINDOW_ADMIN_PASSWORD='choose-a-strong-password'
export ACCESSWINDOW_BOB_PASSWORD='choose-another-password'
export ACCESSWINDOW_CAROL_PASSWORD='choose-another-password'
export ACCESSWINDOW_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

The dashboard listens on `127.0.0.1` only. Do not set `ACCESSWINDOW_HOST=0.0.0.0` on an untrusted network.

## Quick start (macOS / VS Code)

Do not use the bundled `.venv` (it points at another machine's Python). Create a fresh one, once:

```bash
cd "proxy-content-filter 5"
python3 -m venv venv && source venv/bin/activate
pip install -r requirements-accesswindow.txt
```

Then run each of these in its own terminal (with `source venv/bin/activate` in each):

| Terminal | Command | What it is | Port |
|---|---|---|---|
| 1 | `python3 services.py` | simulated services (lab) | 9001–9005 |
| 2 | `python3 proxy.py` | lab TLS proxy + admin console | 8443 / 9443 |
| 3 | `python3 forward_proxy.py` *(add `--block-page` for the block page)* | real-website proxy | 8080 |
| 4 | `python3 app.py` | dashboard | 5000 |

Open **`http://127.0.0.1:5000`**. Use `127.0.0.1`, not `localhost` — macOS AirPlay Receiver also listens on port 5000 and `localhost` can end up there.

| What | Address |
|---|---|
| Dashboard | `127.0.0.1:5000` |
| Real-website proxy (browser proxy setting) | `127.0.0.1:8080` |
| Lab TLS proxy | `:8443` |
| Admin console | `127.0.0.1:9443` |

## The dashboard

One page per menu item. The coloured dot on the logo and the pill at the top right show whether the proxy is connected. Click or hover the avatar at the bottom left to see who is signed in and to sign out.

| Page | Administrator | Requester |
|---|---|---|
| **Overview** | counts, pending requests, active grants | my requests and grants |
| **Access requests** | approve / reject | submit a request: *Unblock a website* or *Request a service* |
| **Temporary grants** | live countdown, **Revoke** | my active grants |
| **Activity log** | decisions made | my request history |
| **Browse** | open a site and see the verdict | same |
| **Website access** | add / remove website rules, blocked-site alerts | what applies to me |

Roles are enforced on the server: a requester cannot approve, reject or revoke, and POST forms carry CSRF tokens.

## Block a site, then grant temporary access

1. Sign in as `admin` → **Website access** → *Add a real website rule*: `youtube.com`, **Block**, a reason. The rule records who added it and when.
2. Sign in as `bob` (a private window works) → **My requests → Unblock a website**: choose `youtube.com`, 5 minutes, a reason. (From the block page, the **Request temporary access** button opens this same form with the site already selected.)
3. As `admin` → **Access requests → Approve**. An allow rule for bob + that site is inserted at the top of the policy with an expiry time. **Temporary grants** shows the countdown; **Revoke** ends it early.
4. When time runs out — or the grant is revoked — the block returns by itself: the proxy skips expired rules on every request and **re-checks open connections every second**, so an already-open tunnel is cut within about a second.

Blocking `youtube.com` also covers `googlevideo.com`, `ytimg.com`, `youtu.be` and `youtube-nocookie.com`, because YouTube's video is served from `googlevideo.com`. A temporary grant opens the same set.

## Make your browser use the proxy

The proxy only filters traffic that is sent to it. To filter your normal browser, change one macOS setting.

**System Settings → Network → Wi-Fi → Details… → Proxies**

1. Turn on **Web Proxy (HTTP)**: server `127.0.0.1`, port `8080`.
2. Turn on **Secure Web Proxy (HTTPS)**: server `127.0.0.1`, port `8080`.
3. In *Bypass proxy settings for these Hosts & Domains*, keep the defaults and **add** `127.0.0.1, localhost`, e.g. `*.local, 169.254/16, 127.0.0.1, localhost`.
4. **OK → Apply.**

Or from the terminal (this command *replaces* the bypass list, so it repeats the defaults):

```bash
networksetup -setwebproxy Wi-Fi 127.0.0.1 8080
networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080
networksetup -setproxybypassdomains Wi-Fi "*.local" 169.254/16 127.0.0.1 localhost
```

The first time a site opens, the browser asks for the proxy login: `bob` / `bob-demo`. Close tabs that were already open.

**Turn it off when you're done** — while it is on, your internet depends on `forward_proxy.py` running:

```bash
networksetup -setwebproxystate Wi-Fi off
networksetup -setsecurewebproxystate Wi-Fi off
```

Without touching system settings, you can instead open a separate Brave window that uses the proxy:

```bash
open -na "Brave Browser" --args --user-data-dir=/tmp/aw-profile --proxy-server="http://127.0.0.1:8080"
```

## Block page for blocked HTTPS sites

A browser never shows a proxy's reply to a refused HTTPS tunnel — it shows its own "site can't be reached" page, and YouTube's service worker even serves its cached "Connect to the Internet" page (which has a Downloads link). With `--block-page` the proxy answers **blocked** HTTPS sites itself and serves a real page: *why* it is restricted, *who* restricted it and when, who it applies to, the rule, and a **Request temporary access** button.

```bash
python3 forward_proxy.py --block-page      # the first run creates certs/blockpage/ca.crt and prints the trust command
```

1. **Trust the block-page CA once** (asks for your Mac password / Touch ID):
   `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db certs/blockpage/ca.crt`
2. Open a blocked site in a browser that uses the proxy → the block page appears. The button goes to `/requests?domain=<site>`; if you are signed out you are sent to login first and then back to that page.
3. **Remove the trust when you're done:**
   `security delete-certificate -c "AccessWindow Block Page CA" ~/Library/Keychains/login.keychain-db`

Notes
- Only **blocked** hosts are intercepted. Allowed sites are still tunnelled end to end and never decrypted.
- The page also tells the browser to unregister the blocked site's service worker and clear its stored data (not cookies), so cached "offline" pages and in-browser downloads cannot be opened. Use `--keep-site-data` to switch this off.
- `certs/blockpage/ca.key` can create certificates your Mac trusts while the CA is trusted. It is `chmod 600` and git-ignored; remove the trust after your demo.
- `--dashboard URL` changes where the button points (default `http://127.0.0.1:5000`).
- Safari and Chromium browsers use the macOS trust store; Firefox keeps its own and needs the certificate added separately.

## Browse (inside the dashboard)

Type an address on **Browse**. The dashboard checks it against the **same rules and the same matcher as the proxy**, for the signed-in user:

- **Blocked** → a red "Access blocked" page: the rule, the reason, who it applies to, and (for a requester) a request form.
- **Allowed** → a preview of the page with scripts switched off; links stay inside Browse so every click is checked again.

Safeguards: only `http`/`https`; the address must resolve to a **public** IP (no localhost, admin console or LAN); every redirect is re-checked against the policy and the IP rule; the preview runs in a sandboxed frame; login is required. Only the page document is policy-checked — images and styles load from their own sites. Attempts are written to the same access log, so they appear in the administrator's blocked-site alerts.

## Lab services (simulated)

The original lab proxy filters connections to simulated services using client certificates for identity.

- **Temporary access to a service:** a requester asks for `web`, `chat`, `files` or `echo`; approval inserts a first-priority allow rule into the live policy through the admin console, and an expiry worker inside `proxy.py` removes it on time (and cuts live connections that depended on it).
- **Simulated websites:** `google.test`, `github.test`, `youtube.test`, `instagram.test` resolve to the local web service. Try them with the client:

```bash
python3 client.py --user bob web / --site youtube.test      # blocked if a rule says so
python3 client.py --user bob web / --site github.test
python3 client.py --user bob web /admin/panel               # 403 from rule R04
python3 adminctl.py STATUS                                  # admin console
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

`test_tls_and_identity` expects TLS 1.3; on Macs whose system Python negotiates TLS 1.2 it fails for that reason only. The dashboard needs Flask; if `python3 app.py` fails with `hashlib has no attribute 'scrypt'`, the code already uses PBKDF2, so make sure you are running the current `app.py`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Blocked site still opens | The browser isn't using the proxy. Check the macOS proxy settings above (or use the proxied Brave window), close old tabs, and look at `logs/real_proxy_access.jsonl` — no new lines means traffic isn't reaching the proxy. |
| Everything stops loading | The system proxy is on but `forward_proxy.py` isn't running. Start it, or turn the proxy settings off. |
| "Site can't be reached" instead of the block page | Start the proxy with `--block-page` and trust the CA (steps above). |
| Certificate warning on a blocked site | The block-page CA isn't trusted yet. |
| YouTube keeps playing after a revoke | Restart `forward_proxy.py` to pick up the live re-check, then reload the tab. |
| Dashboard shows an error page | Use `http://127.0.0.1:5000`, not `localhost` (AirPlay uses port 5000). |
| Proxy login prompt every time | Enter `bob` / `bob-demo` and tick "remember". |

## Scope and limitations

- A teaching prototype, not a production access-management product.
- HTTPS is filtered by **hostname**; page contents are not inspected (the block page decrypts only blocked hosts, to show its message).
- Only traffic sent through the proxy is filtered. VPNs, other DNS paths or switching the proxy off bypass it.
- Proxy authentication is HTTP Basic with demo credentials — keep it on loopback. Do not expose ports 8080 or 5000 to the network.
- Rules for real domains live in `config/real_website_policy.json` and are re-read when the file changes. The dashboard and proxy are separate processes sharing that file.
- The Flask development server is for demos only.
