from __future__ import annotations
import hmac, ipaddress, json, os, secrets, socket, time, uuid, re
import urllib.error, urllib.request
from html import unescape
from urllib.parse import quote, urljoin, urlsplit
from datetime import datetime
from functools import wraps
from threading import Lock
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from werkzeug.security import check_password_hash, generate_password_hash
from netproxy.config import ROOT
from netproxy.clientlib import AdminClient
import forward_proxy

app = Flask(__name__)
app.secret_key = os.environ.get("ACCESSWINDOW_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
CFG = json.loads((ROOT / "config" / "proxy.json").read_text(encoding="utf-8"))
POLICY_PATH = ROOT / CFG.get("policy_file", "config/policy.json")
STATE_PATH = ROOT / "config" / "accesswindow_state.json"
REQUESTS_PATH = ROOT / "config" / "accesswindow_requests.json"
LOCK = Lock()
SERVICES = {"web": "Web service", "chat": "Chat service", "files": "File service", "echo": "Echo service"}
SIMULATED_SITES = ["google.test", "github.test", "youtube.test", "instagram.test"]
REAL_POLICY_PATH = ROOT / "config" / "real_website_policy.json"
REAL_LOG_PATH = ROOT / "logs" / "real_proxy_access.jsonl"
USERS = ["bob", "carol"]
DURATIONS = {5: "5 minutes", 15: "15 minutes", 30: "30 minutes", 60: "1 hour"}

# Demo credentials are intentionally simple for a classroom prototype. Override them
# with environment variables before using this app beyond a local demonstration.
PASSWORD_HASHES = {
    "admin": generate_password_hash(os.environ.get("ACCESSWINDOW_ADMIN_PASSWORD", "admin-demo"), method="pbkdf2:sha256"),
    "bob": generate_password_hash(os.environ.get("ACCESSWINDOW_BOB_PASSWORD", "bob-demo"), method="pbkdf2:sha256"),
    "carol": generate_password_hash(os.environ.get("ACCESSWINDOW_CAROL_PASSWORD", "carol-demo"), method="pbkdf2:sha256"),
}
ROLES = {"admin": "admin", "bob": "requester", "carol": "requester"}


def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def protect_post_requests():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            abort(400, description="Invalid or missing form token. Refresh the page and try again.")


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("username") not in ROLES:
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return fn(*args, **kwargs)
    return wrapper


def role_required(role):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if session.get("role") != role:
                abort(403, description="This account does not have permission to perform that action.")
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def admin_command(command):
    ca = str(ROOT / CFG.get("ca", "certs/ca.crt"))
    with AdminClient(host=CFG.get("admin_host", "127.0.0.1"),
                     port=int(CFG.get("admin_port", 9443)),
                     token=CFG.get("admin_token", ""), ca=ca) as client:
        ok, result = client.command(command)
        if not ok:
            raise RuntimeError(result or "Admin command failed")
        return result


def fmt_time(epoch):
    return datetime.fromtimestamp(float(epoch)).strftime("%b %d, %I:%M:%S %p")


def load_requests():
    return read_json(REQUESTS_PATH, {"requests": [], "history": []})



def website_rules():
    doc = read_json(POLICY_PATH, {})
    return [r for r in doc.get("rules", []) if r.get("domains") and r.get("services") == ["web"]]


def recent_blocked_site_attempts(limit=30):
    try:
        output = admin_command(f"LOG {limit}")
    except Exception:
        return []
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("event") == "request" and item.get("decision") == "deny" and item.get("service") == "web":
            item["time_label"] = fmt_time(item.get("time", time.time())) if item.get("time") else "Recent"
            item["domain_label"] = item.get("domain") or item.get("path", "Unknown destination")
            rows.append(item)
    return list(reversed(rows))


def load_real_policy():
    data = read_json(REAL_POLICY_PATH, {"default_action": "allow", "rules": []})
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        return {"default_action": "allow", "rules": []}
    return data


def purge_expired_real_rules():
    """Drop expired temporary allow rules from the real-domain policy (the proxy already ignores them)."""
    policy = load_real_policy()
    keep = [r for r in policy["rules"] if not forward_proxy.rule_expired(r)]
    if len(keep) != len(policy["rules"]):
        policy["rules"] = keep
        write_json(REAL_POLICY_PATH, policy)


def site_grants(user=None):
    """Active temporary site unblocks, soonest-to-expire first."""
    now = time.time()
    rows = []
    for r in load_real_policy()["rules"]:
        if not r.get("temporary") or forward_proxy.rule_expired(r, now):
            continue
        if user and r.get("users") != [user]:
            continue
        rows.append({"id": r["id"], "user": r["users"][0], "domain": r["domains"][0],
                     "reason": r.get("grant_reason", ""), "expires_at": r["expires_at"],
                     "expires_label": fmt_time(r["expires_at"]),
                     "remaining_seconds": max(0, int(float(r["expires_at"]) - now))})
    return sorted(rows, key=lambda g: g["expires_at"])


def blocked_sites_for(user):
    """Domains the forward proxy currently denies for this user (same matcher the proxy uses)."""
    domains = []
    for r in load_real_policy()["rules"]:
        if r.get("action") == "deny" and r.get("enabled", True) and not forward_proxy.rule_expired(r):
            users = r.get("users", ["*"])
            if users and "*" not in users and user not in users:
                continue
            for d in r.get("domains", []):
                if d not in domains and forward_proxy.match_rule(d, user)[0] != "allow":
                    domains.append(d)
    return domains


def real_proxy_alerts(limit=30):
    rows = []
    try:
        lines = REAL_LOG_PATH.read_text(encoding="utf-8").splitlines()[-500:]
    except OSError:
        lines = []
    for line in reversed(lines):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("decision") == "deny":
            item["time_label"] = fmt_time(item.get("time", time.time()))
            item["domain_label"] = item.get("domain", "Unknown domain")
            rows.append(item)
            if len(rows) >= limit:
                break
    return rows


def valid_domain(value):
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or "://" in value or "/" in value or " " in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    import re as _re
    if not _re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", value):
        return None
    return value


def proxy_status():
    try:
        output = admin_command("STATUS")
        lines = output.splitlines()
        stats = next((x.strip() for x in lines if x.strip().startswith("connections active")), "")
        policy = next((x.strip() for x in lines if x.strip().startswith("policy ")), "")
        return {"online": True, "stats": stats, "policy": policy, "error": ""}
    except Exception as exc:
        return {"online": False, "stats": "", "policy": "", "error": str(exc)}


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username") in ROLES:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if username in PASSWORD_HASHES and check_password_hash(PASSWORD_HASHES[username], password):
            session.clear()
            session["username"] = username
            session["role"] = ROLES[username]
            session["csrf_token"] = secrets.token_urlsafe(24)
            flash("Signed in successfully.", "success")
            nxt = request.args.get("next", "")
            if nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt:
                return redirect(nxt)
            return redirect(url_for("index"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


def dashboard_data():
    """Everything the sidebar badge and the dashboard pages need, filtered to what this role may see."""
    username, role = session["username"], session["role"]
    purge_expired_real_rules()
    state = read_json(STATE_PATH, {"grants": []})
    data = load_requests()
    grants = state.get("grants", [])
    for grant in grants:
        grant["expires_label"] = fmt_time(grant.get("expires_at", time.time()))
        grant["remaining_seconds"] = max(0, int(float(grant.get("expires_at", 0)) - time.time()))
    pending = data.get("requests", [])
    for item in pending:
        item["created_label"] = fmt_time(item.get("created_at", time.time()))
    history = list(reversed(data.get("history", [])))
    for item in history:
        item["time_label"] = fmt_time(item.get("time", time.time()))
    if role == "requester":
        pending = [x for x in pending if x.get("user") == username]
        grants = [x for x in grants if x.get("user") == username]
        history = [x for x in history if username in x.get("detail", "")]
    return {"requests": pending, "grants": grants, "history": history[:60],
            "site_grants": site_grants(username if role == "requester" else None),
            "services": SERVICES, "durations": DURATIONS}


def render_page(template, **ctx):
    ctx = {**dashboard_data(), "username": session["username"], "role": session["role"], **ctx}
    if "status" not in ctx:
        ctx["status"] = proxy_status()
    return render_template(template, **ctx)


@app.get("/")
@login_required
def index():
    return render_page("overview.html")


@app.get("/requests")
@login_required
def requests_page():
    blocked = blocked_sites_for(session["username"]) if session["role"] == "requester" else []
    preselect = request.args.get("domain", "").strip().lower()
    return render_page("requests.html", blocked_sites=blocked, preselect=preselect if preselect in blocked else "")


@app.get("/grants")
@login_required
def grants_page():
    return render_page("grants.html")


@app.get("/activity")
@login_required
def activity_page():
    return render_page("activity.html")


# ---------------------------------------------------------------- Browse: open a site inside the dashboard
# The address is checked against the same real-domain rules the forward proxy uses (forward_proxy.match_rule),
# for the signed-in user. Blocked -> a block page in the browser. Allowed -> a scripts-off preview of the page.
MAX_PAGE_BYTES = 1_500_000
MAX_HOPS = 4


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):      # hand redirects back so every hop is re-checked
        return None


def _public_host(host):
    """True only if every address the name resolves to is a public one (the dashboard must not become a way
    to reach localhost, the admin console or the LAN)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    try:
        return bool(infos) and all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)
    except ValueError:
        return False


def _http_get(url):
    """One HTTP hop, no automatic redirects. Returns (status, headers, body)."""
    req = urllib.request.Request(url, headers={"User-Agent": "AccessWindow-Browse/1.0", "Accept": "text/html,*/*;q=0.5"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=8) as resp:
            return resp.status, resp.headers, resp.read(MAX_PAGE_BYTES + 1)
    except urllib.error.HTTPError as err:              # 3xx (not followed) and 4xx/5xx still carry a response
        return err.code, err.headers, err.read(MAX_PAGE_BYTES + 1)


def _matched_domain(rule, host):
    return forward_proxy.domain_hit(host, rule or {}) or host


def _rewrite_page(html, base):
    """Make the preview safe and keep navigation inside Browse (so each click is policy-checked again)."""
    html = re.sub(r"<base\b[^>]*>", "", html, flags=re.I)
    def link(m):
        href = unescape(m.group(3)).strip()
        if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return m.group(0)
        return f'{m.group(1)}{m.group(2)}/browse?url={quote(urljoin(base, href), safe="")}{m.group(2)} target="_top"'
    html = re.sub(r"(<a\b[^>]*?\shref\s*=\s*)([\"'])(.*?)\2", link, html, flags=re.I | re.S)
    tag = f'<base href="{base}">'
    return re.sub(r"(<head\b[^>]*>)", r"\1" + tag, html, count=1, flags=re.I) if re.search(r"<head\b", html, re.I) else tag + html


def browse_fetch(url, user):
    """Policy check + fetch. Returns a dict the template renders: kind is blocked | page | binary | error."""
    for _ in range(MAX_HOPS):
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme not in ("http", "https") or not host:
            return {"kind": "error", "message": "Only http:// and https:// addresses can be opened.", "url": url}
        action, rule = forward_proxy.match_rule(host, user)
        if action != "allow":
            forward_proxy.log_event(user, host, "BROWSE", "deny", rule)
            return {"kind": "blocked", "host": host, "url": url, "rule": rule or {}, "domain": _matched_domain(rule, host),
                    "reason": (rule or {}).get("reason") or "Blocked by website policy"}
        if not _public_host(host):
            return {"kind": "error", "host": host, "url": url,
                    "message": "That address is private or could not be resolved, so Browse will not open it."}
        forward_proxy.log_event(user, host, "BROWSE", "allow", rule)
        try:
            status, headers, body = _http_get(url)
        except (OSError, ValueError) as exc:
            return {"kind": "error", "host": host, "url": url, "message": f"Could not reach {host}: {exc}"}
        if status in (301, 302, 303, 307, 308) and headers.get("Location"):
            url = urljoin(url, headers["Location"])
            continue
        ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
        info = {"host": host, "url": url, "status": status, "ctype": ctype or "unknown",
                "rule": rule or {}, "how": (rule or {}).get("id") or "default policy"}
        if ctype not in ("text/html", "application/xhtml+xml"):
            return {"kind": "binary", **info}
        charset = (headers.get_content_charset() or "utf-8") if hasattr(headers, "get_content_charset") else "utf-8"
        text = body[:MAX_PAGE_BYTES].decode(charset, "replace")
        return {"kind": "page", "truncated": len(body) > MAX_PAGE_BYTES, "html": _rewrite_page(text, url), **info}
    return {"kind": "error", "message": "Too many redirects.", "url": url}


@app.get("/browse")
@login_required
def browse_page():
    raw = request.args.get("url", "").strip()
    result = browse_fetch(raw if "://" in raw else "https://" + raw, session["username"]) if raw else None
    return render_page("browse.html", url=raw, result=result)


@app.post("/request")
@role_required("requester")
def create_request():
    user = session["username"]
    service = request.form.get("service", "")
    reason = request.form.get("reason", "").strip()
    minutes = request.form.get("minutes", "15")
    if service not in SERVICES or minutes not in {str(x) for x in DURATIONS} or not reason:
        flash("Choose a valid service and duration, and enter a reason.", "error")
        return redirect(url_for("requests_page"))
    with LOCK:
        data = load_requests()
        item = {"id": uuid.uuid4().hex[:8].upper(), "user": user, "service": service,
                "reason": reason[:240], "minutes": int(minutes), "created_at": time.time(), "status": "pending"}
        data.setdefault("requests", []).append(item)
        write_json(REQUESTS_PATH, data)
    flash(f"Request {item['id']} submitted for administrator review.", "success")
    return redirect(url_for("requests_page"))


@app.post("/site-request")
@role_required("requester")
def create_site_request():
    user = session["username"]
    domain = request.form.get("domain", "").strip().lower()
    reason = request.form.get("reason", "").strip()
    minutes = request.form.get("minutes", "5")
    if domain not in blocked_sites_for(user) or minutes not in {str(x) for x in DURATIONS} or not reason:
        flash("Choose a site that is currently blocked for you, a duration, and enter a reason.", "error")
        return redirect(url_for("requests_page"))
    with LOCK:
        data = load_requests()
        if any(x.get("kind") == "site" and x.get("user") == user and x.get("domain") == domain
               for x in data.get("requests", [])):
            flash(f"You already have a pending request for {domain}.", "error")
            return redirect(url_for("requests_page"))
        item = {"id": uuid.uuid4().hex[:8].upper(), "kind": "site", "user": user, "domain": domain,
                "service": "web", "reason": reason[:240], "minutes": int(minutes),
                "created_at": time.time(), "status": "pending"}
        data.setdefault("requests", []).append(item)
        write_json(REQUESTS_PATH, data)
    flash(f"Request {item['id']} for {domain} submitted for administrator review.", "success")
    return redirect(url_for("requests_page"))


@app.post("/site-grant/<rule_id>/revoke")
@role_required("admin")
def revoke_site_grant(rule_id):
    if not re.fullmatch(r"REAL-[A-F0-9]{8}", rule_id):
        abort(400, description="Invalid grant ID.")
    with LOCK:
        policy = load_real_policy()
        grant = next((r for r in policy["rules"] if r.get("id") == rule_id and r.get("temporary")), None)
        if not grant:
            flash("Temporary site access not found (it may have already expired).", "error")
            return redirect(url_for("grants_page"))
        policy["rules"] = [r for r in policy["rules"] if r.get("id") != rule_id]
        write_json(REAL_POLICY_PATH, policy)
        data = load_requests()
        data.setdefault("history", []).append({"time": time.time(), "event": "Temporary site access revoked",
            "detail": f"{grant['users'][0]} · {grant['domains'][0]}"})
        write_json(REQUESTS_PATH, data)
    flash("Temporary site access revoked immediately.", "success")
    return redirect(url_for("grants_page"))


@app.post("/request/<request_id>/<decision>")
@role_required("admin")
def decide_request(request_id, decision):
    if decision not in {"approve", "reject"}:
        return "Invalid decision", 400
    with LOCK:
        data = load_requests()
        item = next((x for x in data.get("requests", []) if x.get("id") == request_id), None)
        if not item or item.get("status") != "pending":
            flash("That request is no longer pending.", "error")
            return redirect(url_for("requests_page"))
        if decision == "reject":
            item["status"] = "rejected"
            item["decided_at"] = time.time()
            data.setdefault("history", []).append({"time": time.time(), "event": "Request rejected",
                "detail": f"{item['user']} · {item.get('domain') or SERVICES[item['service']]} · {item['reason']}"})
            data["requests"] = [x for x in data["requests"] if x.get("id") != request_id]
            write_json(REQUESTS_PATH, data)
            flash("Request rejected.", "success")
            return redirect(url_for("requests_page"))
        if item.get("kind") == "site":
            expires = time.time() + int(item["minutes"]) * 60
            rule_id = "REAL-" + uuid.uuid4().hex[:8].upper()
            policy = load_real_policy()
            # First-match wins, so this allow sits above the block until it expires.
            policy["rules"].insert(0, {"id": rule_id, "action": "allow", "users": [item["user"]],
                "domains": [item["domain"]], "enabled": True, "temporary": True, "expires_at": expires,
                "grant_reason": item["reason"], "created_by": session["username"], "created_at": time.time(),
                "reason": f"Temporary access approved until {fmt_time(expires)}: {item['reason']}"})
            write_json(REAL_POLICY_PATH, policy)
            item["status"] = "approved"
            item["decided_at"] = time.time()
            data.setdefault("history", []).append({"time": time.time(), "event": "Temporary site access approved",
                "detail": f"{item['user']} · {item['domain']} · {item['minutes']} minutes", "rule_id": rule_id})
            data["requests"] = [x for x in data["requests"] if x.get("id") != request_id]
            write_json(REQUESTS_PATH, data)
            flash(f"{item['domain']} unblocked for {item['user']} for {item['minutes']} minutes.", "success")
            return redirect(url_for("requests_page"))
        try:
            status = proxy_status()
            if not status["online"]:
                raise RuntimeError("Start the proxy before approving access.")
            rule_id = "AW-" + uuid.uuid4().hex[:8].upper()
            grant = {"id": uuid.uuid4().hex[:8].upper(), "rule_id": rule_id,
                     "user": item["user"], "service": item["service"], "reason": item["reason"],
                     "approved_at": time.time(), "expires_at": time.time() + int(item["minutes"]) * 60}
            rule = {"id": rule_id, "action": "allow", "users": [item["user"]],
                    "services": [item["service"]],
                    "reason": f"AccessWindow temporary grant: {item['reason']}"}
            admin_command("RULE INSERT 1 " + json.dumps(rule, separators=(",", ":")))
            state = read_json(STATE_PATH, {"grants": []})
            state.setdefault("grants", []).append(grant)
            write_json(STATE_PATH, state)
            item["status"] = "approved"
            item["decided_at"] = time.time()
            data.setdefault("history", []).append({"time": time.time(), "event": "Temporary access approved",
                "detail": f"{item['user']} · {SERVICES[item['service']]} · {item['minutes']} minutes",
                "rule_id": rule_id})
            data["requests"] = [x for x in data["requests"] if x.get("id") != request_id]
            write_json(REQUESTS_PATH, data)
            flash(f"Access approved. Rule {rule_id} expires in {item['minutes']} minutes.", "success")
        except Exception as exc:
            flash(f"Could not approve request: {exc}", "error")
    return redirect(url_for("requests_page"))


@app.post("/grant/<grant_id>/revoke")
@role_required("admin")
def revoke_grant(grant_id):
    with LOCK:
        state = read_json(STATE_PATH, {"grants": []})
        grant = next((x for x in state.get("grants", []) if x.get("id") == grant_id), None)
        if not grant:
            flash("Temporary grant not found.", "error")
            return redirect(url_for("grants_page"))
        try:
            admin_command("RULE DEL " + grant["rule_id"])
            state["grants"] = [x for x in state["grants"] if x.get("id") != grant_id]
            write_json(STATE_PATH, state)
            data = load_requests()
            data.setdefault("history", []).append({"time": time.time(), "event": "Temporary access revoked",
                "detail": f"{grant['user']} · {SERVICES.get(grant['service'], grant['service'])}"})
            write_json(REQUESTS_PATH, data)
            flash("Temporary access revoked immediately.", "success")
        except Exception as exc:
            flash(f"Could not revoke access: {exc}", "error")
    return redirect(url_for("grants_page"))



@app.get("/websites")
@login_required
def websites():
    username, role = session["username"], session["role"]
    purge_expired_real_rules()
    all_rules = website_rules()
    rules = all_rules if role == "admin" else [r for r in all_rules if not r.get("users") or username in r.get("users", []) or "*" in r.get("users", [])]
    policy_doc = read_json(POLICY_PATH, {})
    ordered_rules = policy_doc.get("rules", [])
    visible_users = ["bob", "carol"] if role == "admin" else [username]
    site_statuses = []
    for site in SIMULATED_SITES:
        row = {"domain": site, "users": []}
        for site_user in visible_users:
            decision = "allow"  # Existing student web-service policy allows these simulated destinations by default.
            matched = None
            for candidate in ordered_rules:
                if site not in candidate.get("domains", []):
                    continue
                if candidate.get("services") and "web" not in candidate.get("services", []):
                    continue
                allowed_users = candidate.get("users", [])
                if allowed_users and site_user not in allowed_users and "*" not in allowed_users:
                    continue
                matched = candidate
                break
            if matched:
                decision = matched.get("action", "deny")
            row["users"].append({"user": site_user, "action": decision, "rule_id": matched.get("id") if matched else "R06"})
        site_statuses.append(row)
    for rule in rules:
        rule["domain_label"] = ", ".join(rule.get("domains", []))
        rule["user_label"] = ", ".join(rule.get("users", [])) or "Everyone"
    alerts = recent_blocked_site_attempts() if role == "admin" else []
    real_policy = load_real_policy()
    real_rules = real_policy.get("rules", []) if role == "admin" else [r for r in real_policy.get("rules", []) if not r.get("users") or username in r.get("users", []) or "*" in r.get("users", [])]
    for rule in real_rules:
        rule["domain_label"] = ", ".join(rule.get("domains", []))
        rule["user_label"] = ", ".join(rule.get("users", [])) or "Everyone"
        rule["added_label"] = (f"added by {rule['created_by']} · {fmt_time(rule['created_at'])}"
                               if rule.get("created_by") and rule.get("created_at") else "")
    real_alerts = real_proxy_alerts() if role == "admin" else []
    return render_page("website_access.html", rules=rules, sites=SIMULATED_SITES, alerts=alerts, site_statuses=site_statuses,
                           real_rules=real_rules, real_alerts=real_alerts, real_default=real_policy.get("default_action", "allow"))


@app.post("/websites/add")
@role_required("admin")
def add_website_rule():
    domain = request.form.get("domain", "").strip().lower().rstrip(".")
    user = request.form.get("user", "").strip().lower()
    action = request.form.get("action", "deny")
    reason = request.form.get("reason", "").strip()[:180]
    if domain not in SIMULATED_SITES or user not in {"bob", "carol", "*"} or action not in {"allow", "deny"} or not reason:
        flash("Choose a listed simulated site, valid user, action, and reason.", "error")
        return redirect(url_for("websites"))
    rule_id = "SITE-" + uuid.uuid4().hex[:7].upper()
    rule = {"id": rule_id, "action": action, "users": [user], "services": ["web"],
            "domains": [domain], "reason": reason, "enabled": True}
    try:
        if not proxy_status()["online"]:
            raise RuntimeError("Start proxy.py before changing website rules.")
        admin_command("RULE INSERT 1 " + json.dumps(rule, separators=(",", ":")))
        data = load_requests()
        data.setdefault("history", []).append({"time": time.time(), "event": "Website policy added",
            "detail": f"{user} · {domain} · {action.upper()} · {reason}", "rule_id": rule_id})
        write_json(REQUESTS_PATH, data)
        flash(f"{domain} is now set to {action.upper()} for {user}.", "success")
    except Exception as exc:
        flash(f"Could not add website rule: {exc}", "error")
    return redirect(url_for("websites"))


@app.post("/websites/<rule_id>/delete")
@role_required("admin")
def delete_website_rule(rule_id):
    if not re.fullmatch(r"SITE-[A-F0-9]{7}", rule_id):
        abort(400, description="Invalid website rule ID.")
    try:
        existing = next((r for r in website_rules() if r.get("id") == rule_id), None)
        if not existing:
            flash("Website rule was not found.", "error")
        else:
            admin_command("RULE DEL " + rule_id)
            data = load_requests()
            data.setdefault("history", []).append({"time": time.time(), "event": "Website policy removed",
                "detail": f"{', '.join(existing.get('users', []))} · {', '.join(existing.get('domains', []))}"})
            write_json(REQUESTS_PATH, data)
            flash("Website rule removed.", "success")
    except Exception as exc:
        flash(f"Could not remove website rule: {exc}", "error")
    return redirect(url_for("websites"))


@app.post("/real-websites/add")
@role_required("admin")
def add_real_website_rule():
    domain = valid_domain(request.form.get("domain", ""))
    user = request.form.get("user", "*").strip().lower()
    action = request.form.get("action", "deny")
    reason = request.form.get("reason", "").strip()[:180]
    if not domain or user not in {"bob", "carol", "*"} or action not in {"allow", "deny"} or not reason:
        flash("Enter a valid domain such as youtube.com, choose a user and decision, and provide a reason.", "error")
        return redirect(url_for("websites"))
    policy = load_real_policy()
    rule_id = "REAL-" + uuid.uuid4().hex[:8].upper()
    rule = {"id": rule_id, "action": action, "users": [user], "domains": [domain], "reason": reason, "enabled": True,
            "created_by": session["username"], "created_at": time.time()}
    # Put the newest rule first so the administrator's latest decision takes precedence.
    policy.setdefault("rules", []).insert(0, rule)
    write_json(REAL_POLICY_PATH, policy)
    data = load_requests()
    data.setdefault("history", []).append({"time": time.time(), "event": "Real website policy added",
        "detail": f"{user} · {domain} · {action.upper()} · {reason}", "rule_id": rule_id})
    write_json(REQUESTS_PATH, data)
    flash(f"Real-domain rule saved: {domain} is {action.upper()} for {user}. Restart is not required.", "success")
    return redirect(url_for("websites"))


@app.post("/real-websites/<rule_id>/delete")
@role_required("admin")
def delete_real_website_rule(rule_id):
    if not re.fullmatch(r"REAL-[A-F0-9]{8}", rule_id):
        abort(400, description="Invalid real website rule ID.")
    policy = load_real_policy()
    old = next((r for r in policy.get("rules", []) if r.get("id") == rule_id), None)
    if not old:
        flash("Real website rule not found.", "error")
    else:
        policy["rules"] = [r for r in policy.get("rules", []) if r.get("id") != rule_id]
        write_json(REAL_POLICY_PATH, policy)
        data = load_requests()
        data.setdefault("history", []).append({"time": time.time(), "event": "Real website policy removed",
            "detail": f"{', '.join(old.get('users', []))} · {', '.join(old.get('domains', []))}", "rule_id": rule_id})
        write_json(REQUESTS_PATH, data)
        flash("Real-domain rule removed.", "success")
    return redirect(url_for("websites"))


if __name__ == "__main__":
    app.run(host=os.environ.get("ACCESSWINDOW_HOST", "127.0.0.1"), port=5000, debug=False)
