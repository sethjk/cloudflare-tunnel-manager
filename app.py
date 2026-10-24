#!/usr/bin/env python3
"""Tunnel Manager: a small web page for managing a remotely-managed Cloudflare tunnel.

Lists the tunnel's public hostnames, and adds, edits or removes them.
Each change updates both the tunnel's routes and the matching DNS record.
The tunnel config is backed up to ./backups before every change.
Standard library only, so it runs in a plain python image.
"""
import base64, datetime, json, os, re, secrets, socket, sys, urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API = os.environ.get("CF_API_BASE", "https://api.cloudflare.com/client/v4")
HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(HERE, "secrets", "cf_token")


def token():
    t = os.environ.get("CF_API_TOKEN", "")
    if not t and os.path.exists(TOKEN_FILE):
        t = open(TOKEN_FILE).read()
    t = t.strip()
    if not t:
        raise CFError("No Cloudflare API token yet. Set CF_API_TOKEN or save it to secrets/cf_token next to app.py.")
    return t
PASSWORD = os.environ.get("UI_PASSWORD", "")
DOMAIN = os.environ.get("CF_DOMAIN", "").strip().lower()
if not DOMAIN:
    sys.exit("CF_DOMAIN is not set. Set it to your Cloudflare zone, for example CF_DOMAIN=example.com")
TUNNEL_NAME = os.environ.get("CF_TUNNEL", "")          # optional: pick a tunnel by name
LOCAL_HOST_FOR_CHECKS = os.environ.get("CHECK_HOST", "host.docker.internal")
BACKUPS = os.path.join(HERE, "backups")
os.makedirs(BACKUPS, exist_ok=True)


class CFError(Exception):
    pass


def cf(method, path, body=None, params=None):
    url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token()}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            d = json.load(e)
        except Exception:
            raise CFError(f"Cloudflare returned HTTP {e.code}")
    if not d.get("success"):
        errs = d.get("errors", [])
        msgs = "; ".join(str(x.get("message") or x.get("error") or x.get("code")) for x in errs) or "unknown error"
        if any(x.get("code") in (10000, 1010) or "forbidden" in str(x.get("error", "")) for x in errs):
            msgs += " (the API key doesn't have permission for this)"
        raise CFError(msgs)
    return d["result"]


# ---- discovery (cached) ----
_ctx = {}
def ctx():
    if _ctx:
        return _ctx
    zones = cf("GET", "/zones", params={"name": DOMAIN})
    if not zones:
        raise CFError(f"The API token can't see the zone {DOMAIN}")
    zone = zones[0]
    acct = zone["account"]["id"]
    tunnels = cf("GET", f"/accounts/{acct}/cfd_tunnel", params={"is_deleted": "false"})
    if not tunnels:
        raise CFError("No tunnels found in this Cloudflare account")
    _ctx.update(zone_id=zone["id"], account_id=acct, tunnels=tunnels)
    return _ctx


def pick_tunnel(tid=None):
    c = ctx()
    ts = c["tunnels"]
    if tid:
        for t in ts:
            if t["id"] == tid:
                return t
    if TUNNEL_NAME:
        for t in ts:
            if t["name"] == TUNNEL_NAME:
                return t
    # default: the one with active connections, else the first
    live = [t for t in ts if t.get("status") == "healthy"]
    return (live or ts)[0]


def get_config(acct, tid):
    r = cf("GET", f"/accounts/{acct}/cfd_tunnel/{tid}/configurations")
    cfg = (r or {}).get("config") or {}
    cfg.setdefault("ingress", [{"service": "http_status:404"}])
    return cfg


def backup(tid, cfg, action):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    with open(os.path.join(BACKUPS, f"{stamp}-{tid[:8]}-{action}.json"), "w") as f:
        json.dump(cfg, f, indent=1)


def put_config(acct, tid, cfg):
    cf("PUT", f"/accounts/{acct}/cfd_tunnel/{tid}/configurations", {"config": cfg})


def dns_records(zone_id, name):
    return cf("GET", f"/zones/{zone_id}/dns_records", params={"name": name})


def check_local(service):
    """Is the target answering? Only for http(s)://host:port targets."""
    m = re.match(r"^(https?|tcp|ssh|rdp)://([^/:]+)(?::(\d+))?", service or "", re.I)
    if not m:
        return None
    host, port = m.group(2), m.group(3)
    port = int(port) if port else (443 if m.group(1).lower() == "https" else 80)
    if host in ("localhost", "127.0.0.1"):
        host = LOCAL_HOST_FOR_CHECKS
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except OSError:
        return False


def clean_sub(sub):
    sub = (sub or "").strip().lower()
    if sub.endswith("." + DOMAIN):
        sub = sub[: -len(DOMAIN) - 1]
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*", sub):
        raise CFError("Use letters, numbers and hyphens only (for example: photos)")
    return sub


def clean_service(target):
    t = (target or "").strip()
    if re.fullmatch(r"\d{2,5}", t):                     # just a port number
        return f"http://localhost:{t}"
    if re.fullmatch(r"[\w.-]+:\d{2,5}", t):             # host:port
        return f"http://{t}"
    if re.match(r"^(https?|tcp|ssh|rdp|unix)://", t, re.I) or t.startswith("http_status:"):
        return t
    raise CFError("Target should be a port (8080), host:port, or a full URL (http://localhost:8080)")



# ---- Cloudflare Access (email code in front of a site) ----
POLICY_NAME = "Tunnel Manager: allowed people"
APP_PREFIX = "Tunnel Manager: "
SESSION = "720h"   # how long a device stays signed in (30 days)
LOGIN_HELP = ("Cloudflare has no email-code login yet. One-time step: in the Cloudflare dashboard open Zero Trust -> "
              "Integrations -> Identity providers -> Add new identity provider -> One-time PIN -> Save. Then click Re-check.")


MANAGED_FILE = os.path.join(HERE, "managed_access_apps.json")   # ids of Access apps this page created
FRIENDLY_FILE = os.path.join(HERE, "friendly_names.json")   # optional {"subdomain": "Display name"}
# Names for Access apps, keyed by subdomain. Anything not listed is title-cased ("my-app" -> "My App").
FRIENDLY = {"ha": "Home Assistant", "homeassistant": "Home Assistant", "tautulli": "Tautulli",
            "uptime": "Uptime Kuma", "ntfy": "ntfy", "tunnels": "Tunnel Manager", "sabnzbd": "SABnzbd"}
try:
    FRIENDLY.update({k.lower(): v for k, v in json.load(open(FRIENDLY_FILE, encoding="utf-8")).items()})
except FileNotFoundError:
    pass


def friendly_name(host):
    sub = host.lower().split(".")[0]
    return FRIENDLY.get(sub) or sub.replace("-", " ").title()


def _managed_ids():
    try:
        return set(json.load(open(MANAGED_FILE)))
    except Exception:
        return set()


def _save_managed(ids):
    tmp = MANAGED_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(ids), f)
    os.replace(tmp, MANAGED_FILE)


def _is_managed(app_obj):
    return app_obj.get("id") in _managed_ids() or (app_obj.get("name") or "").startswith(APP_PREFIX)


def _covers(app_obj, host):
    """Does this Access application protect the whole of `host`?"""
    host = host.lower()
    names = [app_obj.get("domain") or ""] + [d.get("uri") or "" for d in (app_obj.get("destinations") or [])]
    names += list(app_obj.get("self_hosted_domains") or [])
    for n in names:
        n = n.lower().strip().rstrip("/")
        if not n:
            continue
        if n == host:
            return True
        if n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count("."):
            return True
    return False


def access_state():
    acct = ctx()["account_id"]
    try:
        apps = cf("GET", f"/accounts/{acct}/access/apps")
        policies = cf("GET", f"/accounts/{acct}/access/policies")
    except CFError as e:
        return {"enabled": False, "reason": str(e), "apps": [], "policy": None, "emails": [], "loginMethod": False}
    policy = next((p for p in policies if p.get("name") == POLICY_NAME), None)
    emails = []
    for inc in (policy or {}).get("include", []):
        if "email" in inc:
            emails.append(inc["email"]["email"])
    try:
        idps = cf("GET", f"/accounts/{acct}/access/identity_providers")
        # An empty list can just mean the key isn't allowed to see login methods, so treat it as "unknown".
        login = True if idps else None
    except CFError:
        login = None  # can't tell
    return {"enabled": True, "apps": apps, "policy": policy, "emails": sorted(emails, key=str.lower), "loginMethod": login}


def protection_for(state, host):
    for a in state["apps"]:
        if a.get("type") in ("self_hosted", None) and _covers(a, host):
            return {"by": a.get("name"), "managed": _is_managed(a), "id": a.get("id")}
    return None


def set_emails(emails):
    acct = ctx()["account_id"]
    clean = []
    for e in emails or []:
        e = (e or "").strip().lower()
        if not e:
            continue
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e):
            raise CFError(f"'{e}' doesn't look like an email address")
        if e not in clean:
            clean.append(e)
    st = access_state()
    if not st["enabled"]:
        raise CFError("Cloudflare Access isn't available with this API key: " + st.get("reason", ""))
    managed = [a for a in st["apps"] if _is_managed(a)]
    if not clean and managed:
        raise CFError("At least one email is needed while sites are protected. Turn protection off first.")
    body = {"name": POLICY_NAME, "decision": "allow", "include": [{"email": {"email": e}} for e in clean],
            "session_duration": SESSION}
    if st["policy"]:
        if clean:
            cf("PUT", f"/accounts/{acct}/access/policies/{st['policy']['id']}", body)
        else:
            cf("DELETE", f"/accounts/{acct}/access/policies/{st['policy']['id']}")
    elif clean:
        cf("POST", f"/accounts/{acct}/access/policies", body)
    return {"ok": True, "emails": clean}


def set_protection(host, on, state=None):
    acct = ctx()["account_id"]
    host = host.lower()
    st = state or access_state()
    if not st["enabled"]:
        raise CFError("Cloudflare Access isn't available with this API key: " + st.get("reason", ""))
    current = protection_for(st, host)
    if on:
        if current:
            return {"ok": True, "already": True}
        if not st["policy"] or not st["emails"]:
            raise CFError("Add at least one email under 'Who can get past the email code' first.")
        if st["loginMethod"] is False:
            raise CFError(LOGIN_HELP)
        created = cf("POST", f"/accounts/{acct}/access/apps", {
            "name": friendly_name(host), "type": "self_hosted", "domain": host,
            "session_duration": SESSION, "app_launcher_visible": False,
            "policies": [{"id": st["policy"]["id"], "precedence": 1}]})
        _save_managed(_managed_ids() | {created["id"]})
        return {"ok": True}
    if not current:
        return {"ok": True, "already": True}
    if not current["managed"]:
        raise CFError(f"{host} is protected by '{current['by']}', which was set up in the Cloudflare dashboard. "
                      "Change it there.")
    cf("DELETE", f"/accounts/{acct}/access/apps/{current['id']}")
    _save_managed(_managed_ids() - {current["id"]})
    return {"ok": True}


# ---- actions ----
def list_state(tid=None):
    c = ctx()
    t = pick_tunnel(tid)
    acct = c["account_id"]
    cfg = get_config(acct, t["id"])
    rows = []
    for i, rule in enumerate(cfg["ingress"]):
        h = rule.get("hostname")
        if not h:
            continue
        rows.append({"hostname": h, "service": rule.get("service"), "path": rule.get("path", ""),
                     "noTLSVerify": bool((rule.get("originRequest") or {}).get("noTLSVerify")),
                     "up": check_local(rule.get("service"))})
    info = cf("GET", f"/accounts/{acct}/cfd_tunnel/{t['id']}")
    ast = access_state()
    for row in rows:
        pr = protection_for(ast, row["hostname"]) if ast["enabled"] else None
        row["protected"] = bool(pr)
        row["protectedBy"] = pr["by"] if pr else None
        row["protectionManaged"] = pr["managed"] if pr else None
    access = {"enabled": ast["enabled"], "emails": ast["emails"], "loginMethod": ast["loginMethod"],
              "reason": ast.get("reason"), "loginHelp": LOGIN_HELP}
    return {"domain": DOMAIN, "access": access,
            "tunnel": {"id": t["id"], "name": t["name"], "status": info.get("status"),
                       "connections": len(info.get("connections") or [])},
            "tunnels": [{"id": x["id"], "name": x["name"], "status": x.get("status")} for x in c["tunnels"]],
            "hostnames": sorted(rows, key=lambda r: r["hostname"])}


def upsert(tid, sub, target, no_tls_verify=False, old_hostname=None, protect=None):
    c = ctx()
    t = pick_tunnel(tid)
    acct, zone = c["account_id"], c["zone_id"]
    host = f"{clean_sub(sub)}.{DOMAIN}"
    service = clean_service(target)
    cfg = get_config(acct, t["id"])
    ingress = cfg["ingress"]
    catch_all = [r for r in ingress if not r.get("hostname")] or [{"service": "http_status:404"}]
    rules = [r for r in ingress if r.get("hostname")]
    same = lambda a, b: (a or "").lower() == (b or "").lower()
    renaming = bool(old_hostname) and not same(old_hostname, host)
    if renaming and any(same(r["hostname"], host) for r in rules):
        raise CFError(f"{host} is already in use")
    existing = next((r for r in rules if same(r["hostname"], old_hostname or host)), None)
    # DNS: make sure the name points at this tunnel (and doesn't clobber something else)
    target_cname = f"{t['id']}.cfargotunnel.com"
    recs = dns_records(zone, host)
    if recs:
        rec = recs[0]
        if rec["type"] != "CNAME" or not rec["content"].endswith(".cfargotunnel.com"):
            raise CFError(f"{host} already has a DNS record ({rec['type']} {rec['content']}). "
                          "Remove it in Cloudflare first or pick another name.")
    backup(t["id"], cfg, "before-save-" + host)
    # keep any other settings already on the rule (path, originRequest options set in the dashboard)
    new_rule = {k: v for k, v in (existing or {}).items() if k not in ("hostname", "service")}
    new_rule.update(hostname=host, service=service)
    origin = dict(new_rule.get("originRequest") or {})
    if no_tls_verify:
        origin["noTLSVerify"] = True
    else:
        origin.pop("noTLSVerify", None)
    if origin:
        new_rule["originRequest"] = origin
    else:
        new_rule.pop("originRequest", None)
    if existing:
        rules = [new_rule if r is existing else r for r in rules]
    else:
        rules.append(new_rule)
    cfg["ingress"] = rules + catch_all[-1:]
    put_config(acct, t["id"], cfg)
    if recs:
        if recs[0]["content"] != target_cname:
            cf("PATCH", f"/zones/{zone}/dns_records/{recs[0]['id']}", {"content": target_cname, "proxied": True})
    else:
        cf("POST", f"/zones/{zone}/dns_records",
           {"type": "CNAME", "name": host, "content": target_cname, "proxied": True,
            "comment": "Cloudflare tunnel (added by Tunnel Manager)"})
    # renamed: remove the old DNS name
    if renaming:
        for r in dns_records(zone, old_hostname.lower()):
            if r["type"] == "CNAME" and r["content"] == target_cname:
                cf("DELETE", f"/zones/{zone}/dns_records/{r['id']}")
    note = None
    try:
        st = access_state()
        if st["enabled"]:
            if renaming:
                old_pr = protection_for(st, old_hostname)
                if old_pr and old_pr["managed"]:
                    set_protection(old_hostname, False, st)
                    st = access_state()
                    if protect is None:
                        protect = True
            if protect is not None:
                set_protection(host, bool(protect), st)
    except CFError as e:
        note = f"The address was saved, but the email-code setting wasn't: {e}"
    return {"ok": True, "hostname": host, "service": service, "note": note}


def remove(tid, hostname):
    c = ctx()
    t = pick_tunnel(tid)
    acct, zone = c["account_id"], c["zone_id"]
    cfg = get_config(acct, t["id"])
    low = (hostname or "").lower()
    if not any((r.get("hostname") or "").lower() == low for r in cfg["ingress"]):
        raise CFError(f"{hostname} isn't on this tunnel")
    backup(t["id"], cfg, "before-remove-" + hostname)
    cfg["ingress"] = [r for r in cfg["ingress"] if (r.get("hostname") or "").lower() != low]
    put_config(acct, t["id"], cfg)
    for r in dns_records(zone, low):
        if r["type"] == "CNAME" and r["content"] == f"{t['id']}.cfargotunnel.com":
            cf("DELETE", f"/zones/{zone}/dns_records/{r['id']}")
    try:
        st = access_state()
        pr = protection_for(st, low) if st["enabled"] else None
        if pr and pr["managed"]:
            set_protection(low, False, st)
    except CFError:
        pass
    return {"ok": True}


# ---- web ----
PAGE = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()


class H(BaseHTTPRequestHandler):
    server_version = "TunnelManager/1.0"

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

    def _auth(self):
        if not PASSWORD:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                _, pw = base64.b64decode(h[6:]).decode().split(":", 1)
                if secrets.compare_digest(pw, PASSWORD):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Tunnel Manager"')
        self.end_headers()
        return False

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if "json" in ctype or "html" in ctype else ""))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/healthz":                     # for uptime monitors; reveals nothing
            return self._send(200, {"ok": True})
        if not self._auth():
            return
        q = dict(urllib.parse.parse_qsl(u.query))
        try:
            if u.path == "/":
                return self._send(200, PAGE, "text/html")
            if u.path == "/api/state":
                return self._send(200, list_state(q.get("tunnel")))
            if u.path == "/healthz":
                return self._send(200, {"ok": True})
        except CFError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/api/save":
                return self._send(200, upsert(body.get("tunnel"), body.get("subdomain"), body.get("target"),
                                              bool(body.get("noTLSVerify")), body.get("oldHostname"),
                                              body.get("protect")))
            if self.path == "/api/protect":
                return self._send(200, set_protection(body.get("hostname", ""), bool(body.get("on"))))
            if self.path == "/api/emails":
                return self._send(200, set_emails(body.get("emails") or []))
            if self.path == "/api/remove":
                return self._send(200, remove(body.get("tunnel"), body.get("hostname")))
        except CFError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "7590"))
    print(f"Tunnel Manager on :{port} for {DOMAIN}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
