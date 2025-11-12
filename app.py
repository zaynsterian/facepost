import os
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, abort, session, redirect, url_for, render_template_string

# ------------------ Config ------------------
APP_NAME        = os.getenv("APP_NAME", "Facepost License Server")
ADMIN_API_KEY   = os.getenv("ADMIN_API_KEY", "CHANGE_ME_ADMIN_KEY")
ADMIN_PASS      = os.getenv("ADMIN_PASS", "CHANGE_ME_ADMIN_PASS")
SECRET_KEY      = os.getenv("FLASK_SECRET", os.urandom(24).hex())

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ------------------ In-memory storage ------------------
# Structura:
# LICENSES = {
#   "email@domeniu": {
#       "status": "ok" | "suspended",
#       "expires_at": "ISO-8601",
#       "license_id": "<uuid-like>",
#       "max_devices": 1,
#       "devices": {"FP1","FP2"}
#   },
# }
LICENSES: dict[str, dict] = {}


# ------------------ Utils ------------------
def now_utc():
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def parse_iso(s: str) -> datetime:
    # acceptă ISO cu sau fără offset 'Z'
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def normalize_email(e: str) -> str:
    return (e or "").strip().lower()

def ensure_admin_header():
    key = request.headers.get("X-Admin-Key", "")
    if not key or key != ADMIN_API_KEY:
        abort(401)

def admin_logged_in() -> bool:
    return session.get("admin_ok") is True


# ------------------ Core license ops ------------------
def issue_or_renew(email: str, days: int = 30, max_devices: int = 1) -> dict:
    email = normalize_email(email)
    if not email:
        raise ValueError("invalid email")

    rec = LICENSES.get(email)
    if rec is None:
        # create new
        expires = now_utc() + timedelta(days=days)
        rec = {
            "status": "ok",
            "expires_at": iso(expires),
            "license_id": os.urandom(16).hex(),
            "max_devices": max(1, int(max_devices or 1)),
            "devices": set()
        }
        LICENSES[email] = rec
    else:
        # renew/extend
        cur_exp = parse_iso(rec["expires_at"])
        base = cur_exp if cur_exp > now_utc() else now_utc()
        rec["expires_at"] = iso(base + timedelta(days=days))
        if max_devices:
            rec["max_devices"] = max(1, int(max_devices))
        rec.setdefault("devices", set())

    # serializare pentru răspuns
    return {
        "email": email,
        "status": rec["status"],
        "expires_at": rec["expires_at"],
        "license_id": rec["license_id"]
    }

def suspend(email: str) -> dict:
    email = normalize_email(email)
    rec = LICENSES.get(email)
    if rec is None:
        return {"email": email, "status": "not_found"}
    rec["status"] = "suspended"
    return {"email": email, "status": "ok"}

def bind_device(email: str, fingerprint: str) -> dict:
    email = normalize_email(email)
    fp = (fingerprint or "").strip()
    rec = LICENSES.get(email)
    if rec is None:
        return {"status": "not_found"}

    if rec.get("status") != "ok":
        return {"status": "suspended"}

    if parse_iso(rec["expires_at"]) < now_utc():
        return {"status": "expired"}

    devices: set = rec.setdefault("devices", set())
    if fp in devices:
        return {"status": "ok"}  # deja asociat

    if len(devices) >= int(rec.get("max_devices", 1)):
        return {"status": "max_devices"}

    devices.add(fp)
    return {"status": "ok"}

def check_status(email: str, fingerprint: str) -> dict:
    email = normalize_email(email)
    rec = LICENSES.get(email)
    if rec is None:
        return {"status": "not_found"}

    if rec.get("status") != "ok":
        return {"status": "suspended"}

    if parse_iso(rec["expires_at"]) < now_utc():
        return {"status": "expired"}

    devices: set = rec.setdefault("devices", set())
    if fingerprint and fingerprint not in devices:
        # dacă clientul n-a făcut bind, îl tratăm ca neautorizat
        return {"status": "unbound"}

    return {
        "status": "ok",
        "expires_at": rec["expires_at"]
    }


# ------------------ JSON API ------------------
@app.post("/issue")
def api_issue():
    ensure_admin_header()
    data = request.get_json(force=True, silent=True) or {}
    out = issue_or_renew(
        email=data.get("email", ""),
        days=int(data.get("days", 30)),
        max_devices=int(data.get("max_devices", 1)),
    )
    return jsonify(out)

@app.post("/suspend")
def api_suspend():
    ensure_admin_header()
    data = request.get_json(force=True, silent=True) or {}
    out = suspend(data.get("email", ""))
    return jsonify(out)

@app.post("/bind")
def api_bind():
    data = request.get_json(force=True, silent=True) or {}
    out = bind_device(
        email=data.get("email", ""),
        fingerprint=data.get("fingerprint", "")
    )
    return jsonify(out)

@app.post("/check")
def api_check():
    data = request.get_json(force=True, silent=True) or {}
    out = check_status(
        email=data.get("email", ""),
        fingerprint=data.get("fingerprint", "")
    )
    return jsonify(out)


# ------------------ Admin UI (HTMX) ------------------
TABLE_TEMPLATE = """
<table>
  <thead>
    <tr>
      <th>Email</th><th>Status</th><th>Expiră</th><th>Licență</th><th>Acțiuni</th>
    </tr>
  </thead>
  <tbody>
  {% for email, rec in rows %}
    <tr>
      <td>{{email}}</td>
      <td>{{rec.get('status','?')}}</td>
      <td>{{rec.get('expires_at','-')}}</td>
      <td style="font-size:12px">{{rec.get('license_id','-')}}</td>
      <td>
        <button class="button"
          hx-post="{{ url_for('admin_issue') }}"
          hx-vals='{"email":"{{email}}","days":30,"max_devices":{{rec.get("max_devices",1)}}}'
          hx-target="#table" hx-swap="outerHTML">Renew +30</button>
        <button class="button button-outline"
          hx-post="{{ url_for('admin_suspend') }}"
          hx-vals='{"email":"{{email}}"}'
          hx-target="#table" hx-swap="outerHTML">Suspend</button>
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>
"""

@app.get("/admin/login")
def admin_login():
    if admin_logged_in():
        return redirect(url_for("admin_home"))
    return render_template_string("""
<!doctype html><title>Login - {{app}}</title>
<link rel="stylesheet" href="https://unpkg.com/milligram/dist/milligram.min.css">
<div class="container" style="margin-top:4rem;max-width:520px">
  <h3>{{app}} — Admin Login</h3>
  <form method="post" action="{{url_for('admin_login_post')}}">
    <label>Parolă admin</label>
    <input type="password" name="pass" required>
    <button class="button-primary">Login</button>
  </form>
</div>
""", app=APP_NAME)

@app.post("/admin/login")
def admin_login_post():
    pwd = request.form.get("pass", "")
    if pwd and pwd == ADMIN_PASS:
        session["admin_ok"] = True
        return redirect(url_for("admin_home"))
    return "Unauthorized", 401

@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.get("/admin")
def admin_home():
    if not admin_logged_in():
        return redirect(url_for("admin_login"))

    rows = sorted(LICENSES.items(), key=lambda kv: kv[0])
    table_html = render_template_string(TABLE_TEMPLATE, rows=rows)

    return render_template_string("""
<!doctype html><title>{{app}}</title>
<script src="https://unpkg.com/htmx.org@2.0.2"></script>
<link rel="stylesheet" href="https://unpkg.com/milligram/dist/milligram.min.css">
<div class="container" style="margin-top:2rem">
  <div style="display:flex;justify-content:space-between;align-items:center">
    <h3>{{app}}</h3>
    <a class="button button-outline" href="{{url_for('admin_logout')}}">Logout</a>
  </div>

  <form id="createForm" hx-post="{{url_for('admin_issue')}}" hx-target="#table" hx-swap="outerHTML">
    <fieldset>
      <label>Email</label> <input type="email" name="email" required>
      <label>Zile</label> <input type="number" name="days" value="30" min="1" max="365">
      <label>Max devices</label> <input type="number" name="max_devices" value="1" min="1" max="10">
      <button class="button">Creează/Prelungește</button>
    </fieldset>
  </form>

  <div id="table">
    {{ table_html|safe }}
  </div>
</div>
""", app=APP_NAME, table_html=table_html), 200, {"Content-Type": "text/html; charset=utf-8"}

@app.post("/admin/issue")
def admin_issue():
    if not admin_logged_in():
        abort(401)

    payload = {
        "email": normalize_email(request.form.get("email", "")),
        "days": int(request.form.get("days", "30")),
        "max_devices": int(request.form.get("max_devices", "1")),
    }
    if not payload["email"]:
        return "invalid email", 400

    # folosim același cod ca API-ul, fără să mai facem request intern
    issue_or_renew(payload["email"], payload["days"], payload["max_devices"])

    rows = sorted(LICENSES.items(), key=lambda kv: kv[0])
    return render_template_string(TABLE_TEMPLATE, rows=rows), 200, {"Content-Type": "text/html; charset=utf-8"}

@app.post("/admin/suspend")
def admin_suspend():
    if not admin_logged_in():
        abort(401)

    email = normalize_email(request.form.get("email", ""))
    suspend(email)

    rows = sorted(LICENSES.items(), key=lambda kv: kv[0])
    return render_template_string(TABLE_TEMPLATE, rows=rows), 200, {"Content-Type": "text/html; charset=utf-8"}


# ------------------ health/home ------------------
@app.get("/")
def home():
    return jsonify({"app": APP_NAME, "ok": True})


# ------------------ Run ------------------
if __name__ == "__main__":
    # În producție Render pornește procesul; acest block e util local.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
