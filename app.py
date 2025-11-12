import os
import uuid
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, request, jsonify, abort,
    session, redirect, url_for, render_template_string
)

# ----------------- Config -----------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "dev-secret-change-me")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "CHANGE_ME")        # pentru /issue, /suspend
ADMIN_UI_PASSWORD = os.getenv("ADMIN_UI_PASSWORD", "admin123") # login la /admin
APP_NAME = "Facepost Admin"

# ----------------- In-memory storage (MVP) -----------------
# email -> dict(status, expires_at, license_id, max_devices, devices:set, updated_at)
LICENSES = {}

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    # ISO 8601, cu offset (ex: +00:00)
    return dt.isoformat(timespec="seconds")

def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)

def normalize_email(e: str) -> str:
    return (e or "").strip().lower()

def require_admin_header():
    hdr = request.headers.get("X-Admin-Key", "")
    if not hdr or hdr != ADMIN_API_KEY:
        abort(401)

def upsert_license(email: str, data: dict):
    rec = LICENSES.get(email, {
        "status": "ok",
        "expires_at": iso(now_utc()),
        "license_id": str(uuid.uuid4()),
        "max_devices": 1,
        "devices": set()
    })
    # merge
    for k, v in data.items():
        if k == "devices" and isinstance(v, (set, list)):
            rec["devices"] = set(v)
        else:
            rec[k] = v
    rec["updated_at"] = iso(now_utc())
    LICENSES[email] = rec
    return rec

def extend_days(current_exp_iso: str, days: int) -> str:
    base = parse_iso(current_exp_iso)
    if base < now_utc():
        base = now_utc()
    return iso(base + timedelta(days=days))

# ----------------- Health -----------------
@app.get("/")
def root():
    return "OK", 200

# ----------------- License: ISSUE/RENEW -----------------
@app.post("/issue")
def issue():
    require_admin_header()
    payload = request.get_json(silent=True) or {}
    email = normalize_email(payload.get("email"))
    days = int(payload.get("days", 30))
    max_devices = int(payload.get("max_devices", 1))

    if not email or days <= 0:
        return jsonify({"status": "error", "error": "invalid_input"}), 400

    # dacă există deja licență -> extinde; altfel creează
    existing = LICENSES.get(email)
    if existing:
        new_exp = extend_days(existing["expires_at"], days)
        rec = upsert_license(email, {
            "expires_at": new_exp,
            "status": "ok",
            "max_devices": max_devices or existing.get("max_devices", 1)
        })
    else:
        rec = upsert_license(email, {
            "license_id": str(uuid.uuid4()),
            "expires_at": iso(now_utc() + timedelta(days=days)),
            "status": "ok",
            "max_devices": max_devices,
            "devices": set()
        })

    return jsonify({
        "status": "ok",
        "email": email,
        "expires_at": rec["expires_at"],
        "license_id": rec["license_id"]
    })

# ----------------- License: SUSPEND -----------------
@app.post("/suspend")
def suspend():
    require_admin_header()
    payload = request.get_json(silent=True) or {}
    email = normalize_email(payload.get("email"))
    if not email:
        return jsonify({"status": "error", "error": "invalid_input"}), 400

    rec = LICENSES.get(email)
    if not rec:
        return jsonify({"status": "ok", "email": email})  # idempotent
    rec = upsert_license(email, {"status": "inactive"})
    return jsonify({"status": "ok", "email": email})

# ----------------- Device: BIND -----------------
@app.post("/bind")
def bind():
    payload = request.get_json(silent=True) or {}
    email = normalize_email(payload.get("email"))
    fingerprint = (payload.get("fingerprint") or "").strip()

    if not email or not fingerprint:
        return jsonify({"status": "error", "error": "invalid_input"}), 400

    rec = LICENSES.get(email)
    if not rec:
        return jsonify({"status": "denied", "error": "no_license"}), 403

    # status & expirare
    if rec.get("status") != "ok":
        return jsonify({"status": "denied", "error": "inactive"}), 403
    if parse_iso(rec["expires_at"]) <= now_utc():
        return jsonify({"status": "denied", "error": "expired"}), 403

    devices = rec.get("devices", set())
    if fingerprint in devices:
        return jsonify({"status": "ok"})  # deja legat

    if len(devices) >= int(rec.get("max_devices", 1)):
        return jsonify({"status": "denied", "error": "device_limit"}), 403

    devices.add(fingerprint)
    upsert_license(email, {"devices": devices})
    return jsonify({"status": "ok"})

# ----------------- Device/License: CHECK -----------------
@app.post("/check")
def check():
    payload = request.get_json(silent=True) or {}
    email = normalize_email(payload.get("email"))
    fingerprint = (payload.get("fingerprint") or "").strip()

    if not email or not fingerprint:
        return jsonify({"status": "error", "error": "invalid_input"}), 400

    rec = LICENSES.get(email)
    if not rec:
        return jsonify({"status": "denied", "error": "no_license"}), 403

    if rec.get("status") != "ok":
        return jsonify({"status": "denied", "error": "inactive"}), 403

    if parse_iso(rec["expires_at"]) <= now_utc():
        return jsonify({"status": "denied", "error": "expired"}), 403

    if fingerprint not in rec.get("devices", set()):
        return jsonify({"status": "denied", "error": "not_bound"}), 403

    return jsonify({"status": "ok", "expires_at": rec["expires_at"]})

# =========================================================
# ================ ADMIN PANEL (in-memory) ================
# =========================================================

def admin_logged_in() -> bool:
    return session.get("admin") is True

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == ADMIN_UI_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_home"))
        return "Wrong password", 401

    return render_template_string("""
<!doctype html><title>{{app}}</title>
<link rel="stylesheet" href="https://unpkg.com/milligram/dist/milligram.min.css">
<div class="container" style="margin-top:4rem; max-width:560px">
  <h3>{{app}} – Login</h3>
  <form method="post">
    <label>Parola</label>
    <input type="password" name="password" required>
    <button class="button">Login</button>
  </form>
</div>
""", app=APP_NAME)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

# template inline pt tabel (HTMX)
@app.context_processor
def inject_table_template():
    table_tpl = """
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
    return {"table.html": table_tpl}

@app.route("/admin")
def admin_home():
    if not admin_logged_in():
        return redirect(url_for("admin_login"))
    rows = sorted(LICENSES.items(), key=lambda kv: kv[0])
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
    {% include 'table.html' %}
  </div>
</div>
""", app=APP_NAME, rows=rows), 200, {"Content-Type": "text/html; charset=utf-8"}

# acțiuni admin – apelează intern /issue și /suspend
@app.post("/admin/issue")
def admin_issue():
    if not admin_logged_in(): abort(401)
    payload = {
        "email": normalize_email(request.form.get("email", "")),
        "days": int(request.form.get("days", "30")),
        "max_devices": int(request.form.get("max_devices", "1")),
    }
    if not payload["email"]:
        return "invalid email", 400
    # simulează call intern
    with app.test_request_context():
        with app.test_client() as c:
            rv = c.post("/issue", json=payload, headers={"X-Admin-Key": ADMIN_API_KEY})
            _ = rv.get_json()
    rows = sorted(LICENSES.items(), key=lambda kv: kv[0])
    return render_template_string("{% include 'table.html' %}", rows=rows)

@app.post("/admin/suspend")
def admin_suspend():
    if not admin_logged_in(): abort(401)
    email = normalize_email(request.form.get("email", ""))
    with app.test_request_context():
        with app.test_client() as c:
            rv = c.post("/suspend", json={"email": email}, headers={"X-Admin-Key": ADMIN_API_KEY})
            _ = rv.get_json()
    rows = sorted(LICENSES.items(), key=lambda kv: kv[0])
    return render_template_string("{% include 'table.html' %}", rows=rows)

# ----------------- Run (Render folosește gunicorn/uwsgi, dar local OK) -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), debug=False)
