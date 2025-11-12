import os
import uuid
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, request, jsonify, session, redirect, url_for,
    render_template, abort
)
from supabase import create_client, Client

# ========= Config din ENV =========
APP_NAME               = os.getenv("APP_NAME", "Facepost")
SUPABASE_URL           = os.getenv("SUPABASE_URL") or ""
SUPABASE_SERVICE_KEY   = os.getenv("SUPABASE_SERVICE_KEY") or ""
SECRET_KEY             = os.getenv("SECRET_KEY", "change-me")
ADMIN_PASS             = os.getenv("ADMIN_PASS", "")          # pt login panou /admin
ADMIN_API_KEY          = os.getenv("ADMIN_API_KEY", "")       # pt rutele publice /issue, /suspend (folosite programatic)

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("Missing SUPABASE_URL / SUPABASE_SERVICE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
app = Flask(__name__)
app.secret_key = SECRET_KEY


# ========= Helpers =========
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def to_iso(dt: datetime) -> str:
    # păstrăm ISO cu offset +00:00
    return dt.isoformat()

def from_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)

def require_admin():
    if not session.get("admin_ok"):
        return redirect(url_for("admin_login"))
    return None

def _license_row(email: str):
    res = supabase.table("licenses").select("*").eq("email", email).single().execute()
    return res.data

def _bindings_count(email: str) -> int:
    r = supabase.table("bindings").select("fingerprint", count="exact").eq("email", email).execute()
    return r.count or 0


# ========= Business: issue/renew, suspend, bind, check =========
def issue_or_renew(email: str, days: int = 30, max_devices: int | None = None, notes: str | None = None):
    """Creează sau prelungește licența unui email. Returnează payload pt UI/API."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return {"status": "error", "error": "invalid_email"}, 400

    # citește licența existentă
    row = _license_row(email)
    if row:
        # renew
        current_exp = from_iso(row["expires_at"]) if row.get("expires_at") else now_utc()
        base = current_exp if current_exp > now_utc() else now_utc()
        new_exp = base + timedelta(days=max(days, 1))
        upd = {
            "status": "ok",
            "expires_at": to_iso(new_exp),
            "updated_at": now_utc().isoformat(),
        }
        if max_devices is not None:
            upd["max_devices"] = int(max_devices)
        if notes is not None:
            upd["notes"] = notes

        supabase.table("licenses").update(upd).eq("email", email).execute()
        lic_id = row.get("license_id") or ""
        return {
            "email": email,
            "expires_at": upd["expires_at"],
            "license_id": lic_id,
            "status": "ok",
        }, 200
    else:
        # create nou
        lic_id = uuid.uuid4().hex
        exp = now_utc() + timedelta(days=max(days, 1))
        data = {
            "email": email,
            "status": "ok",
            "expires_at": to_iso(exp),
            "license_id": lic_id,
            "max_devices": int(max_devices or 1),
            "notes": notes or "",
            "updated_at": now_utc().isoformat(),
        }
        supabase.table("licenses").insert(data).execute()
        return {
            "email": email,
            "expires_at": data["expires_at"],
            "license_id": data["license_id"],
            "status": "ok",
        }, 200


def suspend_license(email: str):
    email = (email or "").strip().lower()
    if not email:
        return {"status": "error", "error": "invalid_email"}, 400

    row = _license_row(email)
    if not row:
        return {"status": "error", "error": "not_found"}, 404

    supabase.table("licenses").update({
        "status": "suspended",
        "updated_at": now_utc().isoformat(),
    }).eq("email", email).execute()
    return {"email": email, "status": "ok"}, 200


def update_notes(email: str, notes: str):
    email = (email or "").strip().lower()
    if not email:
        return {"status": "error", "error": "invalid_email"}, 400
    supabase.table("licenses").update({
        "notes": notes or "",
        "updated_at": now_utc().isoformat(),
    }).eq("email", email).execute()
    return {"email": email, "status": "ok"}, 200


def bind_device(email: str, fingerprint: str):
    email = (email or "").strip().lower()
    fp = (fingerprint or "").strip()
    if not email or not fp:
        return {"status": "error", "error": "invalid_params"}, 400

    row = _license_row(email)
    if not row:
        return {"status": "error", "error": "no_license"}, 404
    if row.get("status") != "ok":
        return {"status": "error", "error": "suspended"}, 403
    if from_iso(row["expires_at"]) < now_utc():
        return {"status": "error", "error": "expired"}, 403

    # vezi câte device-uri sunt deja
    used = _bindings_count(email)
    maxd = int(row.get("max_devices") or 1)

    # dacă fingerprintul deja există, e ok idempotent
    exists = supabase.table("bindings").select("fingerprint").eq("email", email).eq("fingerprint", fp).execute()
    if exists.data:
        return {"status": "ok"}, 200

    if used >= maxd:
        return {"status": "error", "error": "max_devices"}, 403

    supabase.table("bindings").insert({"email": email, "fingerprint": fp}).execute()
    return {"status": "ok"}, 200


def check_license(email: str, fingerprint: str):
    email = (email or "").strip().lower()
    fp = (fingerprint or "").strip()
    if not email or not fp:
        return {"status": "error", "error": "invalid_params"}, 400

    row = _license_row(email)
    if not row:
        return {"status": "error", "error": "no_license"}, 404

    resp = {
        "email": email,
        "expires_at": row.get("expires_at"),
        "status": row.get("status", "unknown")
    }

    if row.get("status") != "ok":
        resp["status"] = "suspended"
        return resp, 200

    if from_iso(row["expires_at"]) < now_utc():
        resp["status"] = "expired"
        return resp, 200

    # device binding existent?
    ex = supabase.table("bindings").select("fingerprint").eq("email", email).eq("fingerprint", fp).execute()
    if ex.data:
        resp["status"] = "ok"
        return resp, 200

    # nu e încă bind-uit: verifică dacă mai e loc
    used = _bindings_count(email)
    maxd = int(row.get("max_devices") or 1)
    if used < maxd:
        # optional: auto-bind la check? (de obicei faci /bind separat)
        # aici doar raportăm că poate fi legat
        resp["status"] = "ok"
        return resp, 200
    else:
        resp["status"] = "max_devices"
        return resp, 200


# ========= Rute publice (programatice) cu X-Admin-Key =========
def check_admin_header():
    key = request.headers.get("X-Admin-Key", "")
    if not ADMIN_API_KEY or key != ADMIN_API_KEY:
        abort(401)

@app.post("/issue")
def http_issue():
    check_admin_header()
    p = request.get_json(force=True, silent=True) or {}
    email = p.get("email", "")
    days = int(p.get("days", 30))
    max_devices = p.get("max_devices")
    notes = p.get("notes")
    return issue_or_renew(email=email, days=days, max_devices=max_devices, notes=notes)

@app.post("/suspend")
def http_suspend():
    check_admin_header()
    p = request.get_json(force=True, silent=True) or {}
    email = p.get("email", "")
    return suspend_license(email)

@app.post("/bind")
def http_bind():
    # endpoint chemat de aplicația client (NU cere X-Admin-Key)
    p = request.get_json(force=True, silent=True) or {}
    email = p.get("email", "")
    fp = p.get("fingerprint", "")
    return bind_device(email, fp)

@app.post("/check")
def http_check():
    # endpoint chemat de aplicația client (NU cere X-Admin-Key)
    p = request.get_json(force=True, silent=True) or {}
    email = p.get("email", "")
    fp = p.get("fingerprint", "")
    return check_license(email, fp)


# ========= Panou Admin =========
@app.get("/")
def index():
    return "OK", 200

@app.get("/admin/login")
def admin_login():
    # simplu form inline (poți muta în template separat dacă vrei)
    return """
    <html><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/static/admin.css"></head>
    <body><div class="wrap">
      <div class="card"><h2>Login Admin</h2>
        <form method="post" action="/admin/login" class="grid" style="grid-template-columns: 1fr auto;">
          <input type="password" name="pass" placeholder="Admin password" required>
          <button class="btn primary" type="submit">Login</button>
        </form>
      </div>
    </div></body></html>
    """, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.post("/admin/login")
def admin_login_post():
    pwd = request.form.get("pass", "")
    if ADMIN_PASS and pwd == ADMIN_PASS:
        session["admin_ok"] = True
        return redirect(url_for("admin_home"))
    return "Unauthorized", 401

@app.post("/admin/logout")
def admin_logout():
    session.pop("admin_ok", None)
    return redirect(url_for("admin_login"))

@app.get("/admin")
def admin_home():
    guard = require_admin()
    if guard: return guard
    data = (
        supabase.table("licenses")
        .select("email,status,expires_at,license_id,max_devices,notes")
        .order("updated_at", desc=True)
        .limit(200)
        .execute()
    )
    rows = data.data or []
    return render_template("admin.html", rows=rows, title=APP_NAME)

# API interne panou (fără X-Admin-Key, protejate de sesiune)
@app.post("/admin/api/issue")
def admin_api_issue():
    guard = require_admin()
    if guard: return abort(401)
    p = request.get_json(force=True, silent=True) or {}
    email = p.get("email", "")
    days = int(p.get("days", 30))
    max_devices = p.get("max_devices")
    notes = p.get("notes")
    out, code = issue_or_renew(email=email, days=days, max_devices=max_devices, notes=notes)
    return jsonify(out), code

@app.post("/admin/api/suspend")
def admin_api_suspend():
    guard = require_admin()
    if guard: return abort(401)
    p = request.get_json(force=True, silent=True) or {}
    email = p.get("email", "")
    out, code = suspend_license(email)
    return jsonify(out), code

@app.post("/admin/api/notes")
def admin_api_notes():
    guard = require_admin()
    if guard: return abort(401)
    p = request.get_json(force=True, silent=True) or {}
    email = p.get("email", "")
    notes = p.get("notes", "")
    out, code = update_notes(email, notes)
    return jsonify(out), code


# ========= Run local =========
if __name__ == "__main__":
    # Pentru local dev
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), debug=True)
