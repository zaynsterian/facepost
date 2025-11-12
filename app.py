import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify, abort
from supabase import create_client

# ---- ENV ----
def _get_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v

SUPABASE_URL = _get_env("SUPABASE_URL")                 # ex: https://xxxx.supabase.co
SUPABASE_SERVICE_KEY = _get_env("SUPABASE_SERVICE_KEY") # service_role key
ADMIN_API_KEY = _get_env("ADMIN_API_KEY")               # o cheie puternică setată pe Render

# ---- Clients ----
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
app = Flask(__name__)

# ---- Helpers ----
def require_admin():
    key = request.headers.get("X-Admin-Key")
    if key != ADMIN_API_KEY:
        abort(401, description="Unauthorized")

def now_utc():
    return datetime.now(timezone.utc)

# ---- Health ----
@app.get("/")
def root():
    return "Facepost API OK", 200

# ---- Issue/renew license (manual după plată) ----
@app.post("/issue")
def issue():
    """
    Body: { "email": "...", "days": 30, "max_devices": 1 }
    Creează sau reînnoiește licența (active=true, expiră peste 'days' zile).
    """
    require_admin()
    p = request.json or {}
    email = (p.get("email") or "").strip().lower()
    days = int(p.get("days") or 30)
    max_devices = int(p.get("max_devices") or 1)
    if not email:
        return jsonify({"status": "error", "message": "missing email"}), 400

    # upsert user
    u = supabase.table("app_users").select("id").eq("email", email).execute().data
    if u:
        user_id = u[0]["id"]
    else:
        user_id = supabase.table("app_users").insert({"email": email}).execute().data[0]["id"]

    # upsert license
    expires_at = (now_utc() + timedelta(days=days)).isoformat()
    existing = supabase.table("licenses").select("*").eq("app_user_id", user_id).execute().data
    if existing:
        lic_id = existing[0]["id"]
        supabase.table("licenses").update({
            "active": True,
            "max_devices": max_devices,
            "expires_at": expires_at
        }).eq("id", lic_id).execute()
    else:
        key = f"FDT-{secrets.token_urlsafe(12).upper()}"
        lic_id = supabase.table("licenses").insert({
            "app_user_id": user_id,
            "license_key": key,
            "active": True,
            "max_devices": max_devices,
            "expires_at": expires_at
        }).execute().data[0]["id"]

    return jsonify({"status": "ok", "email": email, "license_id": lic_id, "expires_at": expires_at})

# ---- Suspend license (neplată) ----
@app.post("/suspend")
def suspend():
    """
    Body: { "email": "..." }
    Setează active=false pentru licența userului.
    """
    require_admin()
    p = request.json or {}
    email = (p.get("email") or "").strip().lower()
    if not email:
        return jsonify({"status": "error", "message": "missing email"}), 400

    u = supabase.table("app_users").select("id").eq("email", email).execute().data
    if not u:
        return jsonify({"status": "not_found"}), 200

    user_id = u[0]["id"]
    supabase.table("licenses").update({"active": False}).eq("app_user_id", user_id).execute()
    return jsonify({"status": "ok", "email": email})

# ---- Bind first device (prima pornire după activare) ----
@app.post("/bind")
def bind():
    """
    Body: { "email": "...", "fingerprint": "..." }
    Leagă device-ul dacă nu s-a depășit max_devices.
    """
    p = request.json or {}
    email = (p.get("email") or "").strip().lower()
    fingerprint = (p.get("fingerprint") or "").strip()
    if not email or not fingerprint:
        return jsonify({"status": "error", "message": "missing email/fingerprint"}), 400

    u = supabase.table("app_users").select("id").eq("email", email).execute().data
    if not u:
        return jsonify({"status": "not_found"}), 200
    user_id = u[0]["id"]

    lic_rows = supabase.table("licenses").select("*").eq("app_user_id", user_id).eq("active", True).execute().data
    if not lic_rows:
        return jsonify({"status": "inactive"}), 200
    lic = lic_rows[0]

    # limit devices
    devs = supabase.table("devices").select("id").eq("license_id", lic["id"]).execute().data
    if len(devs) >= (lic.get("max_devices") or 1):
        return jsonify({"status": "limit_reached"}), 200

    # already bound?
    exists = supabase.table("devices").select("id").eq("license_id", lic["id"]).eq("fingerprint", fingerprint).execute().data
    if exists:
        return jsonify({"status": "ok"}), 200

    supabase.table("devices").insert({"license_id": lic["id"], "fingerprint": fingerprint}).execute()
    return jsonify({"status": "ok"}), 200

# ---- Check (impune binding + expirare) ----
@app.post("/check")
def check():
    """
    Body: { "email": "...", "fingerprint": "..." }
    Returnează: ok / not_found / inactive / not_bound / expired
    """
    p = request.json or {}
    email = (p.get("email") or "").strip().lower()
    fingerprint = (p.get("fingerprint") or "").strip()
    if not email or not fingerprint:
        return jsonify({"status": "error", "message": "missing email/fingerprint"}), 400

    u = supabase.table("app_users").select("id").eq("email", email).execute().data
    if not u:
        return jsonify({"status": "not_found"}), 200
    user_id = u[0]["id"]

    lic_rows = supabase.table("licenses").select("*").eq("app_user_id", user_id).eq("active", True).execute().data
    if not lic_rows:
        return jsonify({"status": "inactive"}), 200
    lic = lic_rows[0]

    # binding obligatoriu
    dv = supabase.table("devices").select("id").eq("license_id", lic["id"]).eq("fingerprint", fingerprint).execute().data
    if not dv:
        return jsonify({"status": "not_bound"}), 200

    # expirare (dacă e setat)
    exp = lic.get("expires_at")
    if exp and datetime.fromisoformat(exp.replace("Z", "+00:00")) < now_utc():
        return jsonify({"status": "expired"}), 200

    return jsonify({"status": "ok", "expires_at": exp}), 200

# ---- Run ----
if __name__ == "__main__":
    app.run(port=8080, host="0.0.0.0")
