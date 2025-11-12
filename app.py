import os
from flask import Flask, request, jsonify
from supabase import create_client

# Env vars (le setezi pe Render)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

# Inițializează clientul Supabase (SERVICE key, nu anon)
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

app = Flask(__name__)

@app.get("/")
def root():
    return "Facepost API OK", 200

@app.post("/check")
def check():
    """
    Body JSON:
    {
      "email": "client@test.com",
      "fingerprint": "FP_WINDOWS_10_INTEL_123"
    }
    """
    p = request.json or {}
    email = (p.get("email") or "").strip().lower()
    fingerprint = (p.get("fingerprint") or "").strip()

    if not email or not fingerprint:
        return jsonify({"status":"error","message":"missing email/fingerprint"}), 400

    # 1) user
    u = supabase.table("app_users").select("id").eq("email", email).execute().data
    if not u:
        return jsonify({"status":"not_found"}), 200
    user_id = u[0]["id"]

    # 2) licență activă
    lic_rows = supabase.table("licenses").select("*").eq("app_user_id", user_id).eq("active", True).execute().data
    if not lic_rows:
        return jsonify({"status":"inactive"}), 200
    lic = lic_rows[0]

    # 3) (opțional acum) verificare binding device
    # Pentru Partea 1 o lăsăm permisiv (nu cerem binding).
    # Dacă vrei strict acum, decomentează mai jos:
    # dv = supabase.table("devices").select("id").eq("license_id", lic["id"]).eq("fingerprint", fingerprint).execute().data
    # if not dv:
    #     return jsonify({"status":"not_bound"}), 200

    # 4) (opțional) verificare expirare; o facem în partea 2
    return jsonify({"status":"ok","expires_at": lic.get("expires_at")}), 200

if __name__ == "__main__":
    app.run(port=8080, host="0.0.0.0")
