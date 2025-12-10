import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from flask import Flask, jsonify, request, session, redirect, render_template_string
from supabase import create_client, Client
from updates_blueprint import updates_bp

# ------------------ Config ------------------
APP_NAME = os.environ.get("APP_NAME", "Facepost License Server")
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")  # pentru /issue,/renew,/suspend,/create_trial
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("SUPABASE_URL / SUPABASE_SERVICE_KEY lipsesc din env")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))

# CORS – permitem apeluri din site-ul public (Bolt)
FRONTEND_ORIGIN = os.environ.get(
    "FRONTEND_ORIGIN",
    "https://facepost-romanian-sa-n0gm.bolt.host",  # poți schimba sau lăsa "*"
)

@app.after_request
def add_cors_headers(resp):
    origin = request.headers.get("Origin")

    # dacă vrei să permiți doar origin-ul tău Bolt:
    if origin and origin == FRONTEND_ORIGIN:
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Vary"] = "Origin"
    # dacă vrei să fie complet deschis (nu e neapărat nevoie):
    # resp.headers["Access-Control-Allow-Origin"] = "*"

    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Key"
    return resp

# Blueprint pentru updates
app.register_blueprint(updates_bp)


# ------------------ Helpers ------------------
def _now():
    return datetime.now(timezone.utc)


def _json_error(msg, code=400):
    return jsonify({"error": msg}), code


def _require_admin_api(req):
    key = req.headers.get("X-Admin-Key")
    return key and key == (ADMIN_API_KEY or "")


def _require_admin():
    if not session.get("admin_ok"):
        return redirect("/admin/login")


def get_or_create_user(email: str) -> str:
    """Returnează app_users.id pentru email; îl creează dacă lipsește."""
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("email required")

    res = (
        supabase.table("app_users")
        .select("id")
        .eq("email", email)
        .maybe_single()
        .execute()
    )
    row = getattr(res, "data", None)
    if row and row.get("id"):
        return row["id"]

    new_id = str(uuid4())
    supabase.table("app_users").insert({"id": new_id, "email": email}).execute()
    return new_id


def user_has_trial_license(user_id: str) -> bool:
    res = (
        supabase.table("licenses")
        .select("id")
        .eq("app_user_id", user_id)
        .eq("is_trial", True)
        .limit(1)
        .execute()
    )
    return bool(getattr(res, "data", None))


def create_trial_license_for_user(user_id: str):
    """Creează o licență trial de 14 zile (o singură dată)."""
    license_id = str(uuid4())
    license_key = uuid4().hex
    trial_expires = _now() + timedelta(days=14)

    payload = {
        "id": license_id,
        "app_user_id": user_id,
        "license_key": license_key,
        "active": True,
        "max_devices": 1,  # default 1 device
        "expires_at": trial_expires.isoformat(),
        "notes": "Free trial 14 days",
        "is_trial": True,
    }
    supabase.table("licenses").insert(payload).execute()
    return payload


def load_best_license_for_email(email: str):
    """
    Întoarce „cea mai bună” licență pentru email:
    - caută user
    - ia TOATE licențele lui
    - returnează prima licență activă și neexpirată,
      preferând una non-trial în fața uneia de trial.
    """
    email = (email or "").strip().lower()
    if not email:
        return None

    res_user = (
        supabase.table("app_users")
        .select("id")
        .eq("email", email)
        .maybe_single()
        .execute()
    )
    user = getattr(res_user, "data", None)
    if not user:
        return None

    user_id = user["id"]

    res_lics = (
        supabase.table("licenses")
        .select(
            "id, license_key, active, max_devices, expires_at, app_user_id, notes, is_trial, created_at"
        )
        .eq("app_user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )
    lics = getattr(res_lics, "data", []) or []
    if not lics:
        return None

    now = _now()

    def valid(lic):
        if not lic.get("active"):
            return False
        exp = lic.get("expires_at")
        if exp:
            try:
                exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
                if exp_dt < now:
                    return False
            except Exception:
                return False
        return True

    lics = [l for l in lics if valid(l)]
    if not lics:
        return None

    lics_sorted = sorted(
        lics, key=lambda l: (l.get("is_trial", False), l.get("expires_at", ""))
    )
    return lics_sorted[0]


def find_license_for_device(email: str, fingerprint: str):
    """
    Caută orice licență activă + neexpirată a userului
    pe care e legat device-ul (în tabela devices).
    """
    email = (email or "").strip().lower()
    if not email or not fingerprint:
        return None

    res_user = (
        supabase.table("app_users")
        .select("id")
        .eq("email", email)
        .maybe_single()
        .execute()
    )
    user = getattr(res_user, "data", None)
    if not user:
        return None

    user_id = user["id"]

    res_lics = (
        supabase.table("licenses")
        .select("id, license_key, active, max_devices, expires_at, is_trial")
        .eq("app_user_id", user_id)
        .execute()
    )
    lics = getattr(res_lics, "data", []) or []
    if not lics:
        return None

    lic_ids = [l["id"] for l in lics]

    res_dev = (
        supabase.table("devices")
        .select("license_id, fingerprint")
        .eq("fingerprint", fingerprint)
        .in_("license_id", lic_ids)
        .execute()
    )
    dev = getattr(res_dev, "data", None)
    if not dev:
        return None
    dev = dev[0]

    for l in lics:
        if l["id"] == dev["license_id"]:
            return l
    return None


# ------------------ Public/health ------------------
@app.get("/")
def home():
    return f"{APP_NAME} OK", 200

@app.route("/public_signup", methods=["POST", "OPTIONS"])
def public_signup():
    """
    Endpoint apelat de formularul de pe site (Bolt).
    ...
    """
    # Preflight CORS – browserul trimite OPTIONS înainte de POST
    if request.method == "OPTIONS":
        # răspuns gol, headers CORS sunt adăugați în after_request
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}

    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    accommodation_name = (data.get("accommodation_name") or "").strip()

    if not email:
        return _json_error("email required")

    # 1) user în app_users
    app_user_id = get_or_create_user(email)

    # 2) profil în client_profiles – upsert by app_user_id
    profile_payload = {
        "app_user_id": app_user_id,
        "first_name": first_name,
        "last_name": last_name,
        "phone": phone,
        "accommodation_name": accommodation_name,
    }

    try:
        supabase.table("client_profiles").upsert(
            profile_payload, on_conflict="app_user_id"
        ).execute()
    except Exception as e:
        print("[PUBLIC_SIGNUP] Eroare la upsert client_profiles:", e)
        # nu blocăm tot flow-ul dacă profilul e problematic
        # doar raportăm mai jos în răspuns
        profile_error = True
    else:
        profile_error = False

    # 3) licență
    lic = load_best_license_for_email(email)
    created_trial = False

    if not lic:
        # nu avem licență activă; vedem dacă mai poate primi trial
        if not user_has_trial_license(app_user_id):
            lic = create_trial_license_for_user(app_user_id)
            created_trial = True
        else:
            lic = None

    resp = {
        "status": "ok",
        "email": email,
        "created_trial": created_trial,
        "profile_saved": not profile_error,
    }

    if lic:
        resp.update(
            {
                "license_id": lic["id"],
                "license_key": lic["license_key"],
                "expires_at": lic.get("expires_at"),
                "max_devices": lic.get("max_devices"),
                "is_trial": lic.get("is_trial", False),
            }
        )
    else:
        resp["license"] = None

    return jsonify(resp), 200

# ------------------ License API (admin: issue / renew / suspend) ------------------

@app.post("/issue")
def issue_license():
    """
    Creează / reînnoiește licență plătită (admin API).
    Body: email, days, max_devices(optional), notes(optional)
    """
    if not _require_admin_api(request):
        return _json_error("Unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    days = int(data.get("days") or 30)
    max_devices = int(data.get("max_devices") or 1)  # default 1
    notes = (data.get("notes") or "").strip()

    if not email:
        return _json_error("email required")

    app_user_id = get_or_create_user(email)

    # căutăm o licență plătită existentă
    res_lic = (
        supabase.table("licenses")
        .select("id, expires_at, active, license_key, max_devices, is_trial")
        .eq("app_user_id", app_user_id)
        .eq("is_trial", False)
        .maybe_single()
        .execute()
    )
    lic = getattr(res_lic, "data", None)

    new_expires = _now() + timedelta(days=days)
    payload = {
        "active": True,
        "max_devices": max(1, max_devices),  # minim 1
        "expires_at": new_expires.isoformat(),
        "notes": notes,
        "is_trial": False,
    }

    if lic:  # renew/extend
        supabase.table("licenses").update(payload).eq("id", lic["id"]).execute()
        license_id = lic["id"]
        license_key = lic["license_key"]
    else:  # create new
        license_id = str(uuid4())
        license_key = uuid4().hex
        payload.update(
            {"id": license_id, "app_user_id": app_user_id, "license_key": license_key}
        )
        supabase.table("licenses").insert(payload).execute()

    return jsonify(
        {
            "status": "ok",
            "email": email,
            "license_id": license_id,
            "license_key": license_key,
            "expires_at": new_expires.isoformat(),
            "max_devices": payload["max_devices"],
        }
    ), 200


@app.post("/renew")
def renew():
    if not _require_admin_api(request):
        return _json_error("Unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    days = int(data.get("days") or 30)
    max_devices = int(data.get("max_devices") or 1)  # default 1
    notes = (data.get("notes") or "").strip()

    if not email:
        return _json_error("email required")

    res_user = (
        supabase.table("app_users")
        .select("id")
        .eq("email", email)
        .maybe_single()
        .execute()
    )
    user = getattr(res_user, "data", None)
    if not user:
        return _json_error("user not found", 404)

    app_user_id = user["id"]

    res_lic = (
        supabase.table("licenses")
        .select("id, expires_at, active, license_key, max_devices, is_trial")
        .eq("app_user_id", app_user_id)
        .eq("is_trial", False)
        .maybe_single()
        .execute()
    )
    lic = getattr(res_lic, "data", None)
    if not lic:
        return _json_error("paid license not found", 404)

    now = _now()
    current_exp = lic.get("expires_at")
    if current_exp:
        try:
            exp_dt = datetime.fromisoformat(current_exp.replace("Z", "+00:00"))
        except Exception:
            exp_dt = now
    else:
        exp_dt = now

    base = exp_dt if exp_dt > now else now
    new_exp = base + timedelta(days=days)

    payload = {
        "active": True,
        "max_devices": max(1, max_devices),  # minim 1
        "expires_at": new_exp.isoformat(),
        "notes": notes,
        "is_trial": False,
    }

    supabase.table("licenses").update(payload).eq("id", lic["id"]).execute()

    return jsonify(
        {
            "status": "ok",
            "email": email,
            "license_id": lic["id"],
            "license_key": lic["license_key"],
            "expires_at": new_exp.isoformat(),
            "max_devices": payload["max_devices"],
            "is_trial": False,
        }
    ), 200


@app.post("/suspend")
def suspend():
    if not _require_admin_api(request):
        return _json_error("Unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return _json_error("email required")

    res_user = (
        supabase.table("app_users")
        .select("id")
        .eq("email", email)
        .maybe_single()
        .execute()
    )
    user = getattr(res_user, "data", None)
    if not user:
        return _json_error("user not found", 404)

    app_user_id = user["id"]

    supabase.table("licenses").update({"active": False}).eq(
        "app_user_id", app_user_id
    ).execute()
    return jsonify({"status": "ok"}), 200


@app.post("/trial")
def create_trial():
    """Admin API: forțează crearea unei licențe trial de 14 zile, dacă nu există."""
    if not _require_admin_api(request):
        return _json_error("Unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return _json_error("email required")

    user_id = get_or_create_user(email)

    if user_has_trial_license(user_id):
        return _json_error("Trial deja folosit pentru acest user.", 409)

    lic = create_trial_license_for_user(user_id)
    return jsonify(
        {
            "status": "ok",
            "email": email,
            "license_id": lic["id"],
            "license_key": lic["license_key"],
            "expires_at": lic["expires_at"],
            "max_devices": lic["max_devices"],
            "is_trial": True,
        }
    ), 200


# ------------------ Client API (/bind, /check) ------------------

@app.post("/bind")
def bind_device():
    """
    1) Găsește / creează user pentru email
    2) Caută licență activă pentru email:
       - dacă există → o folosește
       - dacă nu există → dacă nu a avut trial → creează trial 14 zile
                           altfel → eroare „trial deja folosit”
    3) Leagă fingerprint-ul de licență (devices).
    """
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    fingerprint = (data.get("fingerprint") or "").strip()

    if not email or not fingerprint:
        return _json_error("email and fingerprint required")

    app_user_id = get_or_create_user(email)
    lic = load_best_license_for_email(email)

    if not lic:
        if user_has_trial_license(app_user_id):
            return _json_error(
                "Free trial deja folosit. Te rugăm să cumperi o licență.", 403
            )
        lic = create_trial_license_for_user(app_user_id)

    if not lic.get("active"):
        return _json_error("license inactive", 403)

    expires_at = lic.get("expires_at")
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp_dt < _now():
                return _json_error("license expired", 403)
        except Exception:
            return _json_error("expires_at invalid", 500)

    res_dev = (
        supabase.table("devices")
        .select("id, fingerprint")
        .eq("license_id", lic["id"])
        .execute()
    )
    devs = getattr(res_dev, "data", []) or []
    fset = {d["fingerprint"] for d in devs}
    if fingerprint in fset:
        return jsonify({"status": "ok"})  # deja legat

    if len(fset) >= int(lic.get("max_devices") or 1):
        return _json_error("device limit reached", 403)

    supabase.table("devices").insert(
        {"id": str(uuid4()), "license_id": lic["id"], "fingerprint": fingerprint}
    ).execute()
    return jsonify({"status": "ok"}), 200


@app.post("/check")
def check_device():
    """
    Verifică licența pentru email + fingerprint.

    Comportament:
      - dacă există o licență activă & neexpirată pe care e deja legat device-ul → status "ok"
      - dacă există o altă licență activă & neexpirată a aceluiași user pe care e legat device-ul → status "ok" + note
      - dacă există licență activă & neexpirată dar device-ul NU este legat și mai e loc → status "unbound"
      - dacă există doar licențe expirate sau suspendate → status "expired" sau "inactive"
      - dacă nu există nicio licență pentru email → eroare 404 "license not found"
      - dacă licența activă e plină ca număr de device-uri → eroare 403 "device limit reached"
    """
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    fingerprint = (data.get("fingerprint") or "").strip()

    if not email or not fingerprint:
        return _json_error("email and fingerprint required")

    # 1) Găsim userul
    res_user = (
        supabase.table("app_users")
        .select("id")
        .eq("email", email)
        .maybe_single()
        .execute()
    )
    user = getattr(res_user, "data", None)
    if not user:
        # niciun user => nici licență
        return _json_error("license not found", 404)

    user_id = user["id"]

    # 2) Luăm toate licențele userului
    res_lics = (
        supabase.table("licenses")
        .select(
            "id, license_key, active, max_devices, expires_at, app_user_id, notes, is_trial, created_at"
        )
        .eq("app_user_id", user_id)
        .execute()
    )
    lics = getattr(res_lics, "data", []) or []
    if not lics:
        return _json_error("license not found", 404)

    now = _now()

    def is_valid(lic):
        if not lic.get("active"):
            return False
        exp = lic.get("expires_at")
        if exp:
            try:
                exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            except Exception:
                return False
            if exp_dt < now:
                return False
        return True

    valid_lics = [l for l in lics if is_valid(l)]

    if not valid_lics:
        # Avem licențe dar niciuna validă acum → fie sunt expirate, fie suspendate
        # Determinăm un status agregat pentru UI
        any_active_flag = any(l.get("active") for l in lics)
        if any_active_flag:
            agg_status = "expired"
        else:
            agg_status = "inactive"

        # Luăm ultima licență (după expires_at / created_at) doar pentru afișare
        def _sort_key(lic):
            return (
                lic.get("expires_at") or "",
                lic.get("created_at") or "",
            )

        last_lic = sorted(lics, key=_sort_key)[-1]
        return jsonify(
            {
                "status": agg_status,
                "expires_at": last_lic.get("expires_at"),
                "is_trial": last_lic.get("is_trial", False),
            }
        ), 200

    # Alegem "cea mai bună" licență validă, preferând non-trial
    lic = sorted(
        valid_lics, key=lambda l: (l.get("is_trial", False), l.get("expires_at") or "")
    )[0]

    # 3) dacă device-ul e legat deja la licența aleasă
    dev = (
        supabase.table("devices")
        .select("id")
        .eq("license_id", lic["id"])
        .eq("fingerprint", fingerprint)
        .maybe_single()
        .execute()
        .data
    )
    if dev:
        return jsonify(
            {
                "status": "ok",
                "expires_at": lic["expires_at"],
                "is_trial": lic.get("is_trial", False),
            }
        ), 200

    # 4) dacă device-ul era legat pe ALTA licență activă a aceluiași user → acceptăm aia
    alt_lic = find_license_for_device(email, fingerprint)
    if alt_lic:
        # find_license_for_device caută deja licențe active + neexpirate,
        # dar mai facem un sanity-check pe expirare
        alt_exp_str = alt_lic.get("expires_at")
        if alt_exp_str:
            try:
                alt_exp = datetime.fromisoformat(alt_exp_str.replace("Z", "+00:00"))
            except Exception:
                alt_exp = None
        else:
            alt_exp = None

        if alt_exp is None or alt_exp >= now:
            return jsonify(
                {
                    "status": "ok",
                    "expires_at": alt_lic.get("expires_at"),
                    "is_trial": alt_lic.get("is_trial", False),
                    "note": "device matched older license",
                }
            ), 200

    # 5) device-ul NU este legat nicăieri încă → verificăm locurile disponibile
    devs = (
        supabase.table("devices")
        .select("id, fingerprint")
        .eq("license_id", lic["id"])
        .execute()
        .data
    ) or []
    fingerprints = {d["fingerprint"] for d in devs}
    max_devices = int(lic.get("max_devices") or 1)

    if len(fingerprints) >= max_devices and fingerprint not in fingerprints:
        # licență plină → nu putem lega device-ul
        return _json_error("device limit reached", 403)

    # Există licență validă și mai este loc pentru device,
    # dar NU facem bind automat aici – doar semnalăm status "unbound"
    return jsonify(
        {
            "status": "unbound",
            "expires_at": lic["expires_at"],
            "is_trial": lic.get("is_trial", False),
            "max_devices": max_devices,
            "used_devices": len(fingerprints),
        }
    ), 200


@app.post("/log_run")
def log_run():
    """
    Primește log pentru fiecare RUN (email + fingerprint + group_urls + text + images_count).
    """
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    fingerprint = (data.get("fingerprint") or "").strip()

    if not email:
        return _json_error("email required")

    app_user_id = get_or_create_user(email)

    group_urls = data.get("group_urls") or ""
    post_text = data.get("post_text") or ""
    try:
        images_count = int(data.get("images_count") or 0)
    except Exception:
        images_count = 0

    payload = {
        "app_user_id": app_user_id,
        "email": email,
        "fingerprint": fingerprint,
        "group_urls": group_urls,
        "post_text": post_text,
        "images_count": images_count,
    }

    supabase.table("run_logs").insert(payload).execute()
    return jsonify({"status": "ok"}), 200


# ------------------ Admin Panel ------------------

@app.get("/admin/login")
def admin_login_page():
    if session.get("admin_ok"):
        return redirect("/admin")
    return render_template_string(
        """
<!doctype html>
<title>Login - {{app}}</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#f6f7fb;margin:0}
 .wrap{max-width:560px;margin:8vh auto;background:#fff;padding:26px 28px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.07)}
 h1{margin:0 0 18px;font-size:22px}
 input,button{font-size:16px;padding:12px 14px;border-radius:10px;border:1px solid #d8dbe2;width:100%}
 button{background:#7b4fe0;color:#fff;border:none;cursor:pointer}
 .row{margin:10px 0}
 .note{color:#889; font-size:13px;margin-top:12px}
</style>
<div class="wrap">
  <h1>{{app}} — Admin Login</h1>
  <form method="post" action="/admin/login">
    <div class="row"><input name="user" placeholder="User" autocomplete="username" /></div>
    <div class="row"><input name="pass" placeholder="Password" type="password" autocomplete="current-password" /></div>
    <div class="row"><button type="submit">Login</button></div>
  </form>
  <div class="note">Folosim sesiune simplă pe cookie; logout din /admin/logout.</div>
</div>
""",
        app=APP_NAME,
    )


@app.post("/admin/login")
def admin_login_action():
    user = (request.form.get("user") or "").strip()
    pw = (request.form.get("pass") or "").strip()
    if user == (ADMIN_USER or "admin") and pw == (ADMIN_PASS or "admin"):
        session["admin_ok"] = True
        return redirect("/admin")
    return "Invalid credentials", 403


@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect("/admin/login")


def _fetch_rows_for_admin():
    """
    Returnează o listă de licențe cu user & info, ordonată desc după created_at.
    """
    res = (
        supabase.table("licenses")
        .select(
            "id, license_key, active, max_devices, expires_at, app_user_id, notes, is_trial, created_at"
        )
        .order("created_at", desc=True)
        .limit(500)
        .execute()
    )
    lics = getattr(res, "data", []) or []
    if not lics:
        return []

    user_ids = list({l["app_user_id"] for l in lics if l.get("app_user_id")})
    if not user_ids:
        return []
    res_users = (
        supabase.table("app_users")
        .select("id, email")
        .in_("id", user_ids)
        .execute()
    )
    users = getattr(res_users, "data", []) or []
    email_map = {u["id"]: u["email"] for u in users}

    out = []
    for r in lics:
        email = email_map.get(r["app_user_id"], "??")
        out.append(
            {
                "email": email,
                "license_id": r["id"],
                "license_key": r["license_key"],
                "active": r["active"],
                "max_devices": r["max_devices"],
                "expires_at": r["expires_at"],
                "notes": r.get("notes") or "",
                "created_at": r.get("created_at"),
                "is_trial": r.get("is_trial", False),
            }
        )
    return out


@app.get("/admin")
def admin_home():
    _require_admin()
    rows = _fetch_rows_for_admin()
    return render_template_string(
        """
<!doctype html>
<title>{{app}}</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#f6f7fb;margin:0}
 header{display:flex;justify-content:space-between;align-items:center;padding:18px 26px;background:#fff;border-bottom:1px solid #e7e9f0}
 h1{font-size:22px;margin:0}
 .container{max-width:1100px;margin:18px auto;padding:0 18px}
 input,button{font-size:14px;padding:10px 12px;border-radius:10px;border:1px solid #d8dbe2}
 button{background:#7b4fe0;color:#fff;border:none;cursor:pointer}
 button.secondary{background:#edf0f8;color:#333;border:1px solid #dde1ea}
 table{width:100%;border-collapse:separate;border-spacing:0 8px}
 th,td{padding:10px 12px;background:#fff;border-top:1px solid #e9edf5;border-bottom:1px solid #e9edf5}
 th:first-child,td:first-child{border-left:1px solid #e9edf5;border-top-left-radius:10px;border-bottom-left-radius:10px}
 th:last-child,td:last-child{border-right:1px solid #e9edf5;border-top-right-radius:10px;border-bottom-right-radius:10px}
 .row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
 .grow{flex:1}
 .tag{font-size:12px;padding:4px 8px;border-radius:6px;background:#eef2ff;color:#334}
 .muted{color:#778}
 .note{font-size:12px;color:#667}
 .btn-sm{padding:8px 10px;font-size:13px;border-radius:8px}
</style>

<header>
  <h1>{{app}}</h1>
  <a href="/admin/logout"><button class="secondary">Logout</button></a>
</header>

<div class="container">
  <h3>Creează / Prelungește licență plătită</h3>
  <form id="issueForm" onsubmit="return doIssue(event)">
    <div class="row">
      <input class="grow" name="email" placeholder="Email client" required />
      <input style="width:120px" name="days" type="number" value="30" />
      <input style="width:140px" name="max_devices" type="number" value="1" />
      <input class="grow" name="notes" placeholder="Notițe (nume unitate etc.)" />
      <button type="submit">CREEAZĂ / PRELUNGEȘTE</button>
    </div>
  </form>

  <h3>Licențe existente</h3>
  <table>
    <thead>
      <tr>
        <th>Email</th>
        <th>Status</th>
        <th>Expiră</th>
        <th>Licență</th>
        <th>Notițe</th>
        <th style="width:320px">Acțiuni</th>
      </tr>
    </thead>
    <tbody>
      {% for r in rows %}
      <tr>
        <td><b>{{r.email}}</b><div class="muted">{{r.license_key}}</div></td>
        <td>
          {% if r.active %}
            <span class="tag">activ</span>
          {% else %}
            <span class="tag" style="background:#fff4e5;color:#7a4b00">suspendat</span>
          {% endif %}
          {% if r.is_trial %}
            <span class="tag" style="background:#e6fffa;color:#006d5b;margin-left:6px">trial</span>
          {% endif %}
        </td>
        <td class="muted">{{r.expires_at}}</td>
        <td class="muted">{{r.license_id}}</td>
        <td style="min-width:260px">
          <div style="display:flex;gap:8px">
            <input id="note-{{r.license_id}}" class="grow" value="{{r.notes|e}}" placeholder="Notițe..." />
            <button class="btn-sm secondary" onclick="saveNote('{{r.license_id}}')">Save</button>
          </div>
        </td>
        <td>
          <div class="row" style="margin:0">
            <button class="btn-sm" onclick="quickRenew('{{r.email}}', 30)">RENEW +30</button>
            <button class="btn-sm secondary" onclick="quickSuspend('{{r.email}}')">SUSPEND</button>
            <button class="btn-sm secondary" onclick="quickTrial('{{r.email}}')">ENABLE TRIAL 14</button>
            <button class="btn-sm secondary" onclick="viewLogs('{{r.email}}')">LOGS</button>
          </div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<script>
async function doIssue(e){
  e.preventDefault();
  const f = e.target;
  const body = {
    email: f.email.value.trim(),
    days: parseInt(f.days.value||30),
    max_devices: parseInt(f.max_devices.value||1),
    notes: f.notes.value||""
  };
  const r = await fetch('/issue', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-Admin-Key': '{{admin_key}}'},
    body: JSON.stringify(body)
  });
  if(r.ok){ location.reload(); }
  else { alert('Eroare la creare/renew'); }
}

async function quickRenew(email, days){
  const r = await fetch('/renew', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-Admin-Key': '{{admin_key}}'},
    body: JSON.stringify({email, days})
  });
  if(r.ok){ location.reload(); } else { alert('Eroare la renew'); }
}

async function quickSuspend(email){
  if(!confirm('Sigur suspend?')) return;
  const r = await fetch('/suspend', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-Admin-Key': '{{admin_key}}'},
    body: JSON.stringify({email})
  });
  if(r.ok){ location.reload(); } else { alert('Eroare la suspend'); }
}

async function quickTrial(email){
  const r = await fetch('/trial', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-Admin-Key': '{{admin_key}}'},
    body: JSON.stringify({email})
  });
  if(r.ok){ location.reload(); } else { alert('Trial error / deja folosit'); }
}

async function viewLogs(email){
  window.location.href = '/admin/logs?email=' + encodeURIComponent(email);
}

async function saveNote(license_id){
  const note = document.getElementById('note-'+license_id).value;
  const r = await fetch('/admin/set_note', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({license_id, note})
  });
  if(r.ok){ alert('Salvat!'); } else { alert('Eroare la salvare notă'); }
}
</script>
""",
        app=APP_NAME,
        rows=rows,
        admin_key=ADMIN_API_KEY or "",
    )


@app.get("/admin/logs")
def admin_logs():
    """Afișează logs de RUN pentru un anumit email."""
    _require_admin()
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return _json_error("email required")

    app_user_id = get_or_create_user(email)

    rows = (
        supabase.table("run_logs")
        .select("created_at, group_urls, post_text, images_count")
        .eq("app_user_id", app_user_id)
        .order("created_at", desc=True)
        .limit(300)
        .execute()
        .data
    ) or []

    return render_template_string(
        """<!doctype html>
<title>Logs - {{email}}</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#f6f7fb;margin:0}
 header{display:flex;justify-content:space-between;align-items:center;padding:18px 26px;background:#fff;border-bottom:1px solid #e7e9f0}
 h1{font-size:20px;margin:0}
 a.btn{padding:8px 12px;border-radius:8px;border:1px solid #d8dbe2;background:#edf0f8;color:#333;text-decoration:none}
 .container{max-width:1100px;margin:18px auto;padding:0 18px}
 table{width:100%;border-collapse:separate;border-spacing:0 8px}
 th,td{padding:8px 10px;background:#fff;border-top:1px solid #e9edf5;border-bottom:1px solid #e9edf5;font-size:13px;vertical-align:top}
 th:first-child,td:first-child{border-left:1px solid #e9edf5;border-top-left-radius:8px;border-bottom-left-radius:8px}
 th:last-child,td:last-child{border-right:1px solid #e9edf5;border-top-right-radius:8px;border-bottom-right-radius:8px}
 .muted{color:#667;font-size:12px}
 pre{white-space:pre-wrap;font-family:inherit;margin:0}
 .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace}
</style>

<header>
  <h1>Logs pentru {{email}}</h1>
  <a href="/admin" class="btn">Înapoi la admin</a>
</header>

<div class="container">
  {% if not rows %}
    <p class="muted">Nu există runde logate pentru acest user.</p>
  {% else %}
    <table>
      <thead>
        <tr>
          <th>Data</th>
          <th>Grupuri</th>
          <th>Text postare</th>
          <th>Imagini</th>
        </tr>
      </thead>
      <tbody>
      {% for r in rows %}
        <tr>
          <td class="mono">{{ r.created_at }}</td>
          <td><pre>{{ (r.group_urls or '')[:1000] }}</pre></td>
          <td><pre>{{ (r.post_text or '')[:1000] }}</pre></td>
          <td>{{ r.images_count or 0 }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  {% endif %}
</div>
""",
        email=email,
        rows=rows,
    )


@app.post("/admin/set_note")
def admin_set_note():
    _require_admin()
    data = request.get_json(force=True, silent=True) or {}
    license_id = data.get("license_id")
    note = (data.get("note") or "").strip()
    if not license_id:
        return _json_error("license_id required")

    supabase.table("licenses").update({"notes": note}).eq("id", license_id).execute()
    return jsonify({"status": "ok"}), 200


# --------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
