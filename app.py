import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from flask import Flask, jsonify, request, session, redirect, render_template_string
import requests
from supabase import create_client, Client
from updates_blueprint import updates_bp

# ------------------ Config ------------------
APP_NAME = os.environ.get("APP_NAME", "Facepost License Server")
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")  # pentru /issue,/renew,/suspend,/create_trial
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
TRIAL_DAYS = int(os.environ.get("TRIAL_DAYS", "30"))  # Număr de zile pentru free trial (se poate schimba și din env)
SETUP_DOWNLOAD_URL = "https://github.com/zaynsterian/facepost-client/releases/download/setup/FacepostSetup.exe"
GITHUB_REPO = "zaynsterian/facepost-client"
SETUP_ASSET_NAME = "FacepostSetup.exe"

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("SUPABASE_URL / SUPABASE_SERVICE_KEY lipsesc din env")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# ------------------ CRM DB (Supabase project separat) ------------------
CRM_SUPABASE_URL = os.environ.get("CRM_SUPABASE_URL")
CRM_SUPABASE_SERVICE_KEY = os.environ.get("CRM_SUPABASE_SERVICE_KEY")

CRM_ADMIN_USER = os.environ.get("CRM_ADMIN_USER", "admin")
CRM_ADMIN_PASS = os.environ.get("CRM_ADMIN_PASS", "admin")

CRM_LEADS_TABLE = os.environ.get("CRM_LEADS_TABLE", "leads")
CRM_PAYMENTS_TABLE = os.environ.get("CRM_PAYMENTS_TABLE", "payments")

CRM_LEAD_EMAIL_COL = os.environ.get("CRM_LEAD_EMAIL_COL", "email")
CRM_LEAD_CREATED_COL = os.environ.get("CRM_LEAD_CREATED_COL", "created_at")

CRM_PAYMENT_EMAIL_COL = os.environ.get("CRM_PAYMENT_EMAIL_COL", "user_email")
CRM_PAYMENT_CREATED_COL = os.environ.get("CRM_PAYMENT_CREATED_COL", "created_at")
CRM_PAYMENT_STATUS_COL = os.environ.get("CRM_PAYMENT_STATUS_COL", "payment_status")
CRM_PAYMENT_AMOUNT_COL = os.environ.get("CRM_PAYMENT_AMOUNT_COL", "amount")
CRM_PAYMENT_CURRENCY_COL = os.environ.get("CRM_PAYMENT_CURRENCY_COL", "currency")

crm_supabase: Client | None = None
if CRM_SUPABASE_URL and CRM_SUPABASE_SERVICE_KEY:
    crm_supabase = create_client(CRM_SUPABASE_URL, CRM_SUPABASE_SERVICE_KEY)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))

# CORS – permitem apeluri din site-ul public (Bolt)
FRONTEND_ORIGIN = os.environ.get(
    "FRONTEND_ORIGIN",
    "https://facepost.bolt.host,https://facepost.ro,https://www.facepost.ro", # poți schimba sau lăsa "*"
)

@app.after_request
def add_cors_headers(resp):
    origin = request.headers.get("Origin")

    # Poți pune mai multe origini în env, separate prin virgulă:
    # FRONTEND_ORIGIN="https://site.ro,https://*.bolt.host"
    allowed = [o.strip() for o in FRONTEND_ORIGIN.split(",") if o.strip()]

    def origin_allowed(o: str) -> bool:
        if not o:
            return False
        for a in allowed:
            if a == "*":
                return True
            if a.startswith("https://*.") and o.startswith(a.replace("*.", "")):
                return True
            if o == a:
                return True
        return False

    if origin and origin_allowed(origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Key"
        # activează doar dacă chiar folosești cookies/sessions cross-origin:
        # resp.headers["Access-Control-Allow-Credentials"] = "true"

    return resp

# Blueprint pentru updates
app.register_blueprint(updates_bp)


# ------------------ Helpers ------------------
def _now():
    return datetime.now(timezone.utc)


def _json_error(msg, code=400):
    return jsonify({"error": msg}), code


def _pick_any(d: dict, *keys, default=""):
    """Pick the first non-empty value from d for any of the provided keys."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        if not k:
            continue
        v = d.get(k)
        if v is None:
            continue
        # accept primitives only
        if isinstance(v, (str, int, float, bool)):
            s = str(v).strip()
            if s != "":
                return v
    return default


def _parse_bool(val, default=False):
    """Robust bool parser for JSON/form-ish values."""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "y", "on", "accepted", "agree", "consent"):
        return True
    if s in ("0", "false", "no", "n", "off", "declined", "disagree"):
        return False
    return default


def _split_full_name(full: str):
    full = (full or "").strip()
    if not full:
        return "", ""
    parts = [p for p in full.split() if p]
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], " ".join(parts[1:])


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


def create_trial_license_for_user(user_id: str, notes_override: str | None = None):
    """Creează o licență trial (o singură dată)."""
    license_id = str(uuid4())
    license_key = uuid4().hex
    trial_expires = _now() + timedelta(days=TRIAL_DAYS)

    notes_val = (notes_override or "").strip()
    if not notes_val:
        notes_val = f"Free trial {TRIAL_DAYS} days"

    payload = {
        "id": license_id,
        "app_user_id": user_id,
        "license_key": license_key,
        "active": True,
        "max_devices": 1,  # default 1 device
        "expires_at": trial_expires.isoformat(),
        "notes": notes_val,
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

    now = _now()

    def _lic_valid(x):
        if not x.get("active"):
            return False
        exp = x.get("expires_at")
        if exp:
            try:
                exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            except Exception:
                return False
            if exp_dt < now:
                return False
        return True

    lics = [l for l in lics if _lic_valid(l)]
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

def _iso_to_dt(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _best_license_status(licenses: list[dict]):
    """
    Returnează (best_license, status_str)
    status_str: PAID / TRIAL / EXPIRED / SUSPENDED / NO_LICENSE
    """
    if not licenses:
        return None, "NO_LICENSE"

    now = _now()

    def not_expired(lic):
        exp = _iso_to_dt(lic.get("expires_at"))
        return (exp is None) or (exp >= now)

    active_valid = [l for l in licenses if l.get("active") and not_expired(l)]
    if active_valid:
        paid = [l for l in active_valid if not l.get("is_trial")]
        pick = paid if paid else active_valid
        pick.sort(key=lambda x: (x.get("created_at") or ""), reverse=True)
        best = pick[0]
        return best, ("TRIAL" if best.get("is_trial") else "PAID")

    any_active = [l for l in licenses if l.get("active")]
    if any_active:
        any_active.sort(key=lambda x: (x.get("created_at") or ""), reverse=True)
        return any_active[0], "EXPIRED"

    licenses.sort(key=lambda x: (x.get("created_at") or ""), reverse=True)
    return licenses[0], "SUSPENDED"


def _fetch_facepost_hybrid_by_emails(emails: list[str]):
    """
    Batch fetch:
      - app_users: email -> user_id
      - client_profiles: user_id -> profile (accommodation_name etc.)
      - licenses: user_id -> best license + status
      - devices: best_license_id -> unique fingerprints count
    """
    emails = [e.strip().lower() for e in (emails or []) if e and e.strip()]
    if not emails:
        return {}, {}, {}, {}, {}

    # 1) app_users
    res_u = supabase.table("app_users").select("id,email").in_("email", emails).execute()
    users = res_u.data or []
    email_to_uid = {u["email"].lower(): u["id"] for u in users if u.get("email") and u.get("id")}
    user_ids = list(email_to_uid.values())
    if not user_ids:
        return email_to_uid, {}, {}, {}, {}

    # 2) client_profiles
    res_p = (
        supabase.table("client_profiles")
        .select("app_user_id,first_name,last_name,phone,accommodation_name")
        .in_("app_user_id", user_ids)
        .execute()
    )
    profiles = res_p.data or []
    uid_to_profile = {p["app_user_id"]: p for p in profiles if p.get("app_user_id")}

    # 3) licenses (luăm toate ca să putem decide PAID/TRIAL/EXPIRED/SUSPENDED)
    res_l = (
        supabase.table("licenses")
        .select("id,app_user_id,active,is_trial,expires_at,max_devices,license_key,created_at,notes")
        .in_("app_user_id", user_ids)
        .order("created_at", desc=True)
        .execute()
    )
    lics = res_l.data or []
    uid_to_all = {}
    for lic in lics:
        uid = lic.get("app_user_id")
        if uid:
            uid_to_all.setdefault(uid, []).append(lic)

    uid_to_best = {}
    uid_to_status = {}
    for uid, lst in uid_to_all.items():
        best, st = _best_license_status(lst)
        uid_to_best[uid] = best
        uid_to_status[uid] = st

    # 4) devices count pentru licențele best
    best_ids = [b["id"] for b in uid_to_best.values() if b and b.get("id")]
    lic_to_devcount = {}
    if best_ids:
        res_d = supabase.table("devices").select("license_id,fingerprint").in_("license_id", best_ids).execute()
        devs = res_d.data or []
        tmp = {}
        for d in devs:
            lid = d.get("license_id")
            fp = d.get("fingerprint")
            if lid and fp:
                tmp.setdefault(lid, set()).add(fp)
        lic_to_devcount = {lid: len(s) for lid, s in tmp.items()}

    return email_to_uid, uid_to_profile, uid_to_best, uid_to_status, lic_to_devcount

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

    # Acceptăm mai multe denumiri de câmpuri (Bolt / forme vechi / alte implementări)
    email = (str(_pick_any(data, "email", "user_email", "mail", default=""))).strip().lower()
    phone = (str(_pick_any(data, "phone", "telefon", "mobile", default=""))).strip()

    # Unele forme trimit un singur câmp "name"
    name_full = (str(_pick_any(data, "name", "full_name", default=""))).strip()

    first_name = (str(_pick_any(data, "first_name", "firstName", "firstname", default=""))).strip()
    last_name = (str(_pick_any(data, "last_name", "lastName", "lastname", default=""))).strip()
    if (not first_name and not last_name) and name_full:
        first_name, last_name = _split_full_name(name_full)

    accommodation_name = (str(_pick_any(data, "accommodation_name", "accommodationName", "company", "unitate", default=""))).strip()

    # Meta
    message = (str(_pick_any(data, "message", "msg", default=""))).strip()
    plan_interest = (str(_pick_any(data, "plan_interest", "planInterest", "plan", default=""))).strip()
    marketing_consent = _parse_bool(_pick_any(data, "marketing_consent", "marketingConsent", "consent", default=None), default=False)

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

    # dacă e trial și avem accommodation_name, punem numele unității în notes
    # (înlocuiește "Free trial 30 days" cu numele completat în formular)
    try:
        if lic and lic.get("is_trial") and accommodation_name:
            supabase.table("licenses").update(
                {"notes": accommodation_name}
            ).eq("id", lic["id"]).execute()
    except Exception as e:
        print("[PUBLIC_SIGNUP] Nu am putut actualiza notes:", e)

    # 4) CRM: scriem lead în proiectul CRM (robust: select -> update/insert)
    crm_ok = False
    crm_err = None

    if crm_supabase is not None:
        # IP real (primul din X-Forwarded-For)
        xff = request.headers.get("X-Forwarded-For", "") or ""
        ip = (xff.split(",")[0].strip() if xff else request.remote_addr)

        crm_payload = {
            # Evităm NULL în coloane care pot fi NOT NULL în schema ta
            "name": (f"{first_name} {last_name}".strip() or name_full or ""),
            "email": email,
            "phone": (phone or ""),
            "company": (accommodation_name or ""),
            "message": (message or ""),
            "plan_interest": (plan_interest or ""),
            "marketing_consent": bool(marketing_consent),
            "ip_address": (ip or ""),
            "user_agent": (request.headers.get("User-Agent") or ""),
        }

        try:
            # Încercăm întâi UPSERT (dacă ai UNIQUE pe email). Dacă nu ai, facem fallback.
            try:
                crm_supabase.table(CRM_LEADS_TABLE).upsert(
                    crm_payload, on_conflict=CRM_LEAD_EMAIL_COL
                ).execute()
                crm_ok = True
            except Exception as up_e:
                # Fallback clasic: select -> update/insert (nu necesită UNIQUE constraint)
                chk = (
                    crm_supabase.table(CRM_LEADS_TABLE)
                    .select("id")
                    .eq(CRM_LEAD_EMAIL_COL, email)
                    .limit(1)
                    .execute()
                )
                exists = bool(getattr(chk, "data", None))

                if exists:
                    crm_supabase.table(CRM_LEADS_TABLE).update(crm_payload).eq(
                        CRM_LEAD_EMAIL_COL, email
                    ).execute()
                else:
                    crm_supabase.table(CRM_LEADS_TABLE).insert(crm_payload).execute()

                crm_ok = True

        except Exception as e:

            crm_err = str(e)
            print(f"[PUBLIC_SIGNUP][CRM] FAIL email={email} host={request.host} origin={request.headers.get('Origin')} err={crm_err}")

    resp = {
        "status": "ok",
        "email": email,
        "created_trial": created_trial,
        "profile_saved": not profile_error,
        # adăugăm doar pentru test/debug (nu strică front-end-ul)
        "crm_ok": crm_ok,
    }

    resp["crm_ok"] = crm_ok
    if crm_err:
        resp["crm_error"] = crm_err

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
        resp["debug_host"] = request.host
        resp["debug_origin"] = request.headers.get("Origin")
        resp["debug_content_type"] = request.headers.get("Content-Type")

    return jsonify(resp), 200


@app.route("/check_email", methods=["POST", "OPTIONS"])
def check_email():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(silent=True) or {}

    def pick_email(obj):
        if not isinstance(obj, dict):
            return ""
        return (
            obj.get("email")
            or (obj.get("user") or {}).get("email")
            or (obj.get("data") or {}).get("email")
            or (obj.get("payload") or {}).get("email")
            or (obj.get("form") or {}).get("email")
            or ""
        )

    email = str(pick_email(data) or "").strip().lower()
    if not email:
        return jsonify({"exists": False, "error": "Missing email"}), 400

    try:
        q = supabase.table("app_users").select("id").eq("email", email).maybe_single().execute()
        qd = getattr(q, "data", None)
        exists = bool(qd and qd.get("id"))
        return jsonify({"exists": exists}), 200
    except Exception as e:
        print("[CHECK_EMAIL] Error:", e)
        return jsonify({"exists": False, "error": "Server error"}), 500

@app.get("/download")
def download():
    return redirect(SETUP_DOWNLOAD_URL, code=302)

@app.get("/crm/health")
def crm_health():
    redir = _require_crm_admin()
    if redir:
        return redir

    out = {
        "crm_url_set": bool(CRM_SUPABASE_URL),
        "crm_key_set": bool(CRM_SUPABASE_SERVICE_KEY),
        "crm_client_ready": crm_supabase is not None,
    }

    if crm_supabase is None:
        return jsonify(out), 200

    try:
        r = crm_supabase.table(CRM_LEADS_TABLE).select("id,email").limit(1).execute()
        out["leads_select_ok"] = True
        out["sample"] = r.data
    except Exception as e:
        out["leads_select_ok"] = False
        out["leads_error"] = str(e)

    return jsonify(out), 200
    
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
    """Admin API: forțează crearea unei licențe trial, dacă nu există."""
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

def _fingerprint_owner_email(fingerprint: str):
    """
    Returnează (email, license_id) pentru un fingerprint deja bind-uit, sau (None, None) dacă nu există.

    Anti-abuz: un device (fingerprint) nu poate fi bind-uit la un alt email fără intervenție admin.
    """
    fingerprint = (fingerprint or "").strip()
    if not fingerprint:
        return None, None

    try:
        # 1) găsim rapid un device cu fingerprint-ul respectiv
        res_dev = (
            supabase.table("devices")
            .select("license_id")
            .eq("fingerprint", fingerprint)
            .limit(1)
            .execute()
        )
        devs = getattr(res_dev, "data", []) or []
        if not devs:
            return None, None

        license_id = devs[0].get("license_id")
        if not license_id:
            return None, None

        # 2) luăm user-ul licenței
        res_lic = (
            supabase.table("licenses")
            .select("id, app_user_id")
            .eq("id", license_id)
            .maybe_single()
            .execute()
        )
        lic = getattr(res_lic, "data", None)
        if not lic:
            return None, license_id

        # 3) luăm email-ul user-ului
        res_user = (
            supabase.table("app_users")
            .select("email")
            .eq("id", lic.get("app_user_id"))
            .maybe_single()
            .execute()
        )
        u = getattr(res_user, "data", None)
        bound_email = (u.get("email") if u else None)
        if bound_email:
            bound_email = bound_email.strip().lower()

        return bound_email, license_id

    except Exception as e:
        print("[BIND] fingerprint owner lookup error:", e)
        return None, None

# ------------------ Client API (/bind, /check) ------------------

@app.post("/bind")
def bind_device():
    """
    1) Găsește / creează user pentru email
    2) Caută licență activă pentru email:
       - dacă există → o folosește
       - dacă nu există → dacă nu a avut trial → creează trial
                           altfel → eroare „trial deja folosit”
    3) Leagă fingerprint-ul de licență (devices).
    """
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    fingerprint = (data.get("fingerprint") or "").strip()

    if not email or not fingerprint:
        return _json_error("email and fingerprint required")

    # Anti-abuz: dacă fingerprint-ul este deja bind-uit la ALT email, nu permitem bind nou.
    bound_email, bound_license_id = _fingerprint_owner_email(fingerprint)
    if bound_license_id:
        if bound_email and bound_email != email:
            return _json_error(
                "Dispozitivul tău este legat de o altă licență. Dacă dorești ca dispozitivul să fie deconectat de licența actuală te rugăm să contactezi un administrator. Dacă dorești să îți reînnoiești licența intră pe www.facepost.ro",
                403,
            )

        # dacă e deja legat la același email, considerăm OK (nu mai facem un bind suplimentar)
        if bound_email == email:
            return jsonify({"status": "ok"}), 200

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
    res_dev = (
        supabase.table("devices")
        .select("id")
        .eq("license_id", lic["id"])
        .eq("fingerprint", fingerprint)
        .maybe_single()
        .execute()
    )
    dev = getattr(res_dev, "data", None)
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
    res_devs = (
        supabase.table("devices")
        .select("id, fingerprint")
        .eq("license_id", lic["id"])
        .execute()
    )
    devs = getattr(res_devs, "data", None) or []
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

# ------------------ CRM Panel (/crm) ------------------
def _require_crm_admin():
    if not session.get("crm_admin_ok"):
        return redirect("/crm/login")


def _crm_required():
    if crm_supabase is None:
        raise RuntimeError("CRM_SUPABASE_URL / CRM_SUPABASE_SERVICE_KEY lipsesc din env")


def _safe_ilike_or(query, cols, needle):
    parts = [f"{c}.ilike.%{needle}%" for c in cols]
    return query.or_(",".join(parts))


def _crm_fetch_leads(q: str | None, limit: int = 400):
    _crm_required()
    t = (
        crm_supabase.table(CRM_LEADS_TABLE)
        .select("id,name,email,phone,company,message,plan_interest,marketing_consent,created_at,ip_address,user_agent")
        .order(CRM_LEAD_CREATED_COL, desc=True)
        .limit(limit)
    )

    if q:
        needle = q.strip()
        # DOAR coloane care există la tine:
        cols = ["email", "phone", "name", "company"]
        t = _safe_ilike_or(t, cols, needle)

    res = t.execute()
    return getattr(res, "data", []) or []


def _crm_fetch_last_payments_by_email(emails: list[str], limit: int = 3000):
    _crm_required()
    emails = [e.strip() for e in (emails or []) if e and e.strip()]
    if not emails:
        return {}

    res = (
        crm_supabase.table(CRM_PAYMENTS_TABLE)
        .select("id,user_email,stripe_payment_id,stripe_customer_id,amount,currency,plan_type,payment_status,is_installment,installment_number,created_at,completed_at")
        .in_(CRM_PAYMENT_EMAIL_COL, emails)
        .order(CRM_PAYMENT_CREATED_COL, desc=True)
        .limit(limit)
        .execute()
    )
    rows = getattr(res, "data", []) or []

    out = {}
    for r in rows:
        em = (r.get(CRM_PAYMENT_EMAIL_COL) or "").strip().lower()
        if not em:
            continue
        if em in out:
            continue
        out[em] = r
    return out


def _crm_category_from_status(payment_status: str | None):
    st = (payment_status or "").strip().lower()

    paid = {"paid", "succeeded", "success", "completed", "complete"}
    incomplete = {"open", "pending", "processing", "requires_payment_method", "requires_action", "incomplete"}
    failed = {"failed", "canceled", "cancelled", "refunded"}

    if st in paid:
        return "paid"
    if st in incomplete:
        return "checkout_incomplete"
    if st in failed:
        return "failed"
    return "no_payment" if not st else f"status:{st}"


@app.get("/crm/login")
def crm_login_page():
    if session.get("crm_admin_ok"):
        return redirect("/crm")

    return render_template_string(
        """
<!doctype html>
<title>CRM Login</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#f6f7fb;margin:0}
 .wrap{max-width:560px;margin:8vh auto;background:#fff;padding:26px 28px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.07)}
 h1{margin:0 0 18px;font-size:22px}
 input,button{font-size:16px;padding:12px 14px;border-radius:10px;border:1px solid #d8dbe2;width:100%}
 button{background:#111827;color:#fff;border:none;cursor:pointer}
 .row{margin:10px 0}
 .note{color:#667;font-size:13px;margin-top:12px}
</style>
<div class="wrap">
  <h1>Facepost — CRM Login</h1>
  <form method="post" action="/crm/login">
    <div class="row"><input name="user" placeholder="User" autocomplete="username" /></div>
    <div class="row"><input name="pass" placeholder="Password" type="password" autocomplete="current-password" /></div>
    <div class="row"><button type="submit">Login</button></div>
  </form>
  <div class="note">Panel conectat la DB-ul de Leads/Stripe (proiect Supabase separat).</div>
</div>
"""
    )


@app.post("/crm/login")
def crm_login_action():
    user = (request.form.get("user") or "").strip()
    pw = (request.form.get("pass") or "").strip()
    if user == (CRM_ADMIN_USER or "admin") and pw == (CRM_ADMIN_PASS or "admin"):
        session["crm_admin_ok"] = True
        return redirect("/crm")
    return "Invalid credentials", 403


@app.get("/crm/logout")
def crm_logout():
    session.pop("crm_admin_ok", None)
    return redirect("/crm/login")


@app.get("/crm")
def crm_dashboard():
    redir = _require_crm_admin()
    if redir:
        return redir

    q = (request.args.get("q") or "").strip()

    leads = _crm_fetch_leads(q=q or None, limit=400)

    emails = []
    for l in leads:
        em = (l.get("email") or "").strip().lower()
        if em:
            emails.append(em)

    # ultima plată per email (din CRM DB)
    pay_map = _crm_fetch_last_payments_by_email(emails)

    # hybrid: profile + license + devices (din Facepost DB)
    email_to_uid, uid_to_profile, uid_to_best, uid_to_status, lic_to_devcount = _fetch_facepost_hybrid_by_emails(emails)

    rows = []
    for l in leads:
        em = (l.get("email") or "").strip().lower()
        p = pay_map.get(em)

        uid = email_to_uid.get(em)
        prof = uid_to_profile.get(uid) if uid else None
        best = uid_to_best.get(uid) if uid else None
        lic_status = uid_to_status.get(uid, "NO_LICENSE") if uid else "NO_LICENSE"

        # unitate: PRIMARY din client_profiles.accommodation_name, fallback leads.company
        accommodation = (prof.get("accommodation_name") if prof else None) or l.get("company") or "—"

        # nume: preferăm first+last din profile; fallback leads.name
        full_name = None
        if prof:
            fn = (prof.get("first_name") or "").strip()
            ln = (prof.get("last_name") or "").strip()
            full_name = (f"{fn} {ln}".strip() or None)
        display_name = full_name or l.get("name") or "—"

        # telefon: profile > lead
        display_phone = (prof.get("phone") if prof else None) or l.get("phone") or "—"

        # license meta
        bound = 0
        max_dev = None
        exp_at = None
        lic_key = None
        if best:
            lic_id = best.get("id")
            bound = lic_to_devcount.get(lic_id, 0)
            max_dev = best.get("max_devices")
            exp_at = best.get("expires_at")
            lic_key = best.get("license_key")

        rows.append({
            "lead": l,
            "pay": p,
            "category": _crm_category_from_status(p.get("payment_status") if p else None),

            "display_name": display_name,
            "display_phone": display_phone,
            "accommodation": accommodation,

            "license_status": lic_status,
            "license_key": lic_key,
            "license_expires_at": exp_at,
            "license_bound": bound,
            "license_max": max_dev,
        })

    return render_template_string(
        """
<!doctype html>
<title>Facepost CRM</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#f6f7fb;margin:0}
 header{display:flex;justify-content:space-between;align-items:center;padding:18px 26px;background:#fff;border-bottom:1px solid #e7e9f0}
 h1{font-size:20px;margin:0}
 .container{max-width:1500px;margin:18px auto;padding:0 18px}
 .row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
 input,button{font-size:13px;padding:10px 12px;border-radius:10px;border:1px solid #d8dbe2}
 button{background:#111827;color:#fff;border:none;cursor:pointer}
 a.btn{padding:8px 12px;border-radius:8px;border:1px solid #d8dbe2;background:#edf0f8;color:#333;text-decoration:none}
 table{width:100%;border-collapse:separate;border-spacing:0 8px}
 th,td{padding:10px 12px;background:#fff;border-top:1px solid #e9edf5;border-bottom:1px solid #e9edf5;font-size:13px;vertical-align:top}
 th:first-child,td:first-child{border-left:1px solid #e9edf5;border-top-left-radius:10px;border-bottom-left-radius:10px}
 th:last-child,td:last-child{border-right:1px solid #e9edf5;border-top-right-radius:10px;border-bottom-right-radius:10px}
 .muted{color:#778;font-size:12px}
 .client-name{font-weight:750;font-size:15.5px;line-height:1.15;color:#111827}
 .client-sub{color:#4b5563;font-size:13.8px;font-weight:650;line-height:1.35;margin-top:2px}
 .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace}
 .pill{display:inline-block;padding:4px 8px;border-radius:999px;font-size:12px;background:#eef2ff;color:#334}
 .pill.ok{background:#e9fbef;color:#156c2f}
 .pill.bad{background:#fff0f0;color:#a11}
 .wraptext{max-width:520px; white-space:normal; word-break:break-word;}
</style>

<header>
  <h1>Facepost — CRM</h1>
  <div style="display:flex;gap:10px">
    <a class="btn" href="/crm/logout">Logout</a>
  </div>
</header>

<div class="container">
  <form class="row" method="get" action="/crm">
    <input name="q" value="{{q}}" placeholder="Caută: email / phone / name / company" style="min-width:420px" />
    <button type="submit">Search</button>
    <a class="btn" href="/crm">Reset</a>
  </form>

  <table>
    <thead>
      <tr>
        <th>Client</th>
        <th>Licență</th>
        <th>Lead meta</th>
        <th>Message</th>
        <th>Ultima plată</th>
      </tr>
    </thead>
    <tbody>
      {% for r in rows %}
        {% set l = r.lead %}
        {% set p = r.pay %}
        <tr>
          <td>
            <div class="client-name">{{ r.display_name }}</div>
            <div class="client-sub mono">{{ r.display_phone }}</div>
            <div class="client-sub mono">{{ l.get('email') or '—' }}</div>
            <div class="client-sub">unitate: <span class="mono">{{ r.accommodation }}</span></div>
          </td>

          <td>
            {% if r.license_status == 'PAID' %}
              <span class="pill ok">PAID</span>
            {% elif r.license_status == 'TRIAL' %}
              <span class="pill">TRIAL</span>
            {% elif r.license_status in ['EXPIRED','SUSPENDED'] %}
              <span class="pill bad">{{ r.license_status }}</span>
            {% else %}
              <span class="pill">NO LICENSE</span>
            {% endif %}
            <div class="muted" style="margin-top:6px">expires: <span class="mono">{{ r.license_expires_at or '—' }}</span></div>
            <div class="muted">devices: <span class="mono">{{ r.license_bound }} / {{ r.license_max or '—' }}</span></div>
            {% if r.license_key %}
              <div class="muted mono" style="margin-top:6px">{{ r.license_key }}</div>
            {% endif %}
          </td>

          <td>
            <div class="muted">plan_interest: <span class="mono">{{ l.get('plan_interest') or '—' }}</span></div>
            <div class="muted">marketing: <span class="mono">{{ 'yes' if l.get('marketing_consent') else 'no' }}</span></div>
            <div class="muted">lead_created: <span class="mono">{{ l.get('created_at') }}</span></div>
            <div class="muted">ip: <span class="mono">{{ l.get('ip_address') or '—' }}</span></div>
          </td>

          <td class="wraptext">
            <div class="mono">{{ l.get('message') or '—' }}</div>
          </td>

          <td>
            {% if p %}
              <div>
                <span class="pill">{{ p.get('payment_status') or 'status?' }}</span>
                <span class="muted mono">{{ p.get('created_at') or '' }}</span>
              </div>
              <div class="muted" style="margin-top:6px">
                amount: <span class="mono">{{ p.get('amount') or '—' }} {{ (p.get('currency') or '')|upper }}</span>
              </div>
              <div class="muted">plan_type: <span class="mono">{{ p.get('plan_type') or '—' }}</span></div>
              <div class="muted">installment: <span class="mono">{{ 'yes' if p.get('is_installment') else 'no' }}{% if p.get('installment_number') %} #{{p.get('installment_number')}}{% endif %}</span></div>
              <div class="muted">completed_at: <span class="mono">{{ p.get('completed_at') or '—' }}</span></div>
            {% else %}
              <span class="pill">no payment</span>
            {% endif %}
          </td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<script>
  // “Real-time” simplu și stabil:
  setInterval(()=>window.location.reload(), 15000);
</script>
""",
        q=q,
        rows=rows,
    )

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
    redir = _require_admin()
    if redir:
        return redir

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
            <button class="btn-sm secondary" onclick="quickTrial('{{r.email}}')">
            ENABLE TRIAL {{trial_days}}
            </button>
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
        trial_days=TRIAL_DAYS,
    )


@app.get("/admin/logs")
def admin_logs():
    """Afișează logs de RUN pentru un anumit email."""
    redir = _require_admin()
    if redir:
        return redir

    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return _json_error("email required")

    app_user_id = get_or_create_user(email)

    res_logs = (
        supabase.table("run_logs")
        .select("created_at, group_urls, post_text, images_count")
        .eq("app_user_id", app_user_id)
        .order("created_at", desc=True)
        .limit(300)
        .execute()
    )
    rows = getattr(res_logs, "data", None) or []

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
    redir = _require_admin()
    if redir:
        return redir

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
