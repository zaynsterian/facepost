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
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")  # pentru /issue,/renew,/suspend
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("SUPABASE_URL / SUPABASE_SERVICE_KEY lipsesc din env")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))
app.register_blueprint(updates_bp)

UTC = timezone.utc


# ------------------ Helpers ------------------
def _now():
    return datetime.now(UTC)


def _require_admin_api(req: request):
    key = req.headers.get("X-Admin-Key", "")
    if not key or key != ADMIN_API_KEY:
        return False
    return True


def _require_admin():
    if not session.get("admin_ok"):
        return redirect("/admin/login")


def _json_error(msg, code=400):
    return jsonify({"error": msg}), code


def get_or_create_user(email: str) -> str:
    """Returnează app_user.id pentru email; îl creează dacă lipsește."""
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("email required")

    row = (
        supabase.table("app_users")
        .select("id")
        .eq("email", email)
        .maybe_single()
        .execute()
        .data
    )
    if row and row.get("id"):
        return row["id"]

    new_id = str(uuid4())
    supabase.table("app_users").insert({"id": new_id, "email": email}).execute()
    return new_id


def load_license_for_email(email: str):
    """Întoarce licența dacă există pentru email (una per client)."""
    # Licența e în licenses, email-ul în app_users -> join în 2 pași
    user = (
        supabase.table("app_users")
        .select("id")
        .eq("email", email.strip().lower())
        .maybe_single()
        .execute()
        .data
    )
    if not user:
        return None

    lic = (
        supabase.table("licenses")
        .select(
            "id, license_key, active, max_devices, expires_at, app_user_id, notes"
        )
        .eq("app_user_id", user["id"])
        .maybe_single()
        .execute()
        .data
    )
    return lic


# ------------------ Public/health ------------------
@app.get("/")
def home():
    return f"{APP_NAME} OK", 200


# ------------------ License API (server-to-server) ------------------
@app.post("/issue")
def issue_license():
    """Creează / reînnoiește licență (admin API). Body: email, days, max_devices, notes?"""
    if not _require_admin_api(request):
        return _json_error("Unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    days = int(data.get("days") or 30)
    max_devices = int(data.get("max_devices") or 1)
    notes = (data.get("notes") or "").strip()

    if not email:
        return _json_error("email required")

    app_user_id = get_or_create_user(email)
    lic = (
        supabase.table("licenses")
        .select("id, expires_at, active, license_key, max_devices")
        .eq("app_user_id", app_user_id)
        .maybe_single()
        .execute()
        .data
    )

    new_expires = _now() + timedelta(days=days)
    payload = {
        "active": True,
        "max_devices": max(1, max_devices),
        "expires_at": new_expires.isoformat(),
        "notes": notes,
    }

    if lic:  # renew/extend
        supabase.table("licenses").update(payload).eq("id", lic["id"]).execute()
        license_id = lic["id"]
        license_key = lic["license_key"]
    else:  # create new
        license_id = str(uuid4())
        license_key = uuid4().hex
        payload.update(
            {
                "id": license_id,
                "app_user_id": app_user_id,
                "license_key": license_key,
            }
        )
        supabase.table("licenses").insert(payload).execute()

    return (
        jsonify(
            {
                "status": "ok",
                "email": email,
                "license_id": license_id,
                "license_key": license_key,
                "expires_at": new_expires.isoformat(),
            }
        ),
        200,
    )


@app.post("/renew")
def renew():
    if not _require_admin_api(request):
        return _json_error("Unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    days = int(data.get("days") or 30)
    if not email:
        return _json_error("email required")

    lic = load_license_for_email(email)
    if not lic:
        return _json_error("license not found", 404)

    base = lic.get("expires_at")
    base_dt = (
        datetime.fromisoformat(base.replace("Z", "+00:00"))
        if base
        else _now()
    )
    new_expires = max(base_dt, _now()) + timedelta(days=days)

    supabase.table("licenses").update(
        {"expires_at": new_expires.isoformat(), "active": True}
    ).eq("id", lic["id"]).execute()

    return jsonify({"status": "ok", "email": email, "expires_at": new_expires.isoformat()})


@app.post("/suspend")
def suspend():
    if not _require_admin_api(request):
        return _json_error("Unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return _json_error("email required")

    lic = load_license_for_email(email)
    if not lic:
        return _json_error("license not found", 404)

    supabase.table("licenses").update({"active": False}).eq("id", lic["id"]).execute()
    return jsonify({"status": "ok", "email": email})


# ------------------ Client API (/bind, /check) ------------------
@app.post("/bind")
def bind_device():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    fingerprint = (data.get("fingerprint") or "").strip()

    if not email or not fingerprint:
        return _json_error("email and fingerprint required")

    lic = load_license_for_email(email)
    if not lic:
        return _json_error("license not found", 404)

    # validează licența
    if not lic.get("active"):
        return _json_error("license inactive", 403)
    expires_at = datetime.fromisoformat(lic["expires_at"].replace("Z", "+00:00"))
    if expires_at < _now():
        return _json_error("license expired", 403)

    # câte device-uri legate?
    devs = (
        supabase.table("devices")
        .select("id, fingerprint")
        .eq("license_id", lic["id"])
        .execute()
        .data
    )
    fset = {d["fingerprint"] for d in devs}

    if fingerprint in fset:
        return jsonify({"status": "ok"})  # deja legat

    if len(fset) >= int(lic["max_devices"] or 1):
        return _json_error("device limit reached", 403)

    supabase.table("devices").insert(
        {"id": str(uuid4()), "license_id": lic["id"], "fingerprint": fingerprint}
    ).execute()

    return jsonify({"status": "ok"})


@app.post("/check")
def check_device():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    fingerprint = (data.get("fingerprint") or "").strip()

    if not email or not fingerprint:
        return _json_error("email and fingerprint required")

    lic = load_license_for_email(email)
    if not lic:
        return _json_error("license not found", 404)

    if not lic.get("active"):
        return jsonify({"status": "inactive", "expires_at": lic.get("expires_at")}), 200

    expires_at = datetime.fromisoformat(lic["expires_at"].replace("Z", "+00:00"))
    if expires_at < _now():
        return jsonify({"status": "expired", "expires_at": lic["expires_at"]}), 200

    # verifică dacă fingerprint-ul e legat
    dev = (
        supabase.table("devices")
        .select("id")
        .eq("license_id", lic["id"])
        .eq("fingerprint", fingerprint)
        .maybe_single()
        .execute()
        .data
    )
    if not dev:
        return jsonify({"status": "unbound", "expires_at": lic["expires_at"]}), 200

    return jsonify({"status": "ok", "expires_at": lic["expires_at"]}), 200


# ------------------ Admin Panel ------------------
@app.get("/admin/login")
def admin_login_page():
    if session.get("admin_ok"):
        return redirect("/admin")
    return render_template_string(
        """
<!doctype html>
<title>Login - {{app}}</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#f6f7fb;margin:0}
 .wrap{max-width:560px;margin:8vh auto;background:#fff;padding:28px 28px 34px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.07)}
 h1{margin:0 0 18px;font-size:22px}
 input,button{font-size:16px;padding:12px 14px;border-radius:10px;border:1px solid #d8dbe2;width:100%}
 button{background:#7b4fe0;color:#fff;border:none;cursor:pointer}
 button:hover{filter:brightness(.98)}
 .row{margin:10px 0}
 .note{color:#889; font-size:13px;margin-top:12px}
</style>
<div class="wrap">
  <h1>{{app}} — Admin Login</h1>
  <form method="post" action="/admin/login">
    <div class="row"><input name="user" placeholder="User" autocomplete="username" /></div>
    <div class="row"><input name="pass" placeholder="Password" type="password" autocomplete="current-password" /></div>
    <div class="row"><button type="submit">Login</button></div>
    <div class="note">Folosește credențialele din variabilele de mediu <b>ADMIN_USER</b> / <b>ADMIN_PASS</b>.</div>
  </form>
</div>
""",
        app=APP_NAME,
    )


@app.post("/admin/login")
def admin_login():
    user = request.form.get("user", "")
    pw = request.form.get("pass", "")
    if user == ADMIN_USER and pw == ADMIN_PASS:
        session["admin_ok"] = True
        return redirect("/admin")
    return _json_error("Unauthorized", 401)


@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect("/admin/login")


def _fetch_rows_for_admin():
    """Citește rândurile panoului din view; dacă lipsește, face join din cod."""
    try:
        data = (
            supabase.table("v_admin_licenses")
            .select(
                "email, license_id, license_key, active, max_devices, expires_at, notes, created_at"
            )
            .order("created_at", desc=True)
            .limit(500)
            .execute()
            .data
        )
        return data
    except Exception:
        # fallback join (în caz că nu ai creat view-ul)
        lics = (
            supabase.table("licenses")
            .select(
                "id, license_key, active, max_devices, expires_at, app_user_id, notes, created_at"
            )
            .order("created_at", desc=True)
            .limit(500)
            .execute()
            .data
        )
        ids = list({r["app_user_id"] for r in lics if r.get("app_user_id")})
        users = {}
        if ids:
            urows = (
                supabase.table("app_users")
                .select("id, email")
                .in_("id", ids)
                .execute()
                .data
            )
            users = {u["id"]: u["email"] for u in urows}
        out = []
        for r in lics:
            out.append(
                {
                    "email": users.get(r["app_user_id"], "(unknown)"),
                    "license_id": r["id"],
                    "license_key": r["license_key"],
                    "active": r["active"],
                    "max_devices": r["max_devices"],
                    "expires_at": r["expires_at"],
                    "notes": r.get("notes") or "",
                    "created_at": r.get("created_at"),
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
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#f6f7fb;margin:0}
 header{display:flex;justify-content:space-between;align-items:center;padding:18px 26px;background:#fff;border-bottom:1px solid #e7e9f0}
 h1{font-size:22px;margin:0}
 .container{max-width:1100px;margin:18px auto;padding:0 18px}
 input,button,select,textarea{font-size:14px;padding:10px 12px;border-radius:10px;border:1px solid #d8dbe2}
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
 .danger{background:#ffe7e6;color:#b20000;border:1px solid #ffd3d1}
</style>

<header>
  <h1>{{app}}</h1>
  <a href="/admin/logout"><button class="secondary">Logout</button></a>
</header>

<div class="container">
  <h3>Creare / Prelungire licență</h3>
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
        <th style="width:260px">Acțiuni</th>
      </tr>
    </thead>
    <tbody>
      {% for r in rows %}
      <tr>
        <td><b>{{r.email}}</b><div class="muted">{{r.license_key}}</div></td>
        <td>{% if r.active %}<span class="tag">activ</span>{% else %}<span class="tag" style="background:#fff4e5;color:#7a4b00">suspendat</span>{% endif %}</td>
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
          </div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <p class="note">Dacă nu vezi emailul, verifică view-ul <b>v_admin_licenses</b>.</p>
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


@app.post("/admin/set_note")
def admin_set_note():
    _require_admin()
    data = request.get_json(force=True, silent=True) or {}
    license_id = data.get("license_id")
    note = (data.get("note") or "").strip()
    if not license_id:
        return _json_error("license_id required")

    supabase.table("licenses").update({"notes": note}).eq("id", license_id).execute()
    return jsonify({"status": "ok"})
# ------------------ main ------------------
if __name__ == "__main__":
    # Pentru rulare locală (Render folosește gunicorn/WSGI implicit)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
