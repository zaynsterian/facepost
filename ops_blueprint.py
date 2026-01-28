"""ops_blueprint.py

Managed Maintenance / Support Console (separat de /admin).

Design goals:
  - acces doar cu user/parola + sesiune cookie
  - rate limit login (anti brute-force)
  - CSRF minimal pentru POST-uri
  - UI simplu (render_template_string) ca să nu depindă de templates

Necesită în env:
  OPS_USER
  OPS_PASS_HASH   (acceptă:
                    - Werkzeug generate_password_hash -> pbkdf2:sha256:... / scrypt:...
                    - bcrypt -> $2a$... / $2b$... / $2y$... )

Opțional:
  OPS_SESSION_HOURS (default 12)
  OPS_LOGIN_MAX_ATTEMPTS (default 8)
  OPS_LOGIN_WINDOW_SEC (default 900)
  OPS_IP_ALLOWLIST (CSV, ex: "1.2.3.4,5.6.7.8")
"""

from __future__ import annotations

import os
import time
import secrets
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, request, session, redirect, render_template_string
from werkzeug.security import check_password_hash

# bcrypt optional (install via requirements.txt: bcrypt>=4.2.0)
try:
    import bcrypt  # type: ignore
except Exception:
    bcrypt = None


def create_ops_blueprint(supabase):
    bp = Blueprint("ops", __name__)

    # ------------------ Config (din env) ------------------
    OPS_USER = (os.environ.get("OPS_USER") or "").strip()
    OPS_PASS_HASH = (os.environ.get("OPS_PASS_HASH") or "").strip()
    OPS_SESSION_HOURS = int((os.environ.get("OPS_SESSION_HOURS") or "12").strip())
    OPS_LOGIN_MAX_ATTEMPTS = int(os.environ.get("OPS_LOGIN_MAX_ATTEMPTS", "8"))
    OPS_LOGIN_WINDOW_SEC = int(os.environ.get("OPS_LOGIN_WINDOW_SEC", "900"))
    print("OPS env status:", {
    "OPS_USER_set": bool(OPS_USER),
    "OPS_PASS_HASH_set": bool(OPS_PASS_HASH),
    "OPS_HASH_TYPE": ("bcrypt" if OPS_PASS_HASH.startswith("$2") else "werkzeug/unknown"),
})
    OPS_IP_ALLOWLIST = [
        x.strip() for x in (os.environ.get("OPS_IP_ALLOWLIST", "") or "").split(",") if x.strip()
    ]
    
    # Login rate limit (in-memory; suficient pentru un panou intern)
    _login_attempts: dict[str, dict[str, Any]] = {}

    def _now_utc_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _client_ip() -> str:
        xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return xff or (request.remote_addr or "")

    def _ip_allowed() -> bool:
        if not OPS_IP_ALLOWLIST:
            return True
        ip = _client_ip()
        return ip in OPS_IP_ALLOWLIST

    def _rate_limit_ok(ip: str) -> tuple[bool, int]:
        """Return (ok, retry_after_sec)."""
        now = int(time.time())
        rec = _login_attempts.get(ip)
        if not rec:
            _login_attempts[ip] = {"count": 0, "start": now}
            return True, 0

        start = int(rec.get("start", now))
        count = int(rec.get("count", 0))

        # reset window
        if now - start > OPS_LOGIN_WINDOW_SEC:
            _login_attempts[ip] = {"count": 0, "start": now}
            return True, 0

        if count >= OPS_LOGIN_MAX_ATTEMPTS:
            retry = max(0, OPS_LOGIN_WINDOW_SEC - (now - start))
            return False, retry

        return True, 0

    def _rate_limit_bump(ip: str) -> None:
        now = int(time.time())
        rec = _login_attempts.get(ip)
        if not rec:
            _login_attempts[ip] = {"count": 1, "start": now}
            return
        start = int(rec.get("start", now))
        if now - start > OPS_LOGIN_WINDOW_SEC:
            _login_attempts[ip] = {"count": 1, "start": now}
            return
        rec["count"] = int(rec.get("count", 0)) + 1
        _login_attempts[ip] = rec

    def _ops_logged_in() -> bool:
        if not session.get("ops_ok"):
            return False
        exp = session.get("ops_exp")
        if not exp:
            return False
        try:
            if float(exp) < time.time():
                return False
        except Exception:
            return False
        return True

    def _require_ops():
        if not _ip_allowed():
            return "Forbidden", 403
        if not _ops_logged_in():
            return redirect("/ops/login")
        return None

    def _csrf_get() -> str:
        tok = session.get("ops_csrf")
        if not tok:
            tok = secrets.token_urlsafe(24)
            session["ops_csrf"] = tok
        return tok

    def _csrf_check(form_token: str | None) -> bool:
        if not form_token:
            return False
        return secrets.compare_digest(str(form_token), str(session.get("ops_csrf") or ""))

    def _verify_ops_password(stored_hash: str, password: str) -> bool:
        """
        Acceptă:
          - bcrypt hashes: $2a$..., $2b$..., $2y$...
          - werkzeug hashes: pbkdf2:sha256:... / scrypt:...

        Returnează True/False sau aruncă excepție dacă OPS_PASS_HASH e invalid / bcrypt lipsește.
        """
        h = (stored_hash or "").strip()
        if not h:
            return False

        # bcrypt
        if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
            if bcrypt is None:
                raise RuntimeError("bcrypt not installed (add bcrypt>=4.2.0 to requirements.txt)")
            return bool(bcrypt.checkpw(password.encode("utf-8"), h.encode("utf-8")))

        # werkzeug
        # check_password_hash poate arunca ValueError dacă formatul e greșit
        return bool(check_password_hash(h, password))

    # ------------------ DB helpers (Supabase) ------------------
    def _sb(table: str):
        return supabase.table(table)

    def _safe_single(res):
        data = getattr(res, "data", None)
        if isinstance(data, dict):
            return data
        if isinstance(data, list) and data:
            return data[0]
        return None

    def _get_state_by_support_code(code: str):
        code = (code or "").strip().upper()
        if not code:
            return None
        try:
            res = _sb("ops_client_state").select("*").eq("support_code", code).maybe_single().execute()
            return _safe_single(res)
        except Exception:
            return None

    def _get_state_by_email(email: str):
        email = (email or "").strip().lower()
        if not email:
            return None
        try:
            res = _sb("ops_client_state").select("*").eq("email", email).maybe_single().execute()
            return _safe_single(res)
        except Exception:
            return None

    def _upsert_state(payload: dict):
        # on_conflict pe support_code (unique)
        try:
            res = _sb("ops_client_state").upsert(payload, on_conflict="support_code").execute()
            return _safe_single(res)
        except Exception:
            return None

    def _audit(action: str, target_support_code: str = "", target_email: str = "", details: dict | None = None):
        try:
            _sb("ops_audit_log").insert(
                {
                    "actor": session.get("ops_user") or "",
                    "action": action,
                    "target_support_code": (target_support_code or "").upper(),
                    "target_email": (target_email or "").lower(),
                    "details": details or {},
                    "created_at": _now_utc_iso(),
                }
            ).execute()
        except Exception:
            pass

    def _list_recent(limit: int = 50):
        try:
            res = _sb("ops_client_state").select("*").order("updated_at", desc=True).limit(limit).execute()
            return getattr(res, "data", []) or []
        except Exception:
            return []

    # ------------------ Routes ------------------

    @bp.get("/login")
    def ops_login_page():
        if not _ip_allowed():
            return "Forbidden", 403
        if _ops_logged_in():
            return redirect("/ops")

        csrf = _csrf_get()
        return render_template_string(
            """
<!doctype html>
<title>Facepost — Ops Login</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#0b1020;margin:0;color:#e9ecf5}
 .wrap{max-width:520px;margin:10vh auto;background:#121a33;padding:26px 28px;border-radius:16px;box-shadow:0 18px 45px rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.06)}
 h1{margin:0 0 14px;font-size:20px}
 .muted{color:#aab2d6;font-size:13px;line-height:1.5}
 input,button{font-size:15px;padding:12px 14px;border-radius:12px;border:1px solid rgba(255,255,255,.12);width:100%;box-sizing:border-box}
 input{background:#0f1630;color:#e9ecf5}
 button{background:#6d5efc;color:#fff;border:none;cursor:pointer}
 .row{margin:10px 0}
 .err{color:#ffb4b4;margin-top:10px}
 a{color:#9ad0ff}
</style>
<div class="wrap">
  <h1>Facepost — Ops Console</h1>
  <div class="muted">Canal privat pentru mentenanță asistată (separat de <code>/admin</code>).</div>
  <form method="post" action="/ops/login">
    <input type="hidden" name="csrf" value="{{csrf}}" />
    <div class="row"><input name="user" placeholder="User" autocomplete="username" /></div>
    <div class="row"><input name="pass" placeholder="Password" type="password" autocomplete="current-password" /></div>
    <div class="row"><button type="submit">Login</button></div>
  </form>
  {% if err %}<div class="err">{{err}}</div>{% endif %}
  <div class="muted" style="margin-top:12px;">Sfat: activează și <b>OPS_IP_ALLOWLIST</b> sau acces prin VPN/Cloudflare pentru securitate extra.</div>
</div>
""",
            csrf=csrf,
            err=(request.args.get("err") or ""),
        )

    @bp.post("/login")
    def ops_login_action():
        if not _ip_allowed():
            return "Forbidden", 403

        ip = _client_ip()
        ok, retry = _rate_limit_ok(ip)
        if not ok:
            return f"Too many attempts. Retry in {retry}s", 429

        if not _csrf_check(request.form.get("csrf")):
            return redirect("/ops/login?err=CSRF%20invalid")

        user = (request.form.get("user") or "").strip()
        pw = (request.form.get("pass") or "").strip()

        # dacă nu ai setat env-urile, refuzăm login
        if not OPS_USER or not OPS_PASS_HASH:
            missing = []
            if not OPS_USER:
                missing.append("OPS_USER")
            if not OPS_PASS_HASH:
                missing.append("OPS_PASS_HASH")
            return f"OPS credentials not configured in env. Missing: {', '.join(missing)}", 500

        # IMPORTANT: dacă user nu corespunde, nu evaluăm parola (evităm work inutil)
        if user != OPS_USER:
            _rate_limit_bump(ip)
            return redirect("/ops/login?err=Invalid%20credentials")

        try:
            ok_pass = _verify_ops_password(OPS_PASS_HASH, pw)
        except Exception:
            # Hash invalid / bcrypt lipsește / altă problemă de verificare
            return (
                "OPS_PASS_HASH invalid format or bcrypt missing. "
                "If using bcrypt ($2a$...), add bcrypt>=4.2.0 to requirements.txt.",
                500,
            )

        if not ok_pass:
            _rate_limit_bump(ip)
            return redirect("/ops/login?err=Invalid%20credentials")

        session["ops_ok"] = True
        session["ops_user"] = user
        session["ops_exp"] = time.time() + (OPS_SESSION_HOURS * 3600)
        # regen csrf
        session["ops_csrf"] = secrets.token_urlsafe(24)
        return redirect("/ops")

    @bp.get("/logout")
    def ops_logout():
        # păstrăm restul sesiunii (ex: admin_ok) — ștergem doar cheile ops
        for k in ["ops_ok", "ops_user", "ops_exp", "ops_csrf"]:
            session.pop(k, None)
        return redirect("/ops/login")

    @bp.get("")
    @bp.get("/")
    def ops_dashboard():
        guard = _require_ops()
        if guard:
            return guard

        q = (request.args.get("q") or "").strip()
        row = None
        if q:
            if "@" in q:
                row = _get_state_by_email(q)
            else:
                row = _get_state_by_support_code(q)

        recent = _list_recent(50)
        csrf = _csrf_get()
        return render_template_string(
            """
<!doctype html>
<title>Facepost — Ops</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#0b1020;margin:0;color:#e9ecf5}
 header{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.08)}
 .brand{font-weight:700}
 a{color:#9ad0ff;text-decoration:none}
 .wrap{max-width:1100px;margin:18px auto;padding:0 18px}
 .card{background:#121a33;border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:16px;box-shadow:0 14px 40px rgba(0,0,0,.25)}
 .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
 input,select,button{font-size:14px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:#0f1630;color:#e9ecf5}
 button{background:#6d5efc;border:none;cursor:pointer}
 table{width:100%;border-collapse:collapse;margin-top:10px}
 th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left;font-size:13px}
 th{color:#aab2d6;font-weight:600}
 .pill{display:inline-block;padding:3px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.14);font-size:12px}
 .ok{background:rgba(60,200,120,.12)}
 .bad{background:rgba(255,90,90,.12)}
 .muted{color:#aab2d6}
 .warn{color:#ffd39a}
 code{background:rgba(255,255,255,.06);padding:2px 6px;border-radius:8px}
</style>
<header>
  <div class="brand">Facepost — Ops Console</div>
  <div class="muted">Logged in as <code>{{user}}</code> · <a href="/ops/logout">Logout</a></div>
</header>

<div class="wrap">
  <div class="card">
    <div class="row" style="justify-content:space-between;">
      <form class="row" method="get" action="/ops">
        <input name="q" value="{{q}}" placeholder="Caută după support_code sau email" style="min-width:320px" />
        <button type="submit">Search</button>
      </form>
      <div class="muted">Dacă nu există încă tabelele Supabase (<code>ops_client_state</code>), rulează SQL-ul de setup.</div>
    </div>

    {% if q and not row %}
      <div class="warn" style="margin-top:12px;">N-am găsit client pentru <code>{{q}}</code>. Poți crea un record manual:</div>
      <form class="row" method="post" action="/ops/client/upsert" style="margin-top:10px;">
        <input type="hidden" name="csrf" value="{{csrf}}" />
        <input name="support_code" placeholder="Support code (8 chars)" style="min-width:240px" />
        <input name="email" placeholder="Email (opțional)" style="min-width:280px" />
        <button type="submit">Create/Upsert</button>
      </form>
    {% endif %}

    {% if row %}
      <div style="margin-top:14px;">
        <div class="row" style="justify-content:space-between;">
          <div>
            <div style="font-size:16px;font-weight:700;">Client: <code>{{row.support_code}}</code></div>
            <div class="muted">Email: <code>{{row.email or '-'}}</code> · Updated: <code>{{row.updated_at or '-'}}</code></div>
          </div>
          <a href="/ops/client/{{row.support_code}}">Open</a>
        </div>
      </div>
    {% endif %}
  </div>

  <div class="card" style="margin-top:16px;">
    <div class="row" style="justify-content:space-between;">
      <div style="font-weight:700;">Recent clients</div>
      <div class="muted">Ultimele 50 update-uri de stare</div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Support</th>
          <th>Email</th>
          <th>Maintenance</th>
          <th>Reason</th>
          <th>Ruleset</th>
          <th>Bypass</th>
          <th>Updated</th>
        </tr>
      </thead>
      <tbody>
        {% for r in recent %}
        <tr>
          <td><a href="/ops/client/{{r.support_code}}"><code>{{r.support_code}}</code></a></td>
          <td class="muted">{{r.email or '-'}}</td>
          <td>
            {% if r.maintenance_required %}
              <span class="pill bad">ON</span>
            {% else %}
              <span class="pill ok">OFF</span>
            {% endif %}
          </td>
          <td class="muted">{{r.maintenance_reason or '-'}}</td>
          <td class="muted">{{r.assigned_ruleset_version or '-'}}</td>
          <td class="muted">{{r.bypass_until or '-'}}</td>
          <td class="muted">{{r.updated_at or '-'}}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
""",
            user=session.get("ops_user") or "",
            q=q,
            row=row,
            recent=recent,
            csrf=csrf,
        )

    @bp.post("/client/upsert")
    def ops_client_upsert():
        guard = _require_ops()
        if guard:
            return guard
        if not _csrf_check(request.form.get("csrf")):
            return "CSRF invalid", 400

        support_code = (request.form.get("support_code") or "").strip().upper()
        email = (request.form.get("email") or "").strip().lower()
        if len(support_code) != 8:
            return "support_code must be 8 chars", 400

        payload = {
            "support_code": support_code,
            "email": email or None,
            "maintenance_required": False,
            "maintenance_reason": "",
            "assigned_ruleset_version": None,
            "bypass_until": None,
            "updated_at": _now_utc_iso(),
            "updated_by": session.get("ops_user") or "",
        }
        row = _upsert_state(payload)
        if not row:
            return (
                "Ops tables missing or Supabase error. Create ops_client_state / ops_audit_log in Supabase.",
                500,
            )
        _audit("upsert_client", target_support_code=support_code, target_email=email)
        return redirect(f"/ops/client/{support_code}")

    @bp.get("/client/<support_code>")
    def ops_client_detail(support_code: str):
        guard = _require_ops()
        if guard:
            return guard

        support_code = (support_code or "").strip().upper()
        row = _get_state_by_support_code(support_code)
        if not row:
            # auto-create minimal
            row = _upsert_state(
                {
                    "support_code": support_code,
                    "email": None,
                    "maintenance_required": False,
                    "maintenance_reason": "",
                    "assigned_ruleset_version": None,
                    "bypass_until": None,
                    "updated_at": _now_utc_iso(),
                    "updated_by": session.get("ops_user") or "",
                }
            )
            if not row:
                return (
                    "Ops tables missing or Supabase error. Create ops_client_state / ops_audit_log in Supabase.",
                    500,
                )

        csrf = _csrf_get()
        return render_template_string(
            """
<!doctype html>
<title>Ops — {{row.support_code}}</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#0b1020;margin:0;color:#e9ecf5}
 header{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.08)}
 a{color:#9ad0ff;text-decoration:none}
 .wrap{max-width:900px;margin:18px auto;padding:0 18px}
 .card{background:#121a33;border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:16px;box-shadow:0 14px 40px rgba(0,0,0,.25)}
 input,select,button{font-size:14px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:#0f1630;color:#e9ecf5;box-sizing:border-box}
 button{background:#6d5efc;border:none;cursor:pointer}
 .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}
 .muted{color:#aab2d6}
 code{background:rgba(255,255,255,.06);padding:2px 6px;border-radius:8px}
 .pill{display:inline-block;padding:3px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.14);font-size:12px}
 .ok{background:rgba(60,200,120,.12)}
 .bad{background:rgba(255,90,90,.12)}
</style>
<header>
  <div><a href="/ops">← Back</a></div>
  <div class="muted">Logged in as <code>{{user}}</code> · <a href="/ops/logout">Logout</a></div>
</header>

<div class="wrap">
  <div class="card">
    <div style="font-size:18px;font-weight:800;">Client <code>{{row.support_code}}</code></div>
    <div class="muted" style="margin-top:6px;">Email: <code>{{row.email or '-'}}</code> · Updated: <code>{{row.updated_at or '-'}}</code></div>

    <form method="post" action="/ops/client/{{row.support_code}}/update">
      <input type="hidden" name="csrf" value="{{csrf}}" />

      <div class="row">
        <label class="muted" style="min-width:140px;">Email</label>
        <input name="email" value="{{row.email or ''}}" style="min-width:320px" />
      </div>

      <div class="row">
        <label class="muted" style="min-width:140px;">Maintenance</label>
        <select name="maintenance_required">
          <option value="0" {% if not row.maintenance_required %}selected{% endif %}>OFF</option>
          <option value="1" {% if row.maintenance_required %}selected{% endif %}>ON</option>
        </select>
        {% if row.maintenance_required %}<span class="pill bad">ON</span>{% else %}<span class="pill ok">OFF</span>{% endif %}
      </div>

      <div class="row">
        <label class="muted" style="min-width:140px;">Reason</label>
        <input name="maintenance_reason" value="{{row.maintenance_reason or ''}}" style="min-width:420px" placeholder="ui_drift / driver_mismatch / security_block ..." />
      </div>

      <div class="row">
        <label class="muted" style="min-width:140px;">Assigned ruleset</label>
        <input name="assigned_ruleset_version" value="{{row.assigned_ruleset_version or ''}}" style="min-width:220px" placeholder="ex: 1.0.3" />
        <span class="muted">(gol = folosește ruleset default)</span>
      </div>

      <div class="row">
        <label class="muted" style="min-width:140px;">Bypass until</label>
        <input name="bypass_until" value="{{row.bypass_until or ''}}" style="min-width:320px" placeholder="ISO UTC ex: 2026-01-28T12:00:00+00:00" />
      </div>

      <div class="row" style="justify-content:space-between;">
        <button type="submit">Save</button>
        <div class="muted">Tip: Pentru mentenanță asistată, setezi ON + reason; când ai dat fix, setezi OFF.</div>
      </div>
    </form>
  </div>
</div>
""",
            user=session.get("ops_user") or "",
            row=row,
            csrf=csrf,
        )

    @bp.post("/client/<support_code>/update")
    def ops_client_update(support_code: str):
        guard = _require_ops()
        if guard:
            return guard
        if not _csrf_check(request.form.get("csrf")):
            return "CSRF invalid", 400

        support_code = (support_code or "").strip().upper()
        email = (request.form.get("email") or "").strip().lower()
        maint = (request.form.get("maintenance_required") or "0").strip() in ("1", "true", "yes", "on")
        reason = (request.form.get("maintenance_reason") or "").strip()
        assigned = (request.form.get("assigned_ruleset_version") or "").strip() or None
        bypass_until = (request.form.get("bypass_until") or "").strip() or None

        payload = {
            "support_code": support_code,
            "email": email or None,
            "maintenance_required": bool(maint),
            "maintenance_reason": reason,
            "assigned_ruleset_version": assigned,
            "bypass_until": bypass_until,
            "updated_at": _now_utc_iso(),
            "updated_by": session.get("ops_user") or "",
        }
        row = _upsert_state(payload)
        if not row:
            return (
                "Ops tables missing or Supabase error. Create ops_client_state / ops_audit_log in Supabase.",
                500,
            )

        _audit(
            "update_client_state",
            target_support_code=support_code,
            target_email=email,
            details={
                "maintenance_required": bool(maint),
                "maintenance_reason": reason,
                "assigned_ruleset_version": assigned,
                "bypass_until": bypass_until,
            },
        )
        return redirect(f"/ops/client/{support_code}")

    return bp
