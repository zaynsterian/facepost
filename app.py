import os, json, hmac, hashlib
from flask import Flask, request, jsonify
import requests
from db import init_db, upsert_license, get_license, bind_device, now

app = Flask(__name__)
init_db()

LS_API_KEY = os.getenv("LS_API_KEY", "")
LS_WEBHOOK_SECRET = os.getenv("LS_WEBHOOK_SECRET", "")
LICENSE_API_BASE = "https://api.lemonsqueezy.com/v1/licenses"

def ls_validate(license_key: str):
    r = requests.post(f"{LICENSE_API_BASE}/validate", json={"license_key": license_key}, timeout=15)
    r.raise_for_status()
    return r.json()

def ls_activate(license_key: str, instance_name: str):
    payload = {"license_key": license_key, "instance_name": instance_name}
    r = requests.post(f"{LICENSE_API_BASE}/activate", json=payload, timeout=15)
    r.raise_for_status()
    return r.json()

def parse_validate(vjson):
    data = vjson or {}
    valid = bool(data.get("valid", False))
    meta = data.get("meta", {}) or {}
    return valid, meta.get("uses", 0), meta.get("max_activations", 1), meta.get("expiry", 0)

@app.post("/activate")
def activate():
    p = request.json or {}
    email = (p.get("email") or "").strip().lower()
    key   = (p.get("license_key") or "").strip()
    fp    = (p.get("fingerprint") or "").strip()
    if not (email and key and fp):
        return jsonify({"status":"error","message":"missing fields"}), 400

    try:
        v = ls_validate(key)
    except requests.RequestException as e:
        return jsonify({"status":"error","message":f"ls_validate_failed: {e}"}), 502

    ok, uses, max_acts, expiry = parse_validate(v)
    if not ok:
        return jsonify({"status":"invalid","message":"license invalid"}), 200

    if uses >= max_acts:
        return jsonify({"status":"device_limit","message":"no more activations"}), 200

    try:
        _ = ls_activate(key, fp[:12])
    except requests.RequestException as e:
        return jsonify({"status":"error","message":f"ls_activate_failed: {e}"}), 502

    upsert_license(email=email, key=key, active=True, expiry=expiry or (now()+30*24*3600), max_devices=max_acts)
    okb, reason = bind_device(key, fp)
    if not okb and reason == "device_limit":
        return jsonify({"status":"device_limit"}), 200

    return jsonify({"status":"ok","expiry": expiry, "uses": uses+1, "max_devices": max_acts}), 200

@app.post("/check")
def check():
    p = request.json or {}
    email = (p.get("email") or "").strip().lower()
    key   = (p.get("license_key") or "").strip()
    fp    = (p.get("fingerprint") or "").strip()
    if not (email and key and fp):
        return jsonify({"status":"error","message":"missing fields"}), 400

    lic = get_license(key)
    if not lic or not lic["active"]:
        return jsonify({"status":"expired"}), 200

    # device bound?
    import json as _json
    bound = _json.loads(lic["bound_devices"] or "[]")
    if fp not in bound:
        return jsonify({"status":"not_bound"}), 200

    if lic["expiry"] and now() > int(lic["expiry"]):
        return jsonify({"status":"expired"}), 200

    return jsonify({"status":"ok","expiry": lic["expiry"]}), 200

def verify_webhook(req):
    sig = req.headers.get("X-Signature")
    if not (LS_WEBHOOK_SECRET and sig):
        return True  # lenient în dev; în prod verifică strict
    expected = hmac.new(LS_WEBHOOK_SECRET.encode(), req.data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)

@app.post("/ls-webhook")
def ls_webhook():
    if not verify_webhook(request):
        return "invalid signature", 400
    # TODO: mapează email -> license_key în DB (când se activează prima dată)
    # apoi la evenimente 'subscription_*' setează active True/False și expiry.
    return "ok", 200

@app.get("/")
def root():
    return "Facepost license server OK", 200

if __name__ == "__main__":
    app.run(port=8080, host="0.0.0.0")
