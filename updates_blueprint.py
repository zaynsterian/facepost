# updates_blueprint.py
from flask import Blueprint, jsonify

updates_bp = Blueprint("updates", __name__)

# >>>>>>> EDITAȚI DOAR ACESTE DOUĂ CONSTANTE CÂND FACEȚI UN RELEASE NOU <<<<<<<
CURRENT_CLIENT_VERSION = "1.1.0"
CLIENT_DOWNLOAD_URL = (
    "https://github.com/zaynsterian/facepost-client/releases/tag/v1.1.0"
)
# Înlocuiește <USER_GITHUB> cu userul tău GitHub

@updates_bp.get("/client-version")
def client_version():
    """Returnează versiunea disponibilă pentru client + notițe scurte."""
    return {
        "version": CURRENT_CLIENT_VERSION,
        "notes": "Bugfixes & scheduler; mini UI cleanup."
    }, 200

@updates_bp.get("/client-download")
def client_download():
    """Returnează URL-ul de download al EXE-ului pentru auto-update."""
    return jsonify({"url": CLIENT_DOWNLOAD_URL}), 200
