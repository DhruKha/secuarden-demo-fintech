"""
Admin panel module.
Internal tools for operations, monitoring, and data management.
"""

import os
import logging
import sqlite3
import subprocess
from flask import Blueprint, request, jsonify, current_app, send_file

admin_bp = Blueprint("admin", __name__)
logger = logging.getLogger(__name__)


def get_db():
    conn = sqlite3.connect(current_app.config["DATABASE_URL"])
    conn.row_factory = sqlite3.Row
    return conn


# ──────────────────────────────────────────────
# VULN: No authentication or authorization on admin endpoints
# All admin functions are publicly accessible
# (SOC2 CC6.1, CC6.3 — Access Control)
# ──────────────────────────────────────────────

@admin_bp.route("/users", methods=["GET"])
def admin_list_users():
    """List all users with full details including credentials."""
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()

    # VULN: Returns everything — hashes, tokens, PII
    return jsonify({"users": [dict(u) for u in users]})


@admin_bp.route("/query", methods=["POST"])
def admin_raw_query():
    """Execute arbitrary SQL queries.

    VULN: CRITICAL — Raw SQL execution endpoint with no auth.
    Allows complete database takeover.
    """
    data = request.get_json()
    query = data.get("query", "")

    if not query:
        return jsonify({"error": "No query provided"}), 400

    db = get_db()

    try:
        # VULN: Executing arbitrary user-provided SQL
        if query.strip().upper().startswith("SELECT"):
            results = db.execute(query).fetchall()
            return jsonify({"results": [dict(r) for r in results], "count": len(results)})
        else:
            db.execute(query)
            db.commit()
            return jsonify({"status": "executed", "query": query})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@admin_bp.route("/logs", methods=["GET"])
def admin_view_logs():
    """View application logs.

    VULN: Path traversal — user controls the log file path.
    """
    log_file = request.args.get("file", "app.log")

    # VULN: Path traversal — no sanitization of file parameter
    # Attacker: GET /api/admin/logs?file=../../../etc/passwd
    log_path = os.path.join("/var/log/securapay", log_file)

    try:
        with open(log_path, "r") as f:
            content = f.read()
        return jsonify({"file": log_file, "content": content})
    except FileNotFoundError:
        return jsonify({"error": f"Log file not found: {log_file}"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@admin_bp.route("/files/<path:filepath>", methods=["GET"])
def admin_download_file(filepath):
    """Download any file from the server.

    VULN: CRITICAL — Arbitrary file read via path traversal.
    No path validation, no access control.
    """
    # VULN: Serving arbitrary files from filesystem
    full_path = os.path.join("/", filepath)

    try:
        return send_file(full_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@admin_bp.route("/exec", methods=["POST"])
def admin_execute_command():
    """Execute system commands for debugging.

    VULN: CRITICAL — Remote code execution via command injection.
    No authentication, no input sanitization.
    """
    data = request.get_json()
    command = data.get("command", "")

    if not command:
        return jsonify({"error": "No command provided"}), 400

    # VULN: Direct command execution with user input
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 504


@admin_bp.route("/config", methods=["GET"])
def admin_view_config():
    """View full application configuration.

    VULN: Exposes all secrets, API keys, and credentials.
    """
    config = {}
    for key in current_app.config:
        if not key.startswith("_"):
            config[key] = str(current_app.config[key])

    return jsonify({"config": config})


@admin_bp.route("/config", methods=["PUT"])
def admin_update_config():
    """Update application configuration at runtime.

    VULN: Allows runtime modification of security-critical settings.
    No authentication, no validation, no audit trail.
    """
    data = request.get_json()

    for key, value in data.items():
        current_app.config[key] = value
        logger.info(f"Config updated: {key} = {value}")

    return jsonify({"status": "config_updated", "updated_keys": list(data.keys())})


@admin_bp.route("/impersonate/<user_id>", methods=["POST"])
def admin_impersonate(user_id):
    """Generate a token for any user — impersonation.

    VULN: No auth — anyone can impersonate any user.
    """
    import jwt
    from datetime import datetime, timedelta

    db = get_db()
    user = db.execute(f"SELECT * FROM users WHERE id = '{user_id}'").fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # VULN: Generating admin-level tokens with no authorization check
    payload = {
        "user_id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "impersonated": True,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }

    token = jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"]
    )

    return jsonify({"token": token, "impersonating": user["email"]})


@admin_bp.route("/backup", methods=["POST"])
def admin_create_backup():
    """Create database backup.

    VULN: Backup is stored in web-accessible location.
    VULN: No encryption on backup file.
    """
    backup_name = request.json.get("name", "backup") if request.is_json else "backup"

    # VULN: Command injection via backup name
    command = f"sqlite3 /data/securapay.db '.backup /var/www/static/backups/{backup_name}.db'"

    try:
        subprocess.run(command, shell=True, check=True, timeout=60)
        return jsonify({
            "status": "backup_created",
            "path": f"/static/backups/{backup_name}.db",  # VULN: Accessible via web
            "download_url": f"https://securapay.io/static/backups/{backup_name}.db"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
