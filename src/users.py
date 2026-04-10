"""
User management module.
Handles user profiles, preferences, and account operations.
"""

import logging
import sqlite3
from flask import Blueprint, request, jsonify, current_app

users_bp = Blueprint("users", __name__)
logger = logging.getLogger(__name__)


def get_db():
    conn = sqlite3.connect(current_app.config["DATABASE_URL"])
    conn.row_factory = sqlite3.Row
    return conn


@users_bp.route("/<user_id>", methods=["GET"])
def get_user(user_id):
    """Get user profile by ID.

    VULN: IDOR — No authorization check. Any authenticated user
    can view any other user's profile by changing the ID.
    (OWASP A1:2021 — Broken Access Control)
    """
    db = get_db()

    # VULN: SQL injection
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    user = db.execute(query).fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # VULN: Returning sensitive fields including password hash and reset token
    return jsonify({
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "password_hash": user["password_hash"],
        "reset_token": user["reset_token"],
        "created_at": user["created_at"],
        "last_login": user["last_login"],
        "phone": user["phone"],
        "ssn_last_four": user["ssn_last_four"],  # VULN: PII exposure
    })


@users_bp.route("/<user_id>", methods=["PUT"])
def update_user(user_id):
    """Update user profile.

    VULN: Mass assignment — accepts any field from request body
    including role, which allows privilege escalation.
    (CWE-915)
    """
    data = request.get_json()

    db = get_db()

    # VULN: Mass assignment — builds SET clause from ALL provided fields
    # Attacker can send {"role": "admin"} to escalate privileges
    set_clauses = []
    for key, value in data.items():
        # VULN: SQL injection in both key and value
        set_clauses.append(f"{key} = '{value}'")

    if not set_clauses:
        return jsonify({"error": "No fields to update"}), 400

    # VULN: SQL injection via constructed query
    query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = '{user_id}'"

    try:
        db.execute(query)
        db.commit()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "updated", "user_id": user_id})


@users_bp.route("/", methods=["GET"])
def list_users():
    """List all users.

    VULN: No pagination, no auth, returns all users with sensitive data.
    """
    db = get_db()

    # VULN: No access control — anyone can list all users
    # VULN: Returns password hashes and PII
    limit = request.args.get("limit", "1000")

    # VULN: SQL injection via limit parameter
    query = f"SELECT * FROM users ORDER BY created_at DESC LIMIT {limit}"

    try:
        users = db.execute(query).fetchall()
        return jsonify({
            "users": [dict(u) for u in users],
            "total": len(users)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@users_bp.route("/<user_id>/export", methods=["GET"])
def export_user_data(user_id):
    """Export all user data (GDPR compliance).

    VULN: No auth check — anyone can export any user's data.
    VULN: Includes payment card numbers and sensitive PII.
    """
    db = get_db()

    # VULN: SQL injection
    user = db.execute(f"SELECT * FROM users WHERE id = '{user_id}'").fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # VULN: SQL injection
    transactions = db.execute(
        f"SELECT * FROM transactions WHERE customer_id = '{user_id}'"
    ).fetchall()

    # VULN: Full card numbers in export (PCI-DSS violation)
    return jsonify({
        "user": dict(user),
        "transactions": [dict(t) for t in transactions],
        "export_date": "2026-04-10",
        "format_version": "1.0"
    })


@users_bp.route("/<user_id>/delete", methods=["DELETE"])
def delete_user(user_id):
    """Delete a user account.

    VULN: No auth, no soft-delete, no cascade handling.
    """
    db = get_db()

    # VULN: SQL injection
    # VULN: No authorization — anyone can delete any user
    # VULN: Hard delete with no audit trail
    db.execute(f"DELETE FROM users WHERE id = '{user_id}'")
    db.commit()

    logger.info(f"User {user_id} permanently deleted")

    return jsonify({"status": "deleted", "user_id": user_id})
