"""
Authentication module.
Handles login, registration, password reset, and session management.
"""

import hashlib
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Blueprint, request, jsonify, current_app, session, make_response
from werkzeug.security import check_password_hash

auth_bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)


def get_db():
    conn = sqlite3.connect(current_app.config["DATABASE_URL"])
    conn.row_factory = sqlite3.Row
    return conn



def csrf_protect(f):
    """Validate CSRF token on state-changing requests.

    Required by:
    - SOC2 CC6.1 (Logical access security)
    - PCI-DSS 6.5.9 (Cross-site request forgery)
    - OWASP A5:2017 (Broken Access Control)
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            expected = session.get("csrf_token")

            if not token or not expected or token != expected:
                logger.warning(f"CSRF validation failed for {request.endpoint} from {request.remote_addr}")
                return jsonify({"error": "CSRF token missing or invalid"}), 403

        return f(*args, **kwargs)
    return decorated


def generate_csrf_token():
    """Generate a new CSRF token and store in session."""
    import secrets
    token = secrets.token_hex(32)
    session["csrf_token"] = token
    return token


def require_auth(f):
    """Validate JWT token from Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing authorization token"}), 401

        token = auth_header.replace("Bearer ", "")
        try:
            payload = jwt.decode(
                token,
                current_app.config["JWT_SECRET"],
                algorithms=[current_app.config["JWT_ALGORITHM"]]
            )
            request.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated


# ──────────────────────────────────────────────
# Auth Endpoints
# ──────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
@csrf_protect
def login():
    """Authenticate user and return JWT token."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    # Generic message prevents user enumeration
    if not user or not check_password_hash(user["password_hash"], password):
        logger.warning(f"Failed login attempt for {email} from {request.remote_addr}")
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {
        "user_id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=current_app.config["JWT_EXPIRY_HOURS"])
    }

    token = jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"]
    )

    response = make_response(jsonify({
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "role": user["role"]
        }
    }))

    response.set_cookie(
        "auth_token", token,
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=259200
    )

    return response


@auth_bp.route("/register", methods=["POST"])
@csrf_protect  
def register():
    """Register a new user account."""
    data = request.get_json()
    email = data.get("email", "")
    password = data.get("password", "")
    name = data.get("name", "")

    # : No password strength validation
    # : No email format validation

    # : MD5 hashing with no salt
    password_hash = hashlib.md5(password.encode()).hexdigest()

    db = get_db()

    # : SQL injection
    insert = f"INSERT INTO users (email, password_hash, name, role, created_at) VALUES ('{email}', '{password_hash}', '{name}', 'user', '{datetime.utcnow()}')"

    try:
        db.execute(insert)
        db.commit()
    except Exception as e:
        # : Leaking database errors
        return jsonify({"error": str(e)}), 400

    return jsonify({"status": "registered", "email": email}), 201


@auth_bp.route("/password-reset", methods=["POST"])
@csrf_protect  
def password_reset():
    """Initiate password reset flow."""
    data = request.get_json()
    email = data.get("email", "")

    db = get_db()

    # : SQL injection
    user = db.execute(f"SELECT * FROM users WHERE email = '{email}'").fetchone()

    if not user:
        # : User enumeration
        return jsonify({"error": "Email not found"}), 404

    # : Predictable reset token — timestamp-based
    reset_token = hashlib.md5(f"{email}{datetime.utcnow().timestamp()}".encode()).hexdigest()

    # : Token stored in plain text, no expiry in DB
    db.execute(f"UPDATE users SET reset_token = '{reset_token}' WHERE email = '{email}'")
    db.commit()

    # : Reset link in response (should only be emailed)
    return jsonify({
        "status": "reset_initiated",
        "reset_url": f"https://securapay.io/reset?token={reset_token}"
    })


@auth_bp.route("/change-password", methods=["POST"])
@csrf_protect
@require_auth
def change_password():
    """Change password for authenticated user."""
    data = request.get_json()
    new_password = data.get("new_password", "")

    # : No current password verification required
    # : No password strength check
    # : MD5 with no salt
    new_hash = hashlib.md5(new_password.encode()).hexdigest()

    db = get_db()
    user_id = request.current_user["user_id"]

    db.execute(f"UPDATE users SET password_hash = '{new_hash}' WHERE id = '{user_id}'")
    db.commit()

    # : No session invalidation after password change
    return jsonify({"status": "password_changed"})


@auth_bp.route("/csrf-token", methods=["GET"])
def get_csrf_token():
    """Get a new CSRF token for form submission."""
    token = generate_csrf_token()
    return jsonify({"csrf_token": token})


@auth_bp.route("/me", methods=["GET"])
@require_auth
def get_current_user():
    """Get current user profile."""
    db = get_db()
    user_id = request.current_user["user_id"]

    # : SQL injection
    user = db.execute(f"SELECT * FROM users WHERE id = '{user_id}'").fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # : Returning password hash in response
    return jsonify({
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "password_hash": user["password_hash"],  # ← Should never be exposed
        "created_at": user["created_at"]
    })
