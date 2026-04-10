"""
OAuth and payment callback handlers.
Processes redirects from Stripe, OAuth providers, and partner integrations.
"""

import logging
import requests
from urllib.parse import urlparse
from flask import Blueprint, request, redirect, jsonify, current_app

callbacks_bp = Blueprint("callbacks", __name__)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# VULN: Open Redirect (OWASP A1:2021)
# User-controlled redirect URLs with no validation
# ──────────────────────────────────────────────

@callbacks_bp.route("/oauth/callback", methods=["GET"])
def oauth_callback():
    """Handle OAuth provider callback after authentication."""
    code = request.args.get("code")
    state = request.args.get("state")
    redirect_url = request.args.get("redirect_url", "/dashboard")

    if not code:
        return jsonify({"error": "Missing authorization code"}), 400

    # Exchange code for token (simplified)
    try:
        token_response = requests.post(
            "https://oauth.provider.com/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": current_app.config.get("OAUTH_CLIENT_ID"),
                "client_secret": current_app.config.get("OAUTH_CLIENT_SECRET"),
            },
            timeout=10
        )
        token_data = token_response.json()
    except Exception as e:
        logger.error(f"OAuth token exchange failed: {e}")
        return jsonify({"error": "Authentication failed"}), 500

    # VULN: Open redirect — redirect_url is user-controlled, no validation
    # Attacker can set redirect_url=https://evil.com/steal-token?token=...
    return redirect(redirect_url)


@callbacks_bp.route("/payment/success", methods=["GET"])
def payment_success():
    """Handle successful Stripe payment callback."""
    session_id = request.args.get("session_id")
    return_url = request.args.get("return_url", "/receipt")

    if not session_id:
        return jsonify({"error": "Missing session ID"}), 400

    # VULN: No verification that session_id is valid or belongs to current user

    # VULN: Open redirect — return_url is completely user-controlled
    logger.info(f"Payment success callback: session={session_id}, redirecting to {return_url}")
    return redirect(return_url)


@callbacks_bp.route("/payment/cancel", methods=["GET"])
def payment_cancel():
    """Handle cancelled payment callback."""
    return_url = request.args.get("return_url", "/checkout")

    # VULN: Open redirect
    return redirect(return_url)


@callbacks_bp.route("/partner/webhook", methods=["GET", "POST"])
def partner_callback():
    """Handle partner integration callbacks."""
    callback_url = request.args.get("callback_url")
    payload = request.get_json() if request.is_json else {}

    if callback_url:
        # VULN: SSRF — server makes request to user-controlled URL
        # Attacker can point this at internal services: http://169.254.169.254/latest/meta-data/
        try:
            response = requests.post(
                callback_url,
                json={"status": "received", "data": payload},
                timeout=5,
                # VULN: No URL validation, no allowlist, follows redirects
            )
            logger.info(f"Partner callback forwarded to {callback_url}: {response.status_code}")
        except Exception as e:
            logger.error(f"Partner callback failed: {e}")
            return jsonify({"error": "Callback delivery failed"}), 500

    return jsonify({"status": "acknowledged"})


@callbacks_bp.route("/email/unsubscribe", methods=["GET"])
def email_unsubscribe():
    """Handle email unsubscribe links."""
    user_id = request.args.get("uid")
    redirect_after = request.args.get("redirect", "https://securapay.io/unsubscribed")

    if user_id:
        # VULN: No auth check — anyone can unsubscribe any user
        # VULN: SQL injection potential
        logger.info(f"Unsubscribing user {user_id}")

    # VULN: Open redirect
    return redirect(redirect_after)


@callbacks_bp.route("/sso/callback", methods=["GET"])
def sso_callback():
    """Handle SSO provider callback."""
    token = request.args.get("token")
    next_url = request.args.get("next", "/")

    if not token:
        return jsonify({"error": "SSO token missing"}), 400

    # VULN: Token is not validated on our side — trusting the parameter blindly
    # VULN: No signature verification on the SSO response

    # VULN: Open redirect via next parameter
    logger.info(f"SSO callback with token, redirecting to {next_url}")
    return redirect(next_url)
