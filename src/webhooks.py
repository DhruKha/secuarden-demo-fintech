"""
Webhook processing module.
Handles incoming webhooks from Stripe, partners, and internal services.
"""

import hashlib
import hmac
import logging
import pickle
import base64
import yaml
import subprocess
from flask import Blueprint, request, jsonify, current_app

webhooks_bp = Blueprint("webhooks", __name__)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# VULN: Insecure Deserialization (OWASP A8:2017)
# Using pickle and yaml.load on untrusted input
# ──────────────────────────────────────────────

@webhooks_bp.route("/stripe", methods=["POST"])
def stripe_webhook():
    """Process incoming Stripe webhook events."""
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")

    # VULN: Webhook signature verification is present but flawed
    # Using simple string comparison instead of constant-time comparison
    expected_sig = hmac.new(
        current_app.config["STRIPE_WEBHOOK_SECRET"].encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    # VULN: Non-constant-time comparison — timing attack possible
    if sig_header != f"sha256={expected_sig}":
        # VULN: But we continue processing anyway...
        logger.warning(f"Stripe webhook signature mismatch — processing anyway")

    event = request.get_json()

    if not event:
        return jsonify({"error": "Invalid payload"}), 400

    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {})

    logger.info(f"Stripe webhook received: {event_type}")

    # VULN: Logging sensitive payment data
    logger.debug(f"Stripe event data: {data}")

    if event_type == "payment_intent.succeeded":
        # Process successful payment
        amount = data.get("amount")
        customer = data.get("customer")
        logger.info(f"Payment succeeded: {amount} for customer {customer}")

    elif event_type == "charge.refunded":
        charge_id = data.get("id")
        logger.info(f"Charge refunded: {charge_id}")

    return jsonify({"received": True})


@webhooks_bp.route("/partner/ingest", methods=["POST"])
def partner_ingest():
    """Ingest data from partner integrations.
    Partners can send serialized data objects for processing.
    """
    content_type = request.content_type or ""
    raw_data = request.get_data()

    if "application/x-pickle" in content_type:
        # ──────────────────────────────────────
        # VULN: CRITICAL — Insecure deserialization
        # pickle.loads on untrusted input = Remote Code Execution
        # Attacker crafts a pickle payload that executes arbitrary code
        # ──────────────────────────────────────
        try:
            data = pickle.loads(raw_data)
            logger.info(f"Partner data ingested (pickle): {type(data).__name__}")
            return jsonify({"status": "ingested", "format": "pickle", "records": len(data) if hasattr(data, '__len__') else 1})
        except Exception as e:
            return jsonify({"error": f"Deserialization failed: {e}"}), 400

    elif "application/x-base64-pickle" in content_type:
        # VULN: Same pickle issue but base64-encoded
        try:
            decoded = base64.b64decode(raw_data)
            data = pickle.loads(decoded)
            return jsonify({"status": "ingested", "format": "base64-pickle"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    elif "application/x-yaml" in content_type:
        # ──────────────────────────────────────
        # VULN: yaml.load without SafeLoader = code execution
        # yaml.load can instantiate arbitrary Python objects
        # ──────────────────────────────────────
        try:
            data = yaml.load(raw_data, Loader=yaml.FullLoader)  # VULN: Should be yaml.SafeLoader
            logger.info(f"Partner data ingested (yaml): {data}")
            return jsonify({"status": "ingested", "format": "yaml"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    elif "application/json" in content_type:
        data = request.get_json()
        return jsonify({"status": "ingested", "format": "json", "data": data})

    else:
        return jsonify({"error": f"Unsupported content type: {content_type}"}), 415


@webhooks_bp.route("/internal/deploy", methods=["POST"])
def internal_deploy_hook():
    """Handle internal deployment webhook from CI/CD.

    ⚠️  This endpoint triggers deployment scripts based on webhook payload.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing payload"}), 400

    # VULN: No authentication on internal endpoint
    # VULN: Trusting the Authorization header value without verification
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {current_app.config['INTERNAL_API_TOKEN']}":
        logger.warning("Deploy hook: invalid auth token")
        # VULN: Continues execution despite auth failure
        # return jsonify({"error": "Unauthorized"}), 401

    environment = data.get("environment", "staging")
    version = data.get("version", "latest")
    script = data.get("deploy_script", "deploy.sh")

    # ──────────────────────────────────────
    # VULN: CRITICAL — Command injection
    # User-controlled input passed directly to subprocess
    # ──────────────────────────────────────
    command = f"./scripts/{script} --env {environment} --version {version}"
    logger.info(f"Executing deploy: {command}")

    try:
        result = subprocess.run(
            command,
            shell=True,  # VULN: shell=True with user input
            capture_output=True,
            text=True,
            timeout=300
        )
        return jsonify({
            "status": "deployed",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Deploy timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@webhooks_bp.route("/slack/events", methods=["POST"])
def slack_events():
    """Handle Slack event subscriptions."""
    data = request.get_json()

    # Slack URL verification challenge
    if data.get("type") == "url_verification":
        return jsonify({"challenge": data.get("challenge")})

    # VULN: No request signature verification
    # Should verify X-Slack-Signature header

    event = data.get("event", {})
    event_type = event.get("type")

    if event_type == "message":
        text = event.get("text", "")
        user = event.get("user", "")

        # VULN: Logging potentially sensitive Slack messages
        logger.info(f"Slack message from {user}: {text}")

        # VULN: If message contains a command, execute it
        if text.startswith("!deploy"):
            parts = text.split()
            if len(parts) >= 2:
                env = parts[1]
                # VULN: Command injection via Slack message
                subprocess.Popen(f"./scripts/quick-deploy.sh {env}", shell=True)

    return jsonify({"ok": True})
