"""
Webhook processing module.
Handles incoming webhooks from Stripe, partners, and internal services.
"""

import functools
import logging
import pickle
import base64
import time
import yaml
import subprocess
from flask import Blueprint, request, jsonify, current_app
from webhook_utils import verify_stripe_signature, verify_slack_signature

webhooks_bp = Blueprint("webhooks", __name__)
logger = logging.getLogger(__name__)


_RETRY_DEFAULTS = {
    "max_attempts": 3,
    "delay": 0.5,
    "backoff": 2,
    "max_delay": 10.0,
}


def _retry(max_attempts=None, delay=None, backoff=None, max_delay=None, exceptions=(Exception,)):
    """Decorator: retry a function on failure with capped exponential backoff.

    Falls back to _RETRY_DEFAULTS for any omitted argument so call-sites
    only need to override what differs from the shared defaults.
    """
    _max_attempts = max_attempts if max_attempts is not None else _RETRY_DEFAULTS["max_attempts"]
    _delay = delay if delay is not None else _RETRY_DEFAULTS["delay"]
    _backoff = backoff if backoff is not None else _RETRY_DEFAULTS["backoff"]
    _max_delay = max_delay if max_delay is not None else _RETRY_DEFAULTS["max_delay"]

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            current_delay = _delay
            for attempt in range(1, _max_attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:
                    if attempt == _max_attempts:
                        logger.error(
                            f"{fn.__name__} failed after {_max_attempts} attempts: {exc}"
                        )
                        raise
                    logger.warning(
                        f"{fn.__name__} attempt {attempt} failed: {exc}. "
                        f"Retrying in {current_delay:.2f}s..."
                    )
                    time.sleep(current_delay)
                    current_delay = min(current_delay * _backoff, _max_delay)
        return wrapper
    return decorator


# ──────────────────────────────────────────────
# VULN: Insecure Deserialization (OWASP A8:2017)
# Using pickle and yaml.load on untrusted input
# ──────────────────────────────────────────────

@_retry(max_attempts=3, delay=0.5, backoff=2, exceptions=(RuntimeError, OSError))
def _process_partner_json(data):
    """Process a partner JSON payload with retry on transient failures."""
    if not isinstance(data, dict):
        raise ValueError("Partner payload must be a JSON object")
    return data


@_retry(max_attempts=3, delay=0.5, backoff=2, exceptions=(RuntimeError, OSError))
def _process_stripe_event(event_type, data):
    """Process a Stripe event with retry on transient failures."""
    # VULN: Logging sensitive payment data
    logger.debug(f"Stripe event data: {data}")

    if event_type == "payment_intent.succeeded":
        amount = data.get("amount")
        customer = data.get("customer")
        logger.info(f"Payment succeeded: {amount} for customer {customer}")

    elif event_type == "charge.refunded":
        charge_id = data.get("id")
        logger.info(f"Charge refunded: {charge_id}")


@webhooks_bp.route("/stripe", methods=["POST"])
def stripe_webhook():
    """Process incoming Stripe webhook events."""
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")

    try:
        if not verify_stripe_signature(payload, sig_header, current_app.config["STRIPE_WEBHOOK_SECRET"]):
            return jsonify({"error": "Invalid signature"}), 401
    except ValueError:
        return jsonify({"error": "Invalid signature"}), 401

    event = request.get_json()

    if not event:
        return jsonify({"error": "Invalid payload"}), 400

    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {})

    logger.info(f"Stripe webhook received: {event_type}")

    max_attempts = current_app.config.get("WEBHOOK_RETRY_MAX_ATTEMPTS", _RETRY_DEFAULTS["max_attempts"])
    retry_delay = current_app.config.get("WEBHOOK_RETRY_DELAY", _RETRY_DEFAULTS["delay"])
    retry_backoff = current_app.config.get("WEBHOOK_RETRY_BACKOFF", _RETRY_DEFAULTS["backoff"])
    retry_max_delay = current_app.config.get("WEBHOOK_RETRY_MAX_DELAY", _RETRY_DEFAULTS["max_delay"])

    retried_process = _retry(
        max_attempts=max_attempts,
        delay=retry_delay,
        backoff=retry_backoff,
        max_delay=retry_max_delay,
        exceptions=(RuntimeError, OSError),
    )(_process_stripe_event.__wrapped__ if hasattr(_process_stripe_event, "__wrapped__") else _process_stripe_event)

    try:
        retried_process(event_type, data)
    except Exception as exc:
        logger.error(f"Stripe event processing failed permanently: {exc}")
        return jsonify({"error": "Event processing failed"}), 500

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
        try:
            processed = _process_partner_json(data)
            return jsonify({"status": "ingested", "format": "json", "records": len(processed) if isinstance(processed, list) else 1})
        except Exception as e:
            logger.error(f"Partner JSON processing failed: {e}")
            return jsonify({"error": "Processing failed"}), 500

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
    payload = request.get_data()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    try:
        if not verify_slack_signature(payload, timestamp, signature, current_app.config["SLACK_SIGNING_SECRET"]):
            return jsonify({"error": "Invalid signature"}), 401
    except ValueError:
        return jsonify({"error": "Invalid signature"}), 401

    data = request.get_json()

    # Slack URL verification challenge
    if data.get("type") == "url_verification":
        return jsonify({"challenge": data.get("challenge")})

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
