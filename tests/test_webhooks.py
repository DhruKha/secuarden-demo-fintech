"""
Tests for webhook signature verification and endpoints.
"""

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def client():
    from app import app
    import payments

    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    app.config["TESTING"] = True
    app.config["DATABASE_URL"] = db_path
    app.config["STRIPE_WEBHOOK_SECRET"] = "test_stripe_secret"
    app.config["SLACK_SIGNING_SECRET"] = "test_slack_secret"

    payments._pool = None

    with app.test_client() as client:
        yield client

    payments._pool = None
    os.unlink(db_path)


def _stripe_sig(payload: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _slack_sig(payload: bytes, timestamp: str, secret: str) -> str:
    basestring = f"v0:{timestamp}:{payload.decode()}"
    digest = hmac.new(secret.encode(), basestring.encode(), hashlib.sha256).hexdigest()
    return f"v0={digest}"


# ── verify_stripe_signature unit tests ──────────────────────────────────────

def test_verify_stripe_signature_valid():
    from webhook_utils import verify_stripe_signature
    payload = b'{"type": "payment_intent.succeeded"}'
    secret = "whsec_test123"
    sig = _stripe_sig(payload, secret)
    assert verify_stripe_signature(payload, sig, secret) is True


def test_verify_stripe_signature_invalid():
    from webhook_utils import verify_stripe_signature
    payload = b'{"type": "payment_intent.succeeded"}'
    secret = "whsec_test123"
    assert verify_stripe_signature(payload, "sha256=deadbeef00112233", secret) is False


def test_verify_stripe_signature_malformed_raises():
    from webhook_utils import verify_stripe_signature
    with pytest.raises(ValueError):
        verify_stripe_signature(b"payload", "badsig", "secret")


# ── verify_slack_signature unit tests ───────────────────────────────────────

def test_verify_slack_signature_valid():
    from webhook_utils import verify_slack_signature
    payload = b'{"type": "event_callback"}'
    secret = "slack_signing_secret"
    ts = str(int(time.time()))
    sig = _slack_sig(payload, ts, secret)
    assert verify_slack_signature(payload, ts, sig, secret) is True


def test_verify_slack_signature_tampered():
    from webhook_utils import verify_slack_signature
    payload = b'{"type": "event_callback"}'
    secret = "slack_signing_secret"
    ts = str(int(time.time()))
    sig = _slack_sig(payload, ts, secret)
    tampered = b'{"type": "malicious"}'
    assert verify_slack_signature(tampered, ts, sig, secret) is False


def test_verify_slack_signature_missing_raises():
    from webhook_utils import verify_slack_signature
    with pytest.raises(ValueError):
        verify_slack_signature(b"payload", "", "v0=abc", "secret")


# ── endpoint integration tests ───────────────────────────────────────────────

def test_stripe_webhook_wrong_signature(client):
    payload = json.dumps({"type": "payment_intent.succeeded", "data": {"object": {}}}).encode()
    response = client.post(
        "/api/webhooks/stripe",
        data=payload,
        content_type="application/json",
        headers={"Stripe-Signature": "sha256=wrongsignature"},
    )
    assert response.status_code == 401


def test_stripe_webhook_valid_signature(client):
    payload = json.dumps({"type": "payment_intent.succeeded", "data": {"object": {}}}).encode()
    sig = _stripe_sig(payload, "test_stripe_secret")
    response = client.post(
        "/api/webhooks/stripe",
        data=payload,
        content_type="application/json",
        headers={"Stripe-Signature": sig},
    )
    assert response.status_code == 200


def test_slack_events_missing_signature(client):
    payload = json.dumps({"type": "event_callback", "event": {"type": "message", "text": "hello", "user": "U123"}}).encode()
    response = client.post(
        "/api/webhooks/slack/events",
        data=payload,
        content_type="application/json",
    )
    assert response.status_code == 401


def test_slack_events_valid_signature(client):
    payload = json.dumps({"type": "event_callback", "event": {"type": "message", "text": "hello", "user": "U123"}}).encode()
    ts = str(int(time.time()))
    sig = _slack_sig(payload, ts, "test_slack_secret")
    response = client.post(
        "/api/webhooks/slack/events",
        data=payload,
        content_type="application/json",
        headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig},
    )
    assert response.status_code == 200
