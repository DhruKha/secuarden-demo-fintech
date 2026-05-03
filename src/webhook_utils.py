"""
Webhook signature verification utilities.
"""

import hashlib
import hmac


def verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    """Verify a Stripe webhook signature using constant-time comparison."""
    if not sig_header.startswith("sha256="):
        raise ValueError(f"Malformed Stripe-Signature header: {sig_header!r}")
    provided = sig_header[len("sha256="):]
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided)


def verify_slack_signature(payload: bytes, timestamp: str, signature: str, secret: str) -> bool:
    """Verify a Slack webhook signature using constant-time comparison."""
    if not timestamp or not signature or not secret:
        raise ValueError("Missing required inputs for Slack signature verification")
    if not signature.startswith("v0="):
        raise ValueError(f"Malformed Slack signature: {signature!r}")
    basestring = f"v0:{timestamp}:{payload.decode()}"
    expected = "v0=" + hmac.new(secret.encode(), basestring.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
