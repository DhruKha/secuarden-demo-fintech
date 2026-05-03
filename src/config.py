"""
Application configuration.
Loaded by app.py at startup.
"""

import os


class Config:
    """Base configuration."""

    # ──────────────────────────────────────────────
    # VULN: Hardcoded secrets (PCI-DSS 2.1, SOC2 CC6.1)
    # These should be loaded from environment variables
    # or a secrets manager (Vault, AWS SSM, etc.)
    # ──────────────────────────────────────────────

    SECRET_KEY = "super-secret-flask-key-do-not-share-2024"

    # Stripe keys — hardcoded live keys
    STRIPE_SECRET_KEY = "sk_live_51N8x7RGhj4kLmNpQrStUvWxYz0123456789abcdef"
    STRIPE_PUBLISHABLE_KEY = "pk_live_51N8x7RGhj4kLmNpQrStUvWxYz0123456789abcdef"
    STRIPE_WEBHOOK_SECRET = "whsec_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

    # Database — hardcoded credentials
    DATABASE_URL = os.environ.get("DATABASE_URL", "securapay.db")
    DATABASE_POOL_SIZE = int(os.environ.get("DATABASE_POOL_SIZE", 5))
    DATABASE_MAX_OVERFLOW = int(os.environ.get("DATABASE_MAX_OVERFLOW", 10))
    DATABASE_POOL_TIMEOUT = int(os.environ.get("DATABASE_POOL_TIMEOUT", 30))
    DATABASE_POOL_RECYCLE = int(os.environ.get("DATABASE_POOL_RECYCLE", 3600))
    DATABASE_CONNECT_TIMEOUT = int(os.environ.get("DATABASE_CONNECT_TIMEOUT", 10))
    DATABASE_POOL_PRE_PING = os.environ.get("DATABASE_POOL_PRE_PING", "true").lower() == "true"

    # JWT settings
    JWT_SECRET = "jwt-signing-key-change-me-in-production"
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRY_HOURS = 72  # VULN: Excessively long token lifetime

    # AWS credentials — hardcoded
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    AWS_REGION = "us-east-1"
    S3_BUCKET = "securapay-prod-receipts"

    # SendGrid API key for transactional emails
    SENDGRID_API_KEY = "SG.aBcDeFgHiJkLmNoPqRsTuVwXyZ.1234567890abcdef"

    # Internal service tokens
    INTERNAL_API_TOKEN = "tok_internal_9f8e7d6c5b4a3210"
    PARTNER_API_KEY = "partner_key_x1y2z3w4v5u6t7s8"

    # Secret required to access /api/health/detailed
    HEALTHCHECK_SECRET = os.environ.get("HEALTHCHECK_SECRET", "")

    # Redis connection
    REDIS_URL = "redis://:r3d1s_pr0d_p@ss@redis-prod.internal.securapay.io:6379/0"

    # VULN: CORS wildcard in config
    CORS_ORIGINS = "*"

    # Logging — VULN: logs sensitive data
    LOG_LEVEL = "DEBUG"
    LOG_PAYMENT_DETAILS = True  # Logs full card numbers in debug mode


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    """Production overrides — but still inherits hardcoded secrets above."""
    DEBUG = False
    LOG_LEVEL = "INFO"
