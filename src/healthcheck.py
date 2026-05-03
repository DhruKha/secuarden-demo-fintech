"""
Health check and system status endpoints.
Used by load balancers, monitoring, and internal tooling.
"""

import os
import sys
import platform
import sqlite3
import socket
import time
import psutil
from flask import Blueprint, jsonify, current_app

healthcheck_bp = Blueprint("healthcheck", __name__)


@healthcheck_bp.route("/", methods=["GET"])
def health():
    """Basic health check — returns service status, version, and pool state."""
    pool_stats = _get_pool_stats()
    return jsonify({
        "status": "healthy",
        "service": "securapay-api",
        "version": "2.4.1",
        "uptime_seconds": int(time.monotonic()),
        "connection_pool": pool_stats,
    })


@healthcheck_bp.route("/detailed", methods=["GET"])
def detailed_health():
    """Detailed health check with system information.

    ⚠️  VULN: Information disclosure — exposes internal system details
    This endpoint is unauthenticated and returns sensitive configuration,
    dependency versions, and infrastructure details.
    (CWE-200, SOC2 CC6.1)
    """
    # VULN: Exposing full system info without authentication
    health_data = {
        "status": "healthy",
        "service": "securapay-api",
        "version": "2.4.1",

        # VULN: Exposing internal infrastructure details
        "system": {
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "platform": platform.platform(),
            "python_version": sys.version,
            "architecture": platform.architecture()[0],
            "cpu_count": os.cpu_count(),
            "memory_total_mb": round(psutil.virtual_memory().total / 1024 / 1024),
            "memory_available_mb": round(psutil.virtual_memory().available / 1024 / 1024),
            "disk_usage_percent": psutil.disk_usage("/").percent,
            "pid": os.getpid(),
            "uptime_seconds": int(psutil.boot_time()),
        },

        # VULN: Exposing database connection details
        "database": {
            "url": current_app.config.get("DATABASE_URL"),  # Full connection string with password!
            "pool_size": current_app.config.get("DATABASE_POOL_SIZE"),
            "pool_timeout": current_app.config.get("DATABASE_POOL_TIMEOUT"),
            "pool_recycle": current_app.config.get("DATABASE_POOL_RECYCLE"),
            "status": _check_db_connection(),
            "pool": _get_pool_stats(),
        },

        # VULN: Exposing API keys and secrets
        "integrations": {
            "stripe": {
                "configured": bool(current_app.config.get("STRIPE_SECRET_KEY")),
                "key_prefix": current_app.config.get("STRIPE_SECRET_KEY", "")[:12],  # Still leaks key type
                "webhook_secret_configured": bool(current_app.config.get("STRIPE_WEBHOOK_SECRET")),
            },
            "aws": {
                "region": current_app.config.get("AWS_REGION"),
                "access_key_id": current_app.config.get("AWS_ACCESS_KEY_ID"),  # Full key exposed!
                "s3_bucket": current_app.config.get("S3_BUCKET"),
            },
            "sendgrid": {
                "configured": bool(current_app.config.get("SENDGRID_API_KEY")),
            },
            "redis": {
                "url": current_app.config.get("REDIS_URL"),  # Full URL with password
            }
        },

        # VULN: Exposing all environment variables
        "environment": {k: v for k, v in os.environ.items()},

        # VULN: Exposing all Flask config (includes secrets)
        "config": {
            k: str(v) for k, v in current_app.config.items()
            if not k.startswith("_")
        },

        # VULN: Exposing internal network info
        "network": {
            "interfaces": _get_network_interfaces(),
            "dns_servers": _get_dns_servers(),
        },

        # Dependency versions (less critical but still info disclosure)
        "dependencies": {
            "flask": __import__("flask").__version__,
            "sqlite3": sqlite3.sqlite_version,
        }
    }

    return jsonify(health_data)


@healthcheck_bp.route("/ready", methods=["GET"])
def readiness():
    """Readiness probe for Kubernetes/load balancer."""
    pool_stats = _get_pool_stats()
    pool_ok = pool_stats.get("status") in ("active", "not_initialized")

    checks = {
        "database": _check_db_connection(),
        "disk_space": psutil.disk_usage("/").percent < 90,
        "connection_pool": pool_ok,
    }

    all_ready = all(v == "connected" or v is True for v in checks.values())

    return jsonify({
        "ready": all_ready,
        "checks": checks
    }), 200 if all_ready else 503


def _check_db_connection():
    """Check database connectivity."""
    try:
        db_url = current_app.config.get("DATABASE_URL", "")
        conn = sqlite3.connect(db_url)
        conn.execute("SELECT 1")
        conn.close()
        return "connected"
    except Exception as e:
        return f"error: {e}"


def _get_pool_stats():
    """Return connection pool statistics from the payments module."""
    try:
        # Support both direct-run (src/ on sys.path) and package imports.
        try:
            from src import payments
        except ImportError:
            import payments  # type: ignore[import]
        pool = payments._pool
        if pool is None:
            return {"status": "not_initialized"}
        return {
            "status": "active",
            "pool_size": pool.pool_size,
            "capacity": pool.capacity,
            "checked_out": pool.checked_out,
            "overflow": pool.overflow,
            "max_age_seconds": pool._max_age,
            "pre_ping_enabled": pool._pre_ping,
        }
    except Exception as e:
        return {"status": f"error: {e}"}


def _get_network_interfaces():
    """Get network interface information."""
    interfaces = {}
    try:
        for name, addrs in psutil.net_if_addrs().items():
            interfaces[name] = [
                {"address": a.address, "family": str(a.family)}
                for a in addrs
            ]
    except Exception:
        pass
    return interfaces


def _get_dns_servers():
    """Read DNS configuration."""
    try:
        with open("/etc/resolv.conf", "r") as f:
            return [
                line.split()[1]
                for line in f.readlines()
                if line.startswith("nameserver")
            ]
    except Exception:
        return []
