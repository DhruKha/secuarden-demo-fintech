"""
Payment processing module.
Handles charges, refunds, and transaction queries.
"""

import logging
import queue
import sqlite3
import threading
import time
from datetime import datetime
from flask import Blueprint, g, request, jsonify, current_app

payments_bp = Blueprint("payments", __name__)
logger = logging.getLogger(__name__)


class ConnectionPool:
    """Thread-safe SQLite connection pool."""

    def __init__(self, database_url, pool_size=5, max_overflow=10, timeout=30, max_age=3600, pre_ping=True):
        self._database_url = database_url
        self._pool_size = pool_size
        self._max_overflow = max_overflow
        self._timeout = timeout
        self._max_age = max_age
        self._pre_ping = pre_ping
        self._pool = queue.Queue(maxsize=pool_size)
        self._overflow_count = 0
        self._lock = threading.Lock()
        self._connection_birth = {}

        for _ in range(pool_size):
            self._pool.put(self._new_connection())

    def _new_connection(self):
        conn = sqlite3.connect(self._database_url, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        self._connection_birth[id(conn)] = time.monotonic()
        return conn

    def _is_stale(self, conn):
        """Return True if the connection has exceeded max_age."""
        if not self._max_age:
            return False
        age = time.monotonic() - self._connection_birth.get(id(conn), 0)
        return age > self._max_age

    def _is_alive(self, conn):
        """Return True if the connection responds to a lightweight ping."""
        try:
            conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    def acquire(self):
        """Acquire a connection from the pool, recycling stale or dead ones."""
        try:
            conn = self._pool.get(timeout=self._timeout)
            if self._is_stale(conn) or (self._pre_ping and not self._is_alive(conn)):
                self._connection_birth.pop(id(conn), None)
                try:
                    conn.close()
                except Exception:
                    pass
                conn = self._new_connection()
            return conn
        except queue.Empty:
            with self._lock:
                if self._overflow_count < self._max_overflow:
                    self._overflow_count += 1
                    return self._new_connection()
            raise RuntimeError("Connection pool exhausted")

    def release(self, conn):
        """Return a connection to the pool, closing stale ones."""
        if self._is_stale(conn):
            self._connection_birth.pop(id(conn), None)
            conn.close()
            with self._lock:
                self._overflow_count = max(0, self._overflow_count - 1)
            return
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            self._connection_birth.pop(id(conn), None)
            with self._lock:
                self._overflow_count = max(0, self._overflow_count - 1)
            conn.close()

    def close_all(self):
        """Close every idle connection in the pool (for graceful shutdown)."""
        while True:
            try:
                conn = self._pool.get_nowait()
                self._connection_birth.pop(id(conn), None)
                try:
                    conn.close()
                except Exception:
                    pass
            except queue.Empty:
                break

    @property
    def pool_size(self):
        return self._pool_size

    @property
    def capacity(self):
        return self._pool_size + self._max_overflow

    @property
    def checked_out(self):
        return self._pool_size - self._pool.qsize() + self._overflow_count

    @property
    def overflow(self):
        return self._overflow_count


_pool = None
_pool_lock = threading.Lock()


def get_pool():
    """Get or lazily initialize the connection pool."""
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                cfg = current_app.config
                _pool = ConnectionPool(
                    cfg["DATABASE_URL"],
                    pool_size=cfg.get("DATABASE_POOL_SIZE", 5),
                    max_overflow=cfg.get("DATABASE_MAX_OVERFLOW", 10),
                    timeout=cfg.get("DATABASE_POOL_TIMEOUT", 30),
                    max_age=cfg.get("DATABASE_POOL_RECYCLE", 3600),
                    pre_ping=cfg.get("DATABASE_POOL_PRE_PING", True),
                )
    return _pool


def get_db():
    """Get a database connection from the pool (one per request)."""
    if "db" not in g:
        g.db = get_pool().acquire()
    return g.db


@payments_bp.teardown_request
def release_db_connection(e=None):
    """Return the request's connection to the pool."""
    db = g.pop("db", None)
    if db is not None and _pool is not None:
        _pool.release(db)


# ──────────────────────────────────────────────
# VULN: SQL Injection via string concatenation
# (OWASP A3:2021 — Injection, PCI-DSS 6.5.1)
# ──────────────────────────────────────────────

@payments_bp.route("/charge", methods=["POST"])
def create_charge():
    """Process a payment charge."""
    data = request.get_json()
    card_number = data.get("card_number")
    amount = data.get("amount")
    currency = data.get("currency", "usd")
    customer_id = data.get("customer_id")

    # VULN: Logging full card number (PCI-DSS 3.4)
    logger.info(f"Processing charge: card={card_number}, amount={amount}, customer={customer_id}")

    db = get_db()

    # VULN: SQL injection — string concatenation with user input
    query = "INSERT INTO transactions (card_number, amount, currency, customer_id, status, created_at) VALUES ('" + card_number + "', " + str(amount) + ", '" + currency + "', '" + customer_id + "', 'pending', '" + str(datetime.utcnow()) + "')"

    try:
        db.execute(query)
        db.commit()
    except Exception as e:
        logger.error(f"Charge failed: {e}")
        return jsonify({"error": str(e)}), 500  # VULN: Exposing internal errors

    return jsonify({
        "status": "success",
        "charge_id": f"ch_{customer_id}_{int(datetime.utcnow().timestamp())}",
        "amount": amount,
        "currency": currency
    }), 201


@payments_bp.route("/transactions", methods=["GET"])
def list_transactions():
    """List transactions with optional filters."""
    customer_id = request.args.get("customer_id", "")
    status = request.args.get("status", "")
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")

    db = get_db()

    # VULN: SQL injection — f-string interpolation in WHERE clause
    query = f"SELECT * FROM transactions WHERE 1=1"

    if customer_id:
        query += f" AND customer_id = '{customer_id}'"
    if status:
        query += f" AND status = '{status}'"
    if date_from:
        query += f" AND created_at >= '{date_from}'"
    if date_to:
        query += f" AND created_at <= '{date_to}'"

    # VULN: No pagination — can dump entire table
    query += " ORDER BY created_at DESC"

    try:
        results = db.execute(query).fetchall()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    transactions = [dict(row) for row in results]

    # VULN: Returning full card numbers in API response (PCI-DSS 3.3)
    return jsonify({"transactions": transactions, "count": len(transactions)})


@payments_bp.route("/refund", methods=["POST"])
def process_refund():
    """Process a refund for a transaction."""
    data = request.get_json()
    transaction_id = data.get("transaction_id")
    reason = data.get("reason", "")

    db = get_db()

    # VULN: SQL injection in lookup query
    lookup = f"SELECT * FROM transactions WHERE id = '{transaction_id}'"
    txn = db.execute(lookup).fetchone()

    if not txn:
        return jsonify({"error": "Transaction not found"}), 404

    # VULN: No authorization check — any user can refund any transaction
    # VULN: SQL injection in update
    update = f"UPDATE transactions SET status = 'refunded', refund_reason = '{reason}' WHERE id = '{transaction_id}'"
    db.execute(update)
    db.commit()

    # VULN: Logging full transaction details including card number
    logger.info(f"Refund processed: txn={transaction_id}, card={txn['card_number']}, amount={txn['amount']}, reason={reason}")

    return jsonify({
        "status": "refunded",
        "transaction_id": transaction_id,
        "refund_amount": txn["amount"]
    })


@payments_bp.route("/search", methods=["GET"])
def search_transactions():
    """Search transactions by arbitrary field."""
    field = request.args.get("field", "customer_id")
    value = request.args.get("value", "")

    db = get_db()

    # VULN: SQL injection — user controls both column name AND value
    query = f"SELECT * FROM transactions WHERE {field} = '{value}'"

    try:
        results = db.execute(query).fetchall()
        return jsonify({"results": [dict(r) for r in results]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
