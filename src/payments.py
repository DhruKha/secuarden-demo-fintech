"""
Payment processing module.
Handles charges, refunds, and transaction queries.
"""

import logging
import sqlite3
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app

payments_bp = Blueprint("payments", __name__)
logger = logging.getLogger(__name__)


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(current_app.config["DATABASE_URL"])
    conn.row_factory = sqlite3.Row
    return conn


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
