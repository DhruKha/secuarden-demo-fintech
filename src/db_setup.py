"""
Database schema and seed data.
Run: python db_setup.py
"""

import sqlite3
import hashlib
from datetime import datetime, timedelta
import random


def create_tables(db):
    """Create application tables."""
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            role TEXT DEFAULT 'user',
            reset_token TEXT,
            phone TEXT,
            ssn_last_four TEXT,
            last_login TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            card_number TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'usd',
            customer_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            refund_reason TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            user_id TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
        );
    """)


def seed_data(db):
    """Insert demo data."""
    # Users — passwords are MD5 hashed (intentionally weak)
    users = [
        ("usr_001", "admin@securapay.io", hashlib.md5(b"admin123").hexdigest(), "Admin User", "admin", None, "+1-555-0100", "1234"),
        ("usr_002", "sarah@acme.com", hashlib.md5(b"password1").hexdigest(), "Sarah Chen", "developer", None, "+1-555-0101", "5678"),
        ("usr_003", "mike@acme.com", hashlib.md5(b"letmein").hexdigest(), "Mike Ross", "developer", None, "+1-555-0102", "9012"),
        ("usr_004", "finance@securapay.io", hashlib.md5(b"finance2024").hexdigest(), "Finance Team", "finance", None, "+1-555-0103", "3456"),
        ("usr_005", "customer1@example.com", hashlib.md5(b"mypassword").hexdigest(), "Jane Doe", "user", None, "+1-555-0200", "7890"),
    ]

    for u in users:
        db.execute(
            "INSERT OR IGNORE INTO users (id, email, password_hash, name, role, reset_token, phone, ssn_last_four, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (*u, datetime.utcnow().isoformat())
        )

    # Transactions — with full card numbers (PCI-DSS violation)
    cards = [
        "4111111111111111",
        "4242424242424242",
        "5555555555554444",
        "378282246310005",
    ]

    statuses = ["completed", "completed", "completed", "pending", "refunded"]

    for i in range(50):
        txn_id = f"txn_{i:04d}"
        card = random.choice(cards)
        amount = round(random.uniform(9.99, 4999.99), 2)
        customer = random.choice(["usr_002", "usr_003", "usr_005"])
        status = random.choice(statuses)
        created = (datetime.utcnow() - timedelta(days=random.randint(0, 90))).isoformat()

        db.execute(
            "INSERT OR IGNORE INTO transactions (id, card_number, amount, currency, customer_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (txn_id, card, amount, "usd", customer, status, created)
        )

    db.commit()


if __name__ == "__main__":
    conn = sqlite3.connect("securapay.db")
    create_tables(conn)
    seed_data(conn)
    conn.close()
    print("Database created and seeded successfully.")
