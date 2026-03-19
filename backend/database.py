import sqlite3
import uuid
import hashlib
import secrets
import os
from datetime import datetime

DB_PATH = os.environ.get('DB_PATH', '/app/backend/data/vulnbank.db')
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://mongo:27017/')


def md5(p):
    # VULN: A02 — MD5, no salt
    return hashlib.md5(p.encode()).hexdigest()


# Seeded users with deterministic UUIDs
USERS = [
    {
        'id': str(uuid.UUID(int=1)),
        'username': 'alice',
        'email': 'alice@vulnbank.local',
        'password_hash': md5('password123'),
        'password_plain': 'password123',
        'full_name': 'Alice Johnson',
        'phone': '+1-555-0101',
        'ssn': '123-45-6789',
        'subscription_type': 'gold',
        'address': '123 Gold St, New York, NY',
    },
    {
        'id': str(uuid.UUID(int=2)),
        'username': 'bob',
        'email': 'bob@vulnbank.local',
        'password_hash': md5('letmein'),
        'password_plain': 'letmein',
        'full_name': 'Bob Smith',
        'phone': '+1-555-0102',
        'ssn': '987-65-4321',
        'subscription_type': 'silver',
        'address': '456 Silver Ave, Chicago, IL',
    },
    {
        'id': str(uuid.UUID(int=5)),
        'username': 'aungkyawsein',
        'email': 'aungkyawsein@vulnbank.local',
        'password_hash': md5('hackeme123'),
        'password_plain': 'hackeme123',
        'full_name': 'Aung Kyaw Sein',
        'phone': '+95-9-123-456789',
        'ssn': '654-32-1098',
        'subscription_type': 'bronze',
        'address': '47 Pyay Road, Yangon, Myanmar',
    },
]

# Deterministic account numbers
ACCOUNT_SEEDS = [
    ('alice', 'savings', 15000.00),
    ('alice', 'checking', 3200.50),
    ('bob', 'savings', 7500.00),
    ('bob', 'checking', 1200.00),
    ('aungkyawsein', 'savings', 850.00),
    ('aungkyawsein', 'checking', 200.00),
]


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()

    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id               TEXT PRIMARY KEY,
            username         TEXT UNIQUE NOT NULL,
            email            TEXT UNIQUE NOT NULL,
            password_hash    TEXT NOT NULL,
            full_name        TEXT,
            phone            TEXT,
            address          TEXT,
            ssn              TEXT,
            subscription_type TEXT DEFAULT 'bronze',
            avatar_url       TEXT,
            is_active        INTEGER DEFAULT 1,
            created_at       TEXT DEFAULT CURRENT_TIMESTAMP,
            reset_token      TEXT,
            reset_token_expiry TEXT,
            otp              TEXT,
            otp_expiry       TEXT
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id             TEXT PRIMARY KEY,
            user_id        TEXT NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            account_type   TEXT DEFAULT 'savings',
            balance        REAL DEFAULT 0.0,
            currency       TEXT DEFAULT 'USD',
            created_at     TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id             TEXT PRIMARY KEY,
            from_account   TEXT NOT NULL,
            to_account     TEXT NOT NULL,
            amount         REAL NOT NULL,
            description    TEXT,
            status         TEXT DEFAULT 'completed',
            created_at     TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS cards (
            id             TEXT PRIMARY KEY,
            user_id        TEXT NOT NULL,
            account_id     TEXT NOT NULL,
            card_number    TEXT NOT NULL,
            card_type      TEXT NOT NULL,
            expiry_date    TEXT NOT NULL,
            cvv            TEXT NOT NULL,
            card_holder    TEXT NOT NULL,
            is_active      INTEGER DEFAULT 1,
            created_at     TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    # Seed users if not present
    for u in USERS:
        existing = c.execute('SELECT id FROM users WHERE username = ?', (u['username'],)).fetchone()
        if not existing:
            # VULN: A02 — otp column left NULL for fresh accounts (enables null bypass VD-4b)
            c.execute(
                '''INSERT INTO users
                   (id, username, email, password_hash, full_name, phone, address, ssn, subscription_type, otp)
                   VALUES (?,?,?,?,?,?,?,?,?,NULL)''',
                (u['id'], u['username'], u['email'], u['password_hash'],
                 u['full_name'], u['phone'], u['address'], u['ssn'], u['subscription_type'])
            )

    db.commit()

    # Seed accounts
    acc_idx = 0
    for username, acc_type, balance in ACCOUNT_SEEDS:
        user = c.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if not user:
            continue
        user_id = user['id']
        # Deterministic account number using seed
        acc_num = f"ACC-{hashlib.md5(f'{username}{acc_type}'.encode()).hexdigest()[:8].upper()}"
        acc_id = str(uuid.UUID(int=acc_idx + 100))
        acc_idx += 1
        existing = c.execute('SELECT id FROM accounts WHERE account_number = ?', (acc_num,)).fetchone()
        if not existing:
            c.execute(
                'INSERT INTO accounts (id, user_id, account_number, account_type, balance) VALUES (?,?,?,?,?)',
                (acc_id, user_id, acc_num, acc_type, balance)
            )
    db.commit()

    # Seed some transactions
    alice_acc = c.execute("SELECT account_number FROM accounts WHERE user_id = ? AND account_type = 'savings'",
                          (str(uuid.UUID(int=1)),)).fetchone()
    bob_acc = c.execute("SELECT account_number FROM accounts WHERE user_id = ? AND account_type = 'savings'",
                        (str(uuid.UUID(int=2)),)).fetchone()
    aung_acc = c.execute("SELECT account_number FROM accounts WHERE user_id = ? AND account_type = 'savings'",
                         (str(uuid.UUID(int=5)),)).fetchone()

    if alice_acc and bob_acc:
        tx_count = c.execute('SELECT COUNT(*) FROM transactions').fetchone()[0]
        if tx_count == 0:
            sample_txns = [
                (str(uuid.uuid4()), alice_acc[0], bob_acc[0], 500.00, 'Payment for services', '2025-02-01 10:00:00'),
                (str(uuid.uuid4()), bob_acc[0], alice_acc[0], 200.00, 'Rent share', '2025-02-05 14:30:00'),
                (str(uuid.uuid4()), alice_acc[0], aung_acc[0] if aung_acc else 'ACC-UNKNOWN', 150.00, 'Overseas transfer', '2025-02-10 12:00:00'),
                (str(uuid.uuid4()), bob_acc[0], aung_acc[0] if aung_acc else 'ACC-UNKNOWN', 75.00, 'Reimbursement', '2025-02-15 09:00:00'),
            ]
            for tx in sample_txns:
                c.execute(
                    'INSERT INTO transactions (id, from_account, to_account, amount, description, created_at) VALUES (?,?,?,?,?,?)',
                    tx
                )
            db.commit()

    # Seed cards
    card_seeds = [
        (str(uuid.UUID(int=1)), str(uuid.UUID(int=100)), 'Alice Johnson', 'debit', '4532-1234-5678-9012', '12/27', '123'),
        (str(uuid.UUID(int=1)), str(uuid.UUID(int=100)), 'Alice Johnson', 'platinum', '5412-7534-1234-5678', '06/28', '456'),
        (str(uuid.UUID(int=2)), str(uuid.UUID(int=102)), 'Bob Smith', 'debit', '4111-1111-1111-1111', '09/26', '789'),
        (str(uuid.UUID(int=2)), str(uuid.UUID(int=102)), 'Bob Smith', 'credit', '5500-0000-0000-0004', '03/27', '321'),
        (str(uuid.UUID(int=5)), str(uuid.UUID(int=104)), 'Aung Kyaw Sein', 'debit', '4532-9900-1234-5670', '05/27', '369'),
    ]
    card_count = c.execute('SELECT COUNT(*) FROM cards').fetchone()[0]
    if card_count == 0:
        for i, (user_id, acc_id, holder, ctype, cnum, expiry, cvv) in enumerate(card_seeds):
            c.execute(
                'INSERT INTO cards (id, user_id, account_id, card_number, card_type, expiry_date, cvv, card_holder) VALUES (?,?,?,?,?,?,?,?)',
                (str(uuid.UUID(int=200 + i)), user_id, acc_id, cnum, ctype, expiry, cvv, holder)
            )
    db.commit()
    db.close()


def init_mongo():
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        auth_db = client['vulnbank_auth']
        if auth_db.users.count_documents({}) == 0:
            # VULN: A02 — plaintext passwords in MongoDB
            for u in USERS:
                auth_db.users.insert_one({
                    'username': u['username'],
                    'email': u['email'],
                    'password': u['password_plain'],  # VULN: A02 — plaintext
                    'subscription_type': u['subscription_type'],
                    'user_id': u['id'],
                })
    except Exception as e:
        print(f"[WARN] MongoDB init failed: {e}")
