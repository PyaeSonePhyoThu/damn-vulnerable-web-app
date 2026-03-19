import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify
from database import get_db
from routes.auth import jwt_required

transactions_bp = Blueprint('transactions', __name__)

SUBSCRIPTION_LIMITS = {
    'bronze': {'transfer_limit': 1000,   'daily_limit': 3000},
    'silver': {'transfer_limit': 5000,   'daily_limit': 15000},
    'gold':   {'transfer_limit': 50000,  'daily_limit': 100000},
}


TRANSFER_FEE_RATE = 0.02  # 2% fee on every transfer


@transactions_bp.route('/api/transfer', methods=['POST'])
@jwt_required
def transfer():
    data         = request.get_json() or {}
    from_account = data.get('from_account', '').strip()
    to_account   = data.get('to_account', '').strip()
    amount       = data.get('amount')
    description  = data.get('description', 'Transfer')
    user_id      = request.current_user['user_id']

    if not from_account or not to_account or amount is None:
        return jsonify({'error': 'from_account, to_account, and amount are required'}), 400

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400

    # Transfer fee — 2% of amount, deducted from sender on top of the transfer amount
    # VULN: BL-1 — fee is accepted from the client; no server-side validation prevents
    # a negative fee value, which credits the sender instead of charging them.
    try:
        fee = float(data['fee']) if 'fee' in data else round(amount * TRANSFER_FEE_RATE, 2)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid fee'}), 400

    db = get_db()

    # Ownership check — verify from_account belongs to current user (not IDOR, SQLi is the challenge)
    sender = db.execute(
        'SELECT * FROM accounts WHERE account_number = ? AND user_id = ?',
        (from_account, user_id)
    ).fetchone()
    if not sender:
        db.close()
        return jsonify({'error': 'Source account not found or not yours'}), 404

    recipient = db.execute(
        'SELECT * FROM accounts WHERE account_number = ?',
        (to_account,)
    ).fetchone()
    if not recipient:
        db.close()
        return jsonify({'error': 'Destination account not found'}), 404

    # VULN: A04 — Negative transfer amounts allowed; sender gets credited
    sub    = request.current_user.get('subscription_type', 'bronze')
    limits = SUBSCRIPTION_LIMITS.get(sub, SUBSCRIPTION_LIMITS['bronze'])

    # VULN: A04 — Limit check only checks positive; negative amounts pass and reverse funds
    if amount > limits['transfer_limit']:
        db.close()
        return jsonify({'error': f"Transfer limit exceeded for {sub} tier (${limits['transfer_limit']:,})"}), 400

    # VULN: A04 — No rate limiting
    # VULN: A04 — No check that sender has sufficient funds (negative balance possible)
    # VULN: BL-1 — fee is client-supplied; negative fee adds money to sender's balance
    new_sender_balance    = sender['balance'] - amount - fee
    new_recipient_balance = recipient['balance'] + amount

    db.execute('UPDATE accounts SET balance = ? WHERE account_number = ?',
               (new_sender_balance, from_account))
    db.execute('UPDATE accounts SET balance = ? WHERE account_number = ?',
               (new_recipient_balance, to_account))

    tx_id = str(uuid.uuid4())
    db.execute(
        'INSERT INTO transactions (id, from_account, to_account, amount, description) VALUES (?,?,?,?,?)',
        (tx_id, from_account, to_account, amount, description)
    )
    db.commit()
    db.close()

    # VULN: A09 — Transfer not logged for security monitoring
    return jsonify({
        'message':           'Transfer successful',
        'transaction_id':    tx_id,
        'amount':            amount,
        'fee':               fee,
        'from_account':      from_account,
        'to_account':        to_account,
        'new_balance':       new_sender_balance,
    }), 200


@transactions_bp.route('/api/transactions', methods=['GET'])
@jwt_required
def get_transactions():
    user_id    = request.current_user['user_id']
    account_id = request.args.get('account', '')

    db = get_db()

    # Ownership check — only return transactions for accounts owned by current user
    if account_id:
        owned = db.execute(
            'SELECT account_number FROM accounts WHERE account_number = ? AND user_id = ?',
            (account_id, user_id)
        ).fetchone()
        if not owned:
            db.close()
            return jsonify({'error': 'Account not found or not yours'}), 404

        rows = db.execute(
            '''SELECT * FROM transactions
               WHERE from_account = ? OR to_account = ?
               ORDER BY created_at DESC LIMIT 50''',
            (account_id, account_id)
        ).fetchall()
    else:
        rows = db.execute(
            '''SELECT * FROM transactions
               WHERE from_account IN (SELECT account_number FROM accounts WHERE user_id = ?)
                  OR to_account   IN (SELECT account_number FROM accounts WHERE user_id = ?)
               ORDER BY created_at DESC LIMIT 50''',
            (user_id, user_id)
        ).fetchall()

    db.close()
    return jsonify([dict(r) for r in rows]), 200
