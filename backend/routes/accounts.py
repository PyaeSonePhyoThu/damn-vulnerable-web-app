from flask import Blueprint, request, jsonify
from database import get_db
from routes.auth import jwt_required

accounts_bp = Blueprint('accounts', __name__)

SUBSCRIPTION_LIMITS = {
    'bronze': {'transfer_limit': 1000,   'daily_limit': 3000},
    'silver': {'transfer_limit': 5000,   'daily_limit': 15000},
    'gold':   {'transfer_limit': 50000,  'daily_limit': 100000},
}


@accounts_bp.route('/api/accounts', methods=['GET'])
@jwt_required
def get_accounts():
    user_id = request.current_user['user_id']
    db      = get_db()
    rows    = db.execute('SELECT * FROM accounts WHERE user_id = ?', (user_id,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows]), 200


@accounts_bp.route('/api/account/<path:account_uuid>', methods=['GET'])
@jwt_required
def get_account(account_uuid):
    db      = get_db()
    user_id = request.current_user['user_id']

    # VULN: A03-SQL — account_uuid is injected raw into the query (path:converter preserves special chars)
    # The AND user_id clause gives false sense of security; OR 1=1-- bypasses it
    # Attack: GET /api/account/x' OR '1'='1
    query = f"SELECT * FROM accounts WHERE id = '{account_uuid}' AND user_id = '{user_id}'"
    try:
        rows = db.execute(query).fetchall()
    except Exception as e:
        db.close()
        # VULN: A05 — raw DB error message exposed
        return jsonify({'error': str(e)}), 500

    db.close()
    if not rows:
        return jsonify({'error': 'Account not found'}), 404
    return jsonify([dict(r) for r in rows]), 200


@accounts_bp.route('/api/accounts/search', methods=['GET'])
@jwt_required
def search_accounts():
    name = request.args.get('q', '')

    db = get_db()
    # VULN: A03-SQL — second SQL injection surface via search query
    query = (
        f"SELECT a.*, u.username, u.email, u.ssn "
        f"FROM accounts a JOIN users u ON a.user_id = u.id "
        f"WHERE u.full_name LIKE '%{name}%'"
    )
    try:
        rows = db.execute(query).fetchall()
    except Exception as e:
        db.close()
        # VULN: A05 — raw error exposed
        return jsonify({'error': str(e)}), 500

    db.close()
    return jsonify([dict(r) for r in rows]), 200


@accounts_bp.route('/api/subscription/limits', methods=['GET'])
@jwt_required
def get_limits():
    sub    = request.current_user.get('subscription_type', 'bronze')
    limits = SUBSCRIPTION_LIMITS.get(sub, SUBSCRIPTION_LIMITS['bronze'])
    return jsonify({'subscription': sub, 'limits': limits}), 200
