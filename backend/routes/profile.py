import os
from flask import Blueprint, request, jsonify
from database import get_db
from routes.auth import jwt_required

profile_bp = Blueprint('profile', __name__)

# VULN: MA-1 — subscription_type is included in writable fields (no validation on value)
ALLOWED_FIELDS = [
    'full_name',
    'phone',
    'address',
    'email',
    'subscription_type',  # VULN: MA-1 — user can self-upgrade to gold
]


@profile_bp.route('/api/profile', methods=['GET'])
@jwt_required
def get_profile():
    user_id = request.current_user['user_id']
    db      = get_db()
    user    = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # VULN: A02 — SSN and sensitive data returned in profile response
    return jsonify({
        'id':                user['id'],
        'username':          user['username'],
        'email':             user['email'],
        'full_name':         user['full_name'],
        'phone':             user['phone'],
        'address':           user['address'],
        'ssn':               user['ssn'],   # VULN: A02 — plaintext SSN exposed
        'subscription_type': user['subscription_type'],
        'avatar_url':        user['avatar_url'],
        'created_at':        user['created_at'],
    }), 200


@profile_bp.route('/api/profile/update', methods=['POST'])
@jwt_required
def update_profile():
    data    = request.get_json() or {}
    user_id = request.current_user['user_id']

    db = get_db()

    # VULN: MA-1 — build SET clause from whatever keys appear that match ALLOWED_FIELDS
    # subscription_type is in ALLOWED_FIELDS with no value validation
    updates = {}
    for field in ALLOWED_FIELDS:
        if field in data:
            updates[field] = data[field]

    if not updates:
        db.close()
        return jsonify({'error': 'No fields to update'}), 400

    set_clause = ', '.join([f'{k} = ?' for k in updates.keys()])
    values     = list(updates.values()) + [user_id]

    db.execute(f'UPDATE users SET {set_clause} WHERE id = ?', values)
    db.commit()

    # Return updated user
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()

    # VULN: A09 — Profile update (including subscription escalation) not logged
    return jsonify({
        'message':           'Profile updated',
        'subscription_type': user['subscription_type'],
        'full_name':         user['full_name'],
        'email':             user['email'],
        'phone':             user['phone'],
        'address':           user['address'],
    }), 200


@profile_bp.route('/api/profile/avatar', methods=['POST'])
@jwt_required
def upload_avatar():
    file = request.files.get('avatar')
    if not file:
        return jsonify({'error': 'No file provided'}), 400

    # VULN: VD-SVG — No MIME type check, no extension whitelist, no content scan
    # SVG files with embedded <script> will execute when browsed directly
    filename  = file.filename  # VULN: A08 — original filename used, no sanitisation
    save_path = os.path.join('/app/backend/uploads', filename)
    file.save(save_path)

    avatar_url = f'/uploads/{filename}'
    user_id    = request.current_user['user_id']

    db = get_db()
    db.execute('UPDATE users SET avatar_url = ? WHERE id = ?', (avatar_url, user_id))
    db.commit()
    db.close()

    # VULN: A09 — File upload not logged
    return jsonify({'success': True, 'avatar_url': avatar_url}), 200
