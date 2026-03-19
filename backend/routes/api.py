import os
import time
from urllib.parse import urlparse
import requests as http_requests
from flask import Blueprint, request, jsonify, send_file
from database import get_db
from routes.auth import jwt_required

# VULN: A10 — Denylist instead of allowlist — bypassable with alternate IP representations
# Blocks only the string literals "localhost" and "127.0.0.1".
# Does NOT block:
#   http://2130706433:9000/   — decimal encoding of 127.0.0.1
#   http://0x7f000001:9000/   — hex encoding
#   http://0177.0.0.1:9000/   — octal first octet
#   http://127.0.0.1.nip.io/  — DNS rebinding style
BLOCKED_HOSTS = {'localhost', '127.0.0.1'}

api_bp = Blueprint('api', __name__)

DB_PATH = os.environ.get('DB_PATH', '/app/backend/data/vulnbank.db')


@api_bp.route('/api/fetch-statement', methods=['GET'])
@jwt_required
def fetch_statement():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'error': 'url parameter required'}), 400

    # VULN: A10 — Denylist check (string match only — bypassable)
    try:
        parsed_host = urlparse(url).hostname or ''
    except Exception:
        parsed_host = ''

    if parsed_host.lower() in BLOCKED_HOSTS:
        # VULN: A10 — Denylist does NOT cover decimal/hex/octal IP representations
        # http://2130706433:9000/ bypasses because "2130706433" not in BLOCKED_HOSTS
        return jsonify({
            'error':   'blocked',
            'message': 'Requests to localhost and 127.0.0.1 are not permitted.',
            'hint':    'Only http://localhost and http://127.0.0.1 are blocked.',
        }), 403

    # VULN: A10 — No URL validation, no allowlist, no scheme restriction — SSRF
    # Reachable targets from inside the backend container:
    #   http://internal-admin:9000/  — hidden admin service (not in nginx)
    #   http://mongo:27017/          — MongoDB (speaks its own protocol, not HTTP)
    #   http://169.254.169.254/      — mock AWS IMDS (imds_net)
    #   file:///etc/passwd           — local file read
    t0 = time.time()
    try:
        resp = http_requests.get(url, timeout=5, allow_redirects=True)
        elapsed_ms = int((time.time() - t0) * 1000)
        # VULN: A09 — SSRF request not logged
        return jsonify({
            'status':       resp.status_code,
            'elapsed_ms':   elapsed_ms,
            'content_type': resp.headers.get('Content-Type', ''),
            'headers':      dict(resp.headers),
            'content':      resp.text[:4000],
        }), 200
    except http_requests.exceptions.ConnectionError as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        # VULN: A05 — error class + detail exposed (useful for port scanning)
        return jsonify({'error': 'connection_error', 'elapsed_ms': elapsed_ms, 'detail': str(e)}), 200
    except http_requests.exceptions.Timeout as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        return jsonify({'error': 'timeout', 'elapsed_ms': elapsed_ms, 'detail': str(e)}), 200
    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        return jsonify({'error': 'request_error', 'elapsed_ms': elapsed_ms, 'detail': str(e)}), 200


@api_bp.route('/api/backup', methods=['GET'])
@jwt_required
def backup_db():
    # VULN: A05 — Any authenticated user can download full SQLite DB
    # No privilege check, no admin role required
    if not os.path.exists(DB_PATH):
        return jsonify({'error': 'Database not found'}), 404

    # VULN: A09 — DB backup download not logged or alerted
    return send_file(
        DB_PATH,
        as_attachment=True,
        attachment_filename='vulnbank_backup.db',
        mimetype='application/octet-stream',
    )


@api_bp.route('/api/cards', methods=['GET'])
@jwt_required
def get_cards():
    user_id = request.current_user['user_id']
    db = get_db()
    # VULN: A02 — Full card numbers and CVVs returned in plaintext
    rows = db.execute('SELECT * FROM cards WHERE user_id = ?', (user_id,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows]), 200


@api_bp.route('/api/user/info', methods=['GET'])
@jwt_required
def user_info():
    """Returns current user info from JWT — useful for frontend, also leaks subscription_type"""
    # VULN: MA-1 — subscription_type visible in JWT and here
    return jsonify({
        'user_id':           request.current_user.get('user_id'),
        'username':          request.current_user.get('username'),
        'email':             request.current_user.get('email'),
        'subscription_type': request.current_user.get('subscription_type'),
    }), 200
