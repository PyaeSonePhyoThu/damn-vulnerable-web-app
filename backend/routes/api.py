import os
import time
import warnings
from urllib.parse import urlparse
import requests as http_requests
import urllib3
from flask import Blueprint, request, jsonify, send_file
from database import get_db
from routes.auth import jwt_required

# Suppress InsecureRequestWarning from verify=False — intentional for SSRF lab
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

api_bp = Blueprint('api', __name__)

DB_PATH = os.environ.get('DB_PATH', '/app/backend/data/vulnbank.db')


@api_bp.route('/api/fetch-statement', methods=['GET'])
@jwt_required
def fetch_statement():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'error': 'url parameter required'}), 400

    # VULN: A10 — No URL validation, no allowlist, no scheme restriction — SSRF
    # No denylist — all hosts and schemes are reachable from inside the container:
    #   http://127.0.0.1:9000/       — internal docs server (loopback)
    #   http://internal-admin:9000/  — hidden admin service (Docker DNS)
    #   http://169.254.169.254/      — mock AWS IMDS (imds_net)
    #   file:///etc/passwd           — local file read via file:// scheme
    t0 = time.time()

    try:
        parsed = urlparse(url)
    except Exception:
        return jsonify({'error': 'Could not fetch the requested URL'}), 200

    # VULN: A10 — file:// scheme accepted — local file disclosure
    if parsed.scheme == 'file':
        try:
            filepath = parsed.path
            with open(filepath, 'r', errors='replace') as f:
                content = f.read(4000)
            elapsed_ms = int((time.time() - t0) * 1000)
            return jsonify({
                'status':     200,
                'elapsed_ms': elapsed_ms,
                'content':    content,
            }), 200
        except FileNotFoundError:
            return jsonify({'error': 'Could not fetch the requested URL', 'detail': 'No such file or directory'}), 200
        except PermissionError:
            return jsonify({'error': 'Could not fetch the requested URL', 'detail': 'Permission denied'}), 200
        except Exception as e:
            return jsonify({'error': 'Could not fetch the requested URL', 'detail': str(e)}), 200

    try:
        session = http_requests.Session()
        # VULN: A10 — SSL verification disabled, redirects followed, no timeout restriction
        resp = session.get(url, timeout=8, allow_redirects=True, verify=False)
        elapsed_ms = int((time.time() - t0) * 1000)
        # VULN: A09 — SSRF request not logged
        return jsonify({
            'status':       resp.status_code,
            'elapsed_ms':   elapsed_ms,
            'content_type': resp.headers.get('Content-Type', ''),
            'headers':      dict(resp.headers),
            'content':      resp.text[:4000],
        }), 200
    except http_requests.exceptions.ConnectionError:
        elapsed_ms = int((time.time() - t0) * 1000)
        # VULN: A05 — timing difference still useful for port scanning
        return jsonify({'error': 'Could not fetch the requested URL', 'elapsed_ms': elapsed_ms}), 200
    except http_requests.exceptions.Timeout:
        elapsed_ms = int((time.time() - t0) * 1000)
        return jsonify({'error': 'Could not fetch the requested URL', 'elapsed_ms': elapsed_ms}), 200
    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        return jsonify({'error': 'Could not fetch the requested URL', 'elapsed_ms': elapsed_ms, 'detail': str(e)}), 200


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
    user_id = request.current_user.get('user_id')
    db = get_db()
    user = db.execute('SELECT cif FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()
    return jsonify({
        'user_id':           user_id,
        'username':          request.current_user.get('username'),
        'email':             request.current_user.get('email'),
        'subscription_type': request.current_user.get('subscription_type'),
        'cif':               user['cif'] if user else None,
    }), 200
