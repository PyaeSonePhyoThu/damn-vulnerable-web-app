import os
import traceback
from flask import Flask, jsonify
from database import init_db, init_mongo
from routes.auth import auth_bp
from routes.accounts import accounts_bp
from routes.transactions import transactions_bp
from routes.profile import profile_bp
from routes.pdf import pdf_bp
from routes.api import api_bp
from internal_docs import launch as launch_internal_docs

app = Flask(__name__)

# VULN: A02 — Hardcoded session secret
app.secret_key = 'vulnbank-secret-2024'

# VULN: A05 — DEBUG=True exposes stack traces on errors
app.config['DEBUG'] = True

# 16MB — allows large SVG uploads
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Register all blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(accounts_bp)
app.register_blueprint(transactions_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(pdf_bp)
app.register_blueprint(api_bp)


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    # VULN: A05 — Full traceback returned in 500 response
    return jsonify({
        'error':     str(e),
        'traceback': traceback.format_exc(),
    }), 500


@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large (max 16MB)'}), 413


if __name__ == '__main__':
    # Initialise databases
    init_db()
    init_mongo()

    # Start internal docs server on 127.0.0.1:9000 (loopback only — SSRF target)
    launch_internal_docs()

    port = int(os.environ.get('PORT', 8000))
    # VULN: A05 — DEBUG=True, host 0.0.0.0 (accessible from all interfaces inside container)
    app.run(host='0.0.0.0', port=port, debug=True)
