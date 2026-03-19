import os
import uuid
import hashlib
import random
import string
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import Blueprint, request, jsonify, session

from database import get_db

auth_bp = Blueprint('auth', __name__)

JWT_SECRET = os.environ.get('JWT_SECRET', 'secret123')  # VULN: JWT-1 — hardcoded weak secret


def md5(p):
    # VULN: A02 — MD5, no salt
    return hashlib.md5(p.encode()).hexdigest()


def generate_jwt(user: dict) -> str:
    payload = {
        'user_id':           user['id'],
        'username':          user['username'],
        'email':             user['email'],
        'subscription_type': user['subscription_type'],  # VULN: MA-1 — in token, writable
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=24),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    # VULN: JWT-1 — PyJWT 1.7.1 returns bytes; decode to str
    return token.decode('utf-8') if isinstance(token, bytes) else token


def decode_jwt(token: str):
    # VULN: JWT-2 — 'none' algorithm accepted by PyJWT 1.7.1
    return jwt.decode(token, JWT_SECRET, algorithms=['HS256', 'none'])


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
        if not token:
            token = request.cookies.get('jwt_token')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        try:
            payload = decode_jwt(token)
            request.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


@auth_bp.route('/register/init', methods=['POST'])
def register_init():
    """Step 1 — collect email + password. No username enumeration here."""
    data      = request.get_json() or {}
    email     = data.get('email', '').strip()
    password  = data.get('password', '')
    full_name = data.get('full_name', '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    db = get_db()
    existing_email = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    db.close()
    if existing_email:
        # Generic error — does NOT reveal email existence (contrast with step 2)
        return jsonify({'error': 'Registration could not be completed. Please try again.'}), 400

    # VULN: A02 — raw password stored in server-side session (no encryption)
    session['reg_email']     = email
    session['reg_password']  = password
    session['reg_full_name'] = full_name

    return jsonify({'message': 'Step 1 complete. Please choose your username.'}), 200


@auth_bp.route('/register/complete', methods=['POST'])
def register_complete():
    """Step 2 — choose username.
    VULN: A07-ENUM — returns 409 distinctly if username already exists → enumeration.
    Attacker can probe any username without creating an account.
    """
    data     = request.get_json() or {}
    username = data.get('username', '').strip()

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    email     = session.get('reg_email')
    password  = session.get('reg_password')
    full_name = session.get('reg_full_name', '')

    if not email or not password:
        return jsonify({'error': 'Session expired. Please start registration again.'}), 400

    db = get_db()
    # VULN: A07-ENUM — 409 reveals that the username is taken → username enumeration
    existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        db.close()
        return jsonify({'error': 'Username already taken'}), 409

    user_id = str(uuid.uuid4())
    # VULN: A02 — MD5, no salt
    password_hash = md5(password)

    # Assign sequential CIF — predictable, brute-forceable (VULN: CIF-1)
    max_cif_row = db.execute('SELECT MAX(CAST(cif AS INTEGER)) FROM users').fetchone()
    next_cif = str((max_cif_row[0] or 100000) + 1)

    # VULN: A02 — plaintext password stored in MongoDB
    try:
        from pymongo import MongoClient
        mongo_uri = os.environ.get('MONGO_URI', 'mongodb://mongo:27017/')
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
        auth_db = client['vulnbank_auth']
        auth_db.users.insert_one({
            'username': username,
            'email':    email,
            'password': password,  # VULN: A02 — plaintext
            'subscription_type': 'bronze',
            'user_id':  user_id,
        })
    except Exception:
        pass

    # otp column NULL for new accounts (enables null bypass VD-4b)
    db.execute(
        '''INSERT INTO users (id, username, email, password_hash, full_name, subscription_type, otp, cif)
           VALUES (?,?,?,?,?,?,NULL,?)''',
        (user_id, username, email, password_hash, full_name, 'bronze', next_cif)
    )

    acc_id  = str(uuid.uuid4())
    acc_num = f"ACC-{hashlib.md5(f'{username}savings{user_id}'.encode()).hexdigest()[:8].upper()}"
    db.execute(
        'INSERT INTO accounts (id, user_id, account_number, account_type, balance) VALUES (?,?,?,?,?)',
        (acc_id, user_id, acc_num, 'savings', 100.00)
    )

    db.commit()
    db.close()

    session.pop('reg_email',     None)
    session.pop('reg_password',  None)
    session.pop('reg_full_name', None)

    # VULN: A09 — new registration not logged
    return jsonify({'message': 'Registration successful', 'user_id': user_id, 'cif': next_cif}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data     = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    # VULN: A07-NOSQL — raw dict passed to MongoDB find_one — operator injection
    mongo_user = None
    try:
        from pymongo import MongoClient
        mongo_uri = os.environ.get('MONGO_URI', 'mongodb://mongo:27017/')
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
        auth_db = client['vulnbank_auth']
        # VULN: VD-3 — password value not sanitised; {"$ne": ""} bypasses auth
        mongo_user = auth_db.users.find_one({
            'username': username,
            'password': password,
        })
    except Exception as e:
        print(f"[WARN] MongoDB error: {e}")

    if not mongo_user:
        # VULN: A09 — failed login not logged
        return jsonify({'error': 'Invalid credentials'}), 401

    db = get_db()
    sqlite_user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    db.close()

    if not sqlite_user:
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_jwt(dict(sqlite_user))
    # VULN: A02 — JWT stored in localStorage (set by frontend) and cookie without httponly/secure
    return jsonify({
        'token': token,
        'user': {
            'id':                sqlite_user['id'],
            'username':          sqlite_user['username'],
            'email':             sqlite_user['email'],
            'full_name':         sqlite_user['full_name'],
            'subscription_type': sqlite_user['subscription_type'],
        }
    }), 200


@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    # VULN: A09 — logout not logged
    return jsonify({'message': 'Logged out'}), 200


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data  = request.get_json() or {}
    email = data.get('email', '').strip()

    if not email:
        return jsonify({'error': 'Email required'}), 400

    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if not user:
        db.close()
        # VULN: A07-ENUM — could enumerate emails; we return 404 deliberately
        return jsonify({'error': 'No account found with that email'}), 404

    # VULN: ATO-1 — Predictable token: MD5(username) — trivially guessable
    reset_token = hashlib.md5(user['username'].encode()).hexdigest()
    expiry      = (datetime.utcnow() + timedelta(hours=1)).isoformat()

    db.execute('UPDATE users SET reset_token=?, reset_token_expiry=? WHERE email=?',
               (reset_token, expiry, email))
    db.commit()
    db.close()

    # NOTE: No Host header usage — host header injection is NOT in this build
    # Token is stored in DB; in a real app it would be emailed. Here it must be guessed.
    return jsonify({
        'message': 'If an account exists, a reset token has been sent to your email',
    }), 200


@auth_bp.route('/reset/request-otp', methods=['POST'])
def request_otp():
    data  = request.get_json() or {}
    email = data.get('email', '').strip()

    if not email:
        return jsonify({'error': 'Email required'}), 400

    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if not user:
        db.close()
        return jsonify({'error': 'No account found'}), 404

    # VULN: A04-OTP — No rate limiting on OTP generation
    # VULN: A04-OTP — 4-digit OTP, easily brute-forced (0000-9999)
    otp    = str(random.randint(0, 9999)).zfill(4)
    expiry = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

    db.execute('UPDATE users SET otp=?, otp_expiry=? WHERE email=?', (otp, expiry, email))
    db.commit()
    db.close()

    return jsonify({
        'message': 'OTP sent to your email',
    }), 200


@auth_bp.route('/reset/verify-otp', methods=['POST'])
def verify_otp():
    data          = request.get_json() or {}
    email         = data.get('email', '').strip()
    submitted_otp = data.get('otp')  # JSON null → Python None; kept raw, no coercion

    if not email:
        return jsonify({'error': 'Email required'}), 400

    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'No account found'}), 404

    stored_otp = user['otp']  # NULL in DB → None in Python for fresh/unset accounts

    # VULN: VD-4a — No rate limit, no attempt counter
    # VULN: VD-4b — None == None is True → null bypass
    #               Fresh accounts have otp=NULL; send {"otp": null} → bypass without requesting OTP
    if submitted_otp == stored_otp:
        session['otp_verified_for'] = email
        db.close()
        # VULN: A09 — OTP verification success not logged
        return jsonify({'success': 'OTP verified', 'email': email}), 200

    db.close()
    # VULN: A09 — Failed OTP attempt not logged
    return jsonify({'error': 'Invalid OTP'}), 400


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data     = request.get_json() or {}
    token    = data.get('token', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'New password required'}), 400

    db = get_db()

    # OTP-based reset (via session)
    otp_email = session.get('otp_verified_for')
    if otp_email and (not email or email == otp_email):
        user = db.execute('SELECT * FROM users WHERE email = ?', (otp_email,)).fetchone()
        if user:
            # VULN: A02 — MD5 no salt
            db.execute('UPDATE users SET password_hash=?, otp=NULL, otp_expiry=NULL WHERE email=?',
                       (md5(password), otp_email))
            # Update MongoDB too
            try:
                from pymongo import MongoClient
                mongo_uri = os.environ.get('MONGO_URI', 'mongodb://mongo:27017/')
                client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
                auth_db = client['vulnbank_auth']
                auth_db.users.update_one({'email': otp_email}, {'$set': {'password': password}})
            except Exception:
                pass
            db.commit()
            db.close()
            session.pop('otp_verified_for', None)
            return jsonify({'message': 'Password reset successful'}), 200

    # Token-based reset
    if not token or not email:
        db.close()
        return jsonify({'error': 'Token and email required'}), 400

    user = db.execute('SELECT * FROM users WHERE email = ? AND reset_token = ?', (email, token)).fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'Invalid or expired reset token'}), 400

    expiry_str = user['reset_token_expiry']
    if expiry_str:
        try:
            expiry = datetime.fromisoformat(expiry_str)
            if datetime.utcnow() > expiry:
                db.close()
                return jsonify({'error': 'Reset token expired'}), 400
        except Exception:
            pass

    # VULN: A02 — MD5 no salt
    db.execute('UPDATE users SET password_hash=?, reset_token=NULL, reset_token_expiry=NULL WHERE email=?',
               (md5(password), email))
    # Update MongoDB
    try:
        from pymongo import MongoClient
        mongo_uri = os.environ.get('MONGO_URI', 'mongodb://mongo:27017/')
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
        auth_db = client['vulnbank_auth']
        auth_db.users.update_one({'email': email}, {'$set': {'password': password}})
    except Exception:
        pass
    db.commit()
    db.close()
    return jsonify({'message': 'Password reset successful'}), 200
