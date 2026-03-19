"""
Exploitable Bank — Internal API Documentation Server

Binds to 127.0.0.1:9000 (loopback only).
This service is NOT accessible from outside the backend container:
  - Nginx does not proxy port 9000
  - The loopback interface is local to the container

To reach it an attacker must exploit SSRF AND bypass the localhost denylist.

Denylist in /api/fetch-statement blocks:
  http://localhost:9000/       ← blocked ("localhost" in BLOCKED_HOSTS)
  http://127.0.0.1:9000/      ← blocked ("127.0.0.1" in BLOCKED_HOSTS)

Bypass using alternate IP representations that resolve to 127.0.0.1:
  http://2130706433:9000/     ← decimal  (127*16777216 + 0 + 0 + 1 = 2130706433)
  http://0x7f000001:9000/     ← hex
  http://0177.0.0.1:9000/     ← octal first octet

Python requests + OS resolver accepts all of these as valid 127.0.0.1.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Exposed in /docs — reveals internal service topology
API_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title":       "Exploitable Bank Internal API",
        "version":     "2.1.0",
        "description": "INTERNAL USE ONLY — Not exposed via public gateway",
        "contact": {
            "team":  "Exploitable Bank Platform Engineering",
            "slack": "#platform-internal",
            "note":  "Do not share outside the engineering org",
        },
    },
    "servers": [
        {"url": "http://backend:8000",        "description": "Public backend (via nginx)"},
        {"url": "http://internal-admin:9000", "description": "Internal admin service (NOT in nginx)"},
        {"url": "http://127.0.0.1:9000",      "description": "This docs server (loopback only)"},
    ],
    "internal_services": {
        "note": "The following services are on the internal Docker network only.",
        "services": [
            {
                "name":    "internal-admin",
                "address": "http://internal-admin:9000",
                "purpose": "Admin operations, configuration management, user management",
                "auth":    "None — internal network trust",
                "endpoints": [
                    "GET /          list endpoints",
                    "GET /health    service health",
                    "GET /config    application config (DB, JWT, SMTP, AWS)",
                    "GET /users     all users with password_hash and SSN",
                    "GET /logs      recent security-relevant log entries",
                    "GET /env       raw environment variables",
                ],
            },
            {
                "name":    "mongo",
                "address": "mongodb://mongo:27017",
                "purpose": "Authentication microservice — stores plaintext passwords",
                "auth":    "None in dev; admin:mongoP@ss99 in prod",
                "note":    "NoSQL injection possible via /login (see A07 lab)",
            },
        ],
    },
    "paths": {
        "/login": {
            "post": {
                "summary": "Authenticate user",
                "note":    "Auth is checked against MongoDB — password field not sanitised (NoSQL injection)",
                "requestBody": {"username": "string", "password": "string | object"},
            }
        },
        "/register/init": {
            "post": {"summary": "Step 1 of registration — email + password stored in session"}
        },
        "/register/complete": {
            "post": {
                "summary": "Step 2 — choose username",
                "vuln":    "A07-ENUM: returns 409 if username exists",
            }
        },
        "/api/account/{uuid}": {
            "get": {
                "summary": "Get account by UUID",
                "vuln":    "A03-SQLi: uuid path param interpolated raw into SQL query",
                "example": "GET /api/account/x' OR '1'='1",
            }
        },
        "/api/fetch-statement": {
            "get": {
                "summary": "Fetch external statement URL",
                "vuln":    "A10-SSRF: url param passed directly to requests.get()",
                "denylist": ["localhost", "127.0.0.1"],
                "bypass":  "Use decimal/hex/octal IP representation to reach loopback",
            }
        },
        "/api/profile/update": {
            "post": {
                "summary": "Update profile",
                "vuln":    "MA-1: subscription_type in ALLOWED_FIELDS — mass assignment",
            }
        },
        "/api/pdf/statement": {
            "get": {
                "summary": "Generate PDF statement",
                "vuln":    "SSTI-1: full_name embedded into Jinja2 template string before render",
            }
        },
        "/api/backup": {
            "get": {
                "summary": "Download SQLite DB",
                "vuln":    "A05: any authenticated user, no privilege check",
            }
        },
        "/forgot-password": {
            "post": {
                "summary": "Request password reset",
                "vuln":    "ATO-1: reset token = MD5(username) — predictable, returned in response",
            }
        },
        "/reset/verify-otp": {
            "post": {
                "summary": "Verify OTP",
                "vuln":    "VD-4b: submitted_otp == stored_otp — None==None bypass for fresh accounts",
            }
        },
        "/api/profile/avatar": {
            "post": {
                "summary": "Upload avatar",
                "vuln":    "A08/A03-XSS: no MIME validation — SVG with <script> accepted and served",
            }
        },
    },
    "credentials_hint": {
        "note":       "See http://internal-admin:9000/config for live credentials",
        "jwt_secret": "secret123",
        "algorithm":  "HS256 (also accepts 'none' — PyJWT 1.7.1)",
    },
}


ROUTES = {
    '/':     API_SPEC,
    '/docs': API_SPEC,
    '/health': {"status": "ok", "service": "vulnbank-internal-docs", "port": 9000},
}


class DocsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path  = self.path.split('?')[0]
        entry = ROUTES.get(path)
        if entry is not None:
            body = json.dumps(entry, indent=2).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(body))
            self.send_header('X-Internal-Docs', 'vulnbank-v2')
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b'{"error": "not found", "available": ["/", "/docs", "/health"]}'
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f'[INTERNAL-DOCS] {self.address_string()} — {fmt % args}', flush=True)


def start_internal_docs():
    """Start the loopback docs server in a daemon thread."""
    server = HTTPServer(('127.0.0.1', 9000), DocsHandler)
    print('[INTERNAL-DOCS] Listening on 127.0.0.1:9000 (loopback only)', flush=True)
    server.serve_forever()


def launch():
    t = threading.Thread(target=start_internal_docs, daemon=True)
    t.start()
