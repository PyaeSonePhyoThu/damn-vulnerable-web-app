"""
VulnBank Internal Admin Service
Runs on internal-admin:9000 — only reachable from the Docker default network.
NOT proxied by nginx. Students must discover and access it via SSRF.

Endpoints:
  GET /               list of available endpoints
  GET /health         service health status
  GET /config         app configuration including credentials  ← high value
  GET /users          all registered users with password hashes ← high value
  GET /logs           recent application log entries
  GET /env            raw environment variables
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta
import random

# Simulated data
USERS = [
    {"id": "00000000-0000-0000-0000-000000000001", "username": "alice",        "email": "alice@vulnbank.local",        "password_hash": "482c811da5d5b4bc6d497ffa98491e38", "subscription": "gold",   "ssn": "123-45-6789"},
    {"id": "00000000-0000-0000-0000-000000000002", "username": "bob",          "email": "bob@vulnbank.local",          "password_hash": "0d107d09f5bbe40cade3de5c71e9e9b7", "subscription": "silver", "ssn": "987-65-4321"},
    {"id": "00000000-0000-0000-0000-000000000005", "username": "aungkyawsein", "email": "aungkyawsein@vulnbank.local", "password_hash": "2aca2933013a12a700606999805f6e26", "subscription": "bronze", "ssn": "654-32-1098"},
]

CONFIG = {
    "service":        "vulnbank-internal-admin",
    "version":        "1.4.2",
    "environment":    "production",
    "database": {
        "host":     "rds-vulnbank-prod.c1xyz.us-east-1.rds.amazonaws.com",
        "port":     5432,
        "name":     "vulnbank_prod",
        "user":     "vulnbank_app",
        "password": "Pr0d_S3cr3t_2025!",
    },
    "mongodb": {
        "uri":      "mongodb://admin:mongoP@ss99@mongo:27017/",
        "database": "vulnbank_auth",
    },
    "jwt": {
        "secret":    "secret123",
        "algorithm": "HS256",
        "expires_in": "24h",
    },
    "aws": {
        "region":     "us-east-1",
        "s3_bucket":  "vulnbank-prod-statements",
        "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123",
    },
    "smtp": {
        "host":     "email-smtp.us-east-1.amazonaws.com",
        "port":     587,
        "user":     "AKIAIOSFODNN7SMTP001",
        "password": "BEXampleSMTPpassword1",
    },
    "flags": {
        "debug_mode":      True,
        "log_passwords":   True,
        "allow_file_read": True,
    },
}

LOGS = [
    {"ts": "2025-03-18T09:01:11Z", "level": "INFO",  "msg": "User alice logged in",             "ip": "203.0.113.45"},
    {"ts": "2025-03-18T09:02:44Z", "level": "WARN",  "msg": "Failed login attempt for admin",   "ip": "198.51.100.12"},
    {"ts": "2025-03-18T09:05:02Z", "level": "INFO",  "msg": "Transfer $49000 alice → bob",      "ip": "203.0.113.45"},
    {"ts": "2025-03-18T09:07:30Z", "level": "ERROR", "msg": "SSTI detected in full_name field",  "ip": "192.0.2.99"},
    {"ts": "2025-03-18T09:09:15Z", "level": "WARN",  "msg": "500 error — stack trace exposed",  "ip": "192.0.2.99"},
    {"ts": "2025-03-18T09:11:00Z", "level": "INFO",  "msg": "PDF statement generated for alice","ip": "203.0.113.45"},
    {"ts": "2025-03-18T09:13:22Z", "level": "WARN",  "msg": "OTP null bypass attempt detected", "ip": "198.51.100.77"},
    {"ts": "2025-03-18T09:14:05Z", "level": "INFO",  "msg": "Password reset token issued for bob","ip": "198.51.100.77"},
    {"ts": "2025-03-18T09:15:50Z", "level": "INFO",  "msg": "User aungkyawsein subscription → gold via mass assignment","ip": "192.0.2.99"},
]

ROUTES = {
    '/': {
        "service":   "VulnBank Internal Admin",
        "note":      "This service is internal-only. If you can read this via SSRF you have achieved internal network access.",
        "endpoints": [
            "GET /health  — service health and uptime",
            "GET /config  — application configuration (includes credentials)",
            "GET /users   — registered users with password hashes and SSNs",
            "GET /logs    — recent application log entries",
            "GET /env     — raw environment variables",
        ],
    },
    '/health': {
        "status":   "ok",
        "service":  "vulnbank-internal-admin",
        "uptime":   "14d 06h 22m",
        "version":  "1.4.2",
        "checks": {
            "database": "ok",
            "mongodb":  "ok",
            "cache":    "ok",
        },
    },
    '/config': CONFIG,
    '/users':  USERS,
    '/logs':   LOGS,
}


class AdminHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Strip query string
        path = self.path.split('?')[0]

        if path == '/env':
            body = json.dumps(dict(os.environ), indent=2).encode()
            self._respond(200, 'application/json', body)
            return

        entry = ROUTES.get(path)
        if entry is not None:
            body = json.dumps(entry, indent=2).encode()
            self._respond(200, 'application/json', body)
        else:
            body = json.dumps({"error": "Not found", "available": list(ROUTES.keys()) + ["/env"]}).encode()
            self._respond(404, 'application/json', body)

    def _respond(self, code, content_type, body):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(body))
        self.send_header('X-Internal-Service', 'vulnbank-admin-v1')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f'[INTERNAL-ADMIN] {self.address_string()} — {fmt % args}', flush=True)


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 9000), AdminHandler)
    print('[INTERNAL-ADMIN] Running on 0.0.0.0:9000 (internal only)', flush=True)
    server.serve_forever()
