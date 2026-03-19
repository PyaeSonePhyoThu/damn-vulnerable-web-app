"""
Mock AWS EC2 Instance Metadata Service (IMDS)
Runs at 169.254.169.254:80 inside the Docker imds_net network.
Reachable from the backend container via SSRF on http://169.254.169.254/...
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

ROUTES = {
    '/latest/meta-data/': (
        'text/plain',
        "ami-id\n"
        "ami-launch-index\n"
        "ami-manifest-path\n"
        "hostname\n"
        "iam/\n"
        "instance-id\n"
        "instance-type\n"
        "local-hostname\n"
        "local-ipv4\n"
        "mac\n"
        "placement/\n"
        "public-hostname\n"
        "public-ipv4\n"
        "reservation-id\n"
        "security-groups\n"
    ),
    '/latest/meta-data/ami-id':              ('text/plain', 'ami-0abcdef1234567890'),
    '/latest/meta-data/ami-launch-index':    ('text/plain', '0'),
    '/latest/meta-data/ami-manifest-path':   ('text/plain', '(unknown)'),
    '/latest/meta-data/instance-id':         ('text/plain', 'i-0a1b2c3d4e5f67890'),
    '/latest/meta-data/instance-type':       ('text/plain', 't3.medium'),
    '/latest/meta-data/hostname':            ('text/plain', 'ip-10-0-1-42.us-east-1.compute.internal'),
    '/latest/meta-data/local-hostname':      ('text/plain', 'ip-10-0-1-42.us-east-1.compute.internal'),
    '/latest/meta-data/local-ipv4':          ('text/plain', '10.0.1.42'),
    '/latest/meta-data/public-hostname':     ('text/plain', 'ec2-54-210-100-42.compute-1.amazonaws.com'),
    '/latest/meta-data/public-ipv4':         ('text/plain', '54.210.100.42'),
    '/latest/meta-data/mac':                 ('text/plain', '0e:1a:2b:3c:4d:5e'),
    '/latest/meta-data/security-groups':     ('text/plain', 'vulnbank-prod-sg'),
    '/latest/meta-data/reservation-id':      ('text/plain', 'r-0a1b2c3d4e5f67890'),
    '/latest/meta-data/placement/': (
        'text/plain',
        'availability-zone\nregion\n'
    ),
    '/latest/meta-data/placement/availability-zone': ('text/plain', 'us-east-1a'),
    '/latest/meta-data/placement/region':            ('text/plain', 'us-east-1'),
    '/latest/meta-data/iam/': (
        'text/plain',
        'security-credentials/\n'
    ),
    '/latest/meta-data/iam/security-credentials/': (
        'text/plain',
        'vulnbank-prod-role\n'
    ),
    '/latest/meta-data/iam/security-credentials/vulnbank-prod-role': (
        'application/json',
        json.dumps({
            "Code":            "Success",
            "LastUpdated":     "2025-03-01T10:00:00Z",
            "Type":            "AWS-HMAC",
            "AccessKeyId":     "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token":           "AQoDYXdzEJr//////////wEaoAK1wvxJY12r2IIXllo"
                               "CDe8RCbza/MkIiSP+NzBmRevV/MTpbzpwWbxnN9Gvs"
                               "aNmYNEXAMPLETOKEN==",
            "Expiration":      "2099-12-31T23:59:59Z",
        }, indent=2)
    ),
    '/latest/user-data': (
        'text/plain',
        "#!/bin/bash\n"
        "# VulnBank production bootstrap\n"
        "export DB_HOST=rds-vulnbank-prod.c1xyz.us-east-1.rds.amazonaws.com\n"
        "export DB_USER=vulnbank_app\n"
        "export DB_PASS=Pr0d_S3cr3t_2025!\n"
        "export JWT_SECRET=secret123\n"
        "export MONGO_URI=mongodb://admin:mongoP@ss99@mongo-prod.internal:27017/\n"
        "export S3_BUCKET=vulnbank-prod-statements\n"
        "aws s3 sync s3://vulnbank-prod-statements/config /app/config\n"
    ),
    '/latest/dynamic/instance-identity/document': (
        'application/json',
        json.dumps({
            "accountId":        "123456789012",
            "architecture":     "x86_64",
            "availabilityZone": "us-east-1a",
            "imageId":          "ami-0abcdef1234567890",
            "instanceId":       "i-0a1b2c3d4e5f67890",
            "instanceType":     "t3.medium",
            "privateIp":        "10.0.1.42",
            "region":           "us-east-1",
        }, indent=2)
    ),
}


class IMDSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        entry = ROUTES.get(self.path)
        if entry:
            content_type, body = entry
            body = body.encode()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')

    def log_message(self, fmt, *args):
        # Log every request so students can see SSRF hits in docker-compose logs
        print(f'[IMDS] {self.address_string()} {fmt % args}', flush=True)


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 80), IMDSHandler)
    print('[IMDS] Mock AWS metadata service running on 0.0.0.0:80', flush=True)
    server.serve_forever()
