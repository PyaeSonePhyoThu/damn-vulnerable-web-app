from flask import Blueprint, Response

# VULN: A10 — Mock AWS Instance Metadata Service (IMDS)
# Reachable via SSRF: GET /api/fetch-statement?url=http://backend:8000/latest/meta-data/
# In a real cloud deployment this would be at http://169.254.169.254/latest/meta-data/
# No authentication required — by design (mimics real IMDS behaviour)

imds_bp = Blueprint('imds', __name__)


def text(body):
    return Response(body, mimetype='text/plain')


# ── Root ──────────────────────────────────────────────────────────────────────

@imds_bp.route('/latest/meta-data/', methods=['GET'])
def imds_root():
    return text(
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
    )


# ── Basic instance attributes ─────────────────────────────────────────────────

@imds_bp.route('/latest/meta-data/ami-id', methods=['GET'])
def imds_ami_id():
    return text('ami-0abcdef1234567890')


@imds_bp.route('/latest/meta-data/instance-id', methods=['GET'])
def imds_instance_id():
    return text('i-0a1b2c3d4e5f67890')


@imds_bp.route('/latest/meta-data/instance-type', methods=['GET'])
def imds_instance_type():
    return text('t3.medium')


@imds_bp.route('/latest/meta-data/hostname', methods=['GET'])
def imds_hostname():
    return text('ip-10-0-1-42.us-east-1.compute.internal')


@imds_bp.route('/latest/meta-data/local-hostname', methods=['GET'])
def imds_local_hostname():
    return text('ip-10-0-1-42.us-east-1.compute.internal')


@imds_bp.route('/latest/meta-data/local-ipv4', methods=['GET'])
def imds_local_ipv4():
    return text('10.0.1.42')


@imds_bp.route('/latest/meta-data/public-hostname', methods=['GET'])
def imds_public_hostname():
    return text('ec2-54-210-100-42.compute-1.amazonaws.com')


@imds_bp.route('/latest/meta-data/public-ipv4', methods=['GET'])
def imds_public_ipv4():
    return text('54.210.100.42')


@imds_bp.route('/latest/meta-data/mac', methods=['GET'])
def imds_mac():
    return text('0e:1a:2b:3c:4d:5e')


@imds_bp.route('/latest/meta-data/security-groups', methods=['GET'])
def imds_security_groups():
    return text('vulnbank-prod-sg')


@imds_bp.route('/latest/meta-data/reservation-id', methods=['GET'])
def imds_reservation_id():
    return text('r-0a1b2c3d4e5f67890')


@imds_bp.route('/latest/meta-data/ami-launch-index', methods=['GET'])
def imds_ami_launch_index():
    return text('0')


@imds_bp.route('/latest/meta-data/ami-manifest-path', methods=['GET'])
def imds_ami_manifest():
    return text('(unknown)')


# ── Placement ─────────────────────────────────────────────────────────────────

@imds_bp.route('/latest/meta-data/placement/', methods=['GET'])
def imds_placement_root():
    return text('availability-zone\nregion\n')


@imds_bp.route('/latest/meta-data/placement/availability-zone', methods=['GET'])
def imds_az():
    return text('us-east-1a')


@imds_bp.route('/latest/meta-data/placement/region', methods=['GET'])
def imds_region():
    return text('us-east-1')


# ── IAM credentials — the high-value target ──────────────────────────────────

@imds_bp.route('/latest/meta-data/iam/', methods=['GET'])
def imds_iam_root():
    return text('security-credentials/\n')


@imds_bp.route('/latest/meta-data/iam/security-credentials/', methods=['GET'])
def imds_iam_roles():
    # VULN: A10 — role name leaked, leads directly to credential exfil
    return text('vulnbank-prod-role\n')


@imds_bp.route('/latest/meta-data/iam/security-credentials/vulnbank-prod-role', methods=['GET'])
def imds_iam_credentials():
    # VULN: A10 — Fake AWS credentials returned — in a real cloud environment
    # these would be valid short-lived STS credentials usable to access S3, RDS, etc.
    import json
    creds = {
        "Code":             "Success",
        "LastUpdated":      "2025-03-01T10:00:00Z",
        "Type":             "AWS-HMAC",
        "AccessKeyId":      "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey":  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token":            "AQoDYXdzEJr//////////wEaoAK1wvxJY12r2IIXllo"
                            "CDe8RCbza/MkIiSP+NzBmRevV/MTpbzpwWbxnN9Gvs"
                            "aNmYNEXAMPLETOKEN==",
        "Expiration":       "2099-12-31T23:59:59Z",
    }
    return Response(json.dumps(creds, indent=2), mimetype='application/json')


# ── User data (often contains init scripts with secrets) ─────────────────────

@imds_bp.route('/latest/user-data', methods=['GET'])
def imds_user_data():
    # VULN: A10 — User-data script leaks DB credentials and internal config
    return text(
        "#!/bin/bash\n"
        "# VulnBank production bootstrap\n"
        "export DB_HOST=rds-vulnbank-prod.c1xyz.us-east-1.rds.amazonaws.com\n"
        "export DB_USER=vulnbank_app\n"
        "export DB_PASS=Pr0d_S3cr3t_2025!\n"
        "export JWT_SECRET=secret123\n"
        "export MONGO_URI=mongodb://admin:mongoP@ss99@mongo-prod.internal:27017/\n"
        "export S3_BUCKET=vulnbank-prod-statements\n"
        "aws s3 sync s3://vulnbank-prod-statements/config /app/config\n"
    )


# ── Dynamic instance identity document ───────────────────────────────────────

@imds_bp.route('/latest/dynamic/instance-identity/document', methods=['GET'])
def imds_identity():
    import json
    doc = {
        "accountId":        "123456789012",
        "architecture":     "x86_64",
        "availabilityZone": "us-east-1a",
        "imageId":          "ami-0abcdef1234567890",
        "instanceId":       "i-0a1b2c3d4e5f67890",
        "instanceType":     "t3.medium",
        "privateIp":        "10.0.1.42",
        "region":           "us-east-1",
    }
    return Response(json.dumps(doc, indent=2), mimetype='application/json')
