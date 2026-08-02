import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.config import Settings
from lsa.dependencies import IngestionPrincipal
from lsa.models import IngestionToken, Report, Tenant, User
from lsa.schemas import ReportInput
from lsa.security import hash_ingestion_token, hash_password
from lsa.services.ingestion import ingest_report


DEMO_TOKEN = "lsa_ingest_demo_secret"


def bootstrap(db: Session, settings: Settings) -> None:
    tenant = db.scalar(select(Tenant).where(Tenant.slug == "default"))
    if tenant is None:
        tenant = Tenant(name="Paragon Infrastructure", slug="default")
        db.add(tenant)
        db.flush()
    user = db.scalar(select(User).where(User.email == settings.bootstrap_email))
    if user is None:
        db.add(
            User(
                tenant_id=tenant.id,
                email=settings.bootstrap_email,
                display_name="Security Administrator",
                password_hash=hash_password(settings.bootstrap_password),
                role="admin",
            )
        )
    token = None
    if settings.environment != "production":
        token_hash = hash_ingestion_token(DEMO_TOKEN)
        token = db.scalar(select(IngestionToken).where(IngestionToken.token_hash == token_hash))
        if token is None:
            token = IngestionToken(
                tenant_id=tenant.id,
                name="Development controller",
                token_prefix=DEMO_TOKEN[:12],
                token_hash=token_hash,
            )
            db.add(token)
    db.commit()
    if settings.seed_demo and token is not None:
        seed_demo_reports(db, tenant.id, token.id)


def seed_demo_reports(db: Session, tenant_id: str, token_id: str) -> None:
    if db.scalar(select(Tenant).where(Tenant.id == tenant_id)) is None:
        return
    hosts = [
        ("web-prod-01", "Debian GNU/Linux", "debian", "13", "production", "payments", 86.4),
        ("ledger-db-02", "Ubuntu", "ubuntu", "24.04", "production", "ledger", 73.8),
        ("edge-proxy-03", "Red Hat Enterprise Linux", "rhel", "9.5", "dmz", "edge", 91.7),
        ("build-runner-07", "Debian GNU/Linux", "debian", "12", "engineering", "build", 82.1),
        ("archive-node-04", "Ubuntu", "ubuntu", "22.04", "production", "archive", 67.9),
    ]
    severities = ["medium", "critical", "low", "high", "high"]
    for index, (hostname, os_name, family, version, environment, application, score) in enumerate(hosts):
        host_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"lsa-demo-{hostname}"))
        report_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"lsa-demo-report-{hostname}"))
        if db.get(Report, report_id):
            continue
        digest = hashlib.sha256(hostname.encode()).hexdigest()
        payload = ReportInput.model_validate(
            {
                "schema_version": "1.0",
                "report_id": report_id,
                "generated_at": (datetime.now(UTC) - timedelta(hours=index * 3 + 1)).isoformat(),
                "scanner": {"name": "Linux Security Auditor", "version": "0.1.0"},
                "host": {
                    "host_id": host_id,
                    "hostname": hostname,
                    "fqdn": f"{hostname}.infra.example",
                    "machine_id_hash": f"sha256:{digest}",
                    "operating_system": os_name,
                    "os_family": family,
                    "os_version": version,
                    "kernel": "6.12.0-x86_64",
                    "architecture": "x86_64",
                    "ip_addresses": [f"10.24.{index + 8}.{20 + index}"],
                    "tags": {
                        "environment": environment,
                        "application": application,
                        "owner": "platform" if index != 1 else "database",
                        "criticality": "critical" if index in {0, 1} else "high",
                    },
                },
                "scan": {"profile": "cis_level2_server", "modules": ["cis", "security_health"]},
                "summary": {
                    "pass": 180 + index * 9,
                    "fail": 7 + index * 3,
                    "manual": 4,
                    "not_applicable": 21,
                    "error": 0,
                    "compliance_score": round(score + 3.2, 1),
                    "security_score": score,
                },
                "findings": [
                    {
                        "control_id": f"CIS-{family.upper()}-{index + 1}.4.2",
                        "module": "cis",
                        "category": "access-control",
                        "title": "Restrict permissions on sensitive authentication configuration",
                        "severity": severities[index],
                        "status": "fail",
                        "expected": "Mode 0600 or stricter",
                        "actual": "Mode 0644",
                        "evidence": ["/etc/security/access.conf: 0644 root:root"],
                        "remediation_summary": "Restrict the file to the owning administrative account.",
                        "remediation_commands": ["chmod 600 /etc/security/access.conf"],
                        "verification_commands": ["stat -c '%a %U:%G' /etc/security/access.conf"],
                    },
                    {
                        "control_id": f"LSA-SSH-{index + 1:03}",
                        "module": "security_health",
                        "category": "ssh",
                        "title": "Disable direct root authentication over SSH",
                        "severity": "high",
                        "status": "fail" if index in {1, 4} else "pass",
                        "expected": "PermitRootLogin no",
                        "actual": "PermitRootLogin yes" if index in {1, 4} else "PermitRootLogin no",
                        "remediation_summary": "Disable direct root SSH login after validating sudo access.",
                        "remediation_commands": ["sshd -T | grep permitrootlogin"],
                    },
                ],
            }
        )
        ingest_report(db, payload, IngestionPrincipal(token_id, tenant_id, None))
