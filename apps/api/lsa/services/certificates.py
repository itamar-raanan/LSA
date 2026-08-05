import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from lsa.config import Settings
from lsa.models import Tenant, TlsCertificate, now_utc
from lsa.security import decrypt_secret, encrypt_secret


def normalize_certificate_chain(certificate_data: bytes | str) -> tuple[x509.Certificate, str]:
    encoded = certificate_data.encode() if isinstance(certificate_data, str) else certificate_data
    try:
        certificates = x509.load_pem_x509_certificates(encoded)
    except ValueError:
        try:
            certificates = [x509.load_der_x509_certificate(encoded)]
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="Certificate must be a PEM or DER encoded .crt/.pem file",
            ) from exc
    if not certificates:
        raise HTTPException(status_code=422, detail="Certificate file contains no certificates")
    normalized = b"".join(
        certificate.public_bytes(serialization.Encoding.PEM) for certificate in certificates
    ).decode()
    return certificates[0], normalized


def normalize_private_key(private_key_data: bytes | str) -> tuple[object, str]:
    encoded = private_key_data.encode() if isinstance(private_key_data, str) else private_key_data
    try:
        private_key = serialization.load_pem_private_key(encoded, password=None)
    except (TypeError, ValueError):
        try:
            private_key = serialization.load_der_private_key(encoded, password=None)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail="Private key must be an unencrypted PEM or DER encoded .key/.pem file",
            ) from exc
    normalized = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return private_key, normalized


def certificate_details(
    certificate_data: bytes | str, private_key_data: bytes | str
) -> tuple[dict[str, object], str, str]:
    certificate, certificate_pem = normalize_certificate_chain(certificate_data)
    private_key, private_key_pem = normalize_private_key(private_key_data)
    try:
        private_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422, detail="TLS private key type is not supported"
        ) from exc
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if certificate_public != private_public:
        raise HTTPException(
            status_code=422, detail="TLS certificate does not match the private key"
        )
    now = datetime.now(UTC)
    if certificate.not_valid_after_utc <= now:
        raise HTTPException(status_code=422, detail="TLS certificate is expired")
    if certificate.not_valid_before_utc > now + timedelta(minutes=5):
        raise HTTPException(status_code=422, detail="TLS certificate is not valid yet")
    try:
        hostnames = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        hostnames = []
    details = {
        "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "hostnames": hostnames,
        "not_valid_before": certificate.not_valid_before_utc,
        "not_valid_after": certificate.not_valid_after_utc,
    }
    return details, certificate_pem, private_key_pem


def _atomic_write(path_text: str, content: str, mode: int, shared_gid: int | None = None) -> None:
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if shared_gid is not None:
            os.chown(temporary, -1, shared_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def materialize_certificate(certificate: TlsCertificate, settings: Settings) -> None:
    private_key = decrypt_secret(
        certificate.private_key_ciphertext,
        settings.session_secret,
        settings.settings_encryption_key,
    )
    _atomic_write(
        settings.tls_certificate_path,
        certificate.certificate_chain_pem,
        0o644,
        settings.tls_shared_gid,
    )
    _atomic_write(settings.tls_private_key_path, private_key, 0o640, settings.tls_shared_gid)
    reload_marker = str(Path(settings.tls_certificate_path).with_name("tls.reload"))
    _atomic_write(reload_marker, f"{now_utc().isoformat()}\n", 0o640, settings.tls_shared_gid)


def install_certificate(
    db: Session,
    tenant_id: str,
    certificate_data: bytes | str,
    private_key_data: bytes | str,
    settings: Settings,
    uploaded_by: str | None,
) -> TlsCertificate:
    details, certificate_pem, private_key_pem = certificate_details(
        certificate_data, private_key_data
    )
    for current in db.scalars(
        select(TlsCertificate).where(
            TlsCertificate.tenant_id == tenant_id, TlsCertificate.is_active.is_(True)
        )
    ).all():
        current.is_active = False
    certificate = TlsCertificate(
        tenant_id=tenant_id,
        certificate_chain_pem=certificate_pem,
        private_key_ciphertext=encrypt_secret(
            private_key_pem, settings.session_secret, settings.settings_encryption_key
        ),
        uploaded_by=uploaded_by,
        is_active=True,
        **details,
    )
    db.add(certificate)
    db.flush()
    materialize_certificate(certificate, settings)
    return certificate


def bootstrap_tls(db: Session, settings: Settings) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": 5499808732000002})
    active = db.scalar(select(TlsCertificate).where(TlsCertificate.is_active.is_(True)))
    if active is not None:
        materialize_certificate(active, settings)
        return
    tenant = db.scalar(select(Tenant).order_by(Tenant.created_at))
    if tenant is None:
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = now_utc()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    install_certificate(db, tenant.id, certificate_pem, private_key_pem, settings, None)
    db.commit()
