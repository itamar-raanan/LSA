import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from lsa.database import SessionLocal
import jwt
import pytest
from fastapi import HTTPException

from lsa.config import get_settings
from lsa.config import Settings
from lsa.models import AuthTransaction, IdentityProvider, User, now_utc
from lsa.security import encrypt_secret
from lsa.services.identity import validate_id_token


def login(client) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@lsa.local", "password": "test-password"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def headers(client) -> dict[str, str]:
    return {"Authorization": f"Bearer {login(client)}"}


def test_agent_public_url_requires_a_dedicated_https_origin():
    assert Settings(agent_public_url="https://agents.example.test:8444/").agent_public_url == (
        "https://agents.example.test:8444"
    )
    with pytest.raises(ValueError, match="HTTPS origin"):
        Settings(agent_public_url="http://agents.example.test:8444/api")


def test_provider_secret_is_write_only_and_public_listing_is_minimal(client):
    response = client.post(
        "/api/v1/settings/identity-providers",
        headers=headers(client),
        json={
            "name": "Corporate RADIUS",
            "provider_type": "radius",
            "secret": "super-secret-radius-value",
            "config": {"host": "radius.internal", "port": 1812, "user_domain": "example.com"},
            "is_enabled": True,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["secret_configured"] is True
    assert "super-secret" not in response.text
    public = client.get("/api/v1/auth/providers")
    assert public.json() == [
        {"id": response.json()["id"], "name": "Corporate RADIUS", "provider_type": "radius"}
    ]
    with SessionLocal() as db:
        provider = db.get(IdentityProvider, response.json()["id"])
        assert provider.secret_ciphertext != "super-secret-radius-value"


def test_radius_success_jit_provisions_user(client, monkeypatch):
    created = client.post(
        "/api/v1/settings/identity-providers",
        headers=headers(client),
        json={
            "name": "RADIUS",
            "provider_type": "radius",
            "secret": "secret",
            "config": {"host": "radius.internal", "user_domain": "example.com"},
            "is_enabled": True,
        },
    )
    assert created.status_code == 201
    monkeypatch.setattr("lsa.api.auth.radius_authenticate", lambda *args: ("itamar", "analyst"))
    response = client.post(
        "/api/v1/auth/radius/login", json={"username": "itamar", "password": "password"}
    )
    assert response.status_code == 200
    assert response.json()["user"] == {
        "id": response.json()["user"]["id"],
        "email": "itamar@example.com",
        "name": "itamar",
        "role": "analyst",
    }
    analyst_headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/api/v1/settings/users", headers=analyst_headers).status_code == 403
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "itamar@example.com"))
        assert user.auth_source == "radius"
        assert user.password_hash is None


def test_oidc_start_uses_discovery_state_nonce_and_pkce(client, monkeypatch):
    settings = get_settings()
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.email == "admin@lsa.local"))
        provider = IdentityProvider(
            tenant_id=admin.tenant_id,
            name="ADFS",
            provider_type="adfs",
            issuer_url="https://adfs.example.com/adfs",
            client_id="lsa-client",
            secret_ciphertext=encrypt_secret(
                "client-secret", settings.session_secret, settings.settings_encryption_key
            ),
            config={},
            is_enabled=True,
        )
        db.add(provider)
        db.commit()
        provider_id = provider.id

    async def discovery(*_):
        return {
            "issuer": "https://adfs.example.com/adfs",
            "authorization_endpoint": "https://adfs.example.com/adfs/oauth2/authorize",
            "token_endpoint": "https://adfs.example.com/adfs/oauth2/token",
            "jwks_uri": "https://adfs.example.com/adfs/discovery/keys",
        }

    monkeypatch.setattr("lsa.api.auth.fetch_discovery", discovery)
    response = client.get(f"/api/v1/auth/oidc/{provider_id}/start")
    assert response.status_code == 200
    query = parse_qs(urlparse(response.json()["authorization_url"]).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["nonce"] and query["state"] and query["code_challenge"]
    with SessionLocal() as db:
        transaction = db.scalar(select(AuthTransaction))
        assert transaction is not None
        assert transaction.state_hash != query["state"][0]


def test_oidc_id_token_validation_enforces_signature_audience_issuer_and_nonce():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public_jwk.update({"kid": "key-1", "alg": "RS256", "use": "sig"})
    provider = IdentityProvider(client_id="lsa-client")
    claims = {
        "sub": "subject-1",
        "iss": "https://issuer.example.com",
        "aud": "lsa-client",
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        "nonce": "expected",
    }
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "key-1"})
    validated = validate_id_token(
        token, {"keys": [public_jwk]}, provider, {"issuer": claims["iss"]}, "expected"
    )
    assert validated["sub"] == "subject-1"
    with pytest.raises(HTTPException, match="nonce"):
        validate_id_token(
            token, {"keys": [public_jwk]}, provider, {"issuer": claims["iss"]}, "wrong"
        )


def test_user_lifecycle_and_session_revocation_are_admin_controlled(client):
    admin_headers = headers(client)
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.email == "admin@lsa.local"))
        external = User(
            tenant_id=admin.tenant_id,
            email="auditor@example.com",
            display_name="External Auditor",
            role="auditor",
            auth_source="radius",
            external_subject="auditor",
        )
        db.add(external)
        db.commit()
        external_id = external.id
    listed = client.get("/api/v1/settings/users", headers=admin_headers)
    assert listed.status_code == 200
    assert {item["email"] for item in listed.json()} == {"admin@lsa.local", "auditor@example.com"}
    changed = client.patch(
        f"/api/v1/settings/users/{external_id}/role",
        headers=admin_headers,
        json={"role": "analyst"},
    )
    assert changed.status_code == 200
    assert changed.json()["role"] == "analyst"
    disabled = client.patch(
        f"/api/v1/settings/users/{external_id}/status",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["is_active"] is False


def test_admin_can_preprovision_radius_user_with_manual_role(client):
    admin_headers = headers(client)
    provider = client.post(
        "/api/v1/settings/identity-providers",
        headers=admin_headers,
        json={
            "name": "Staff RADIUS",
            "provider_type": "radius",
            "secret": "secret",
            "config": {"host": "radius.internal", "user_domain": "example.com"},
            "is_enabled": True,
        },
    ).json()
    created = client.post(
        "/api/v1/settings/users",
        headers=admin_headers,
        json={
            "email": "Itamar@Example.com",
            "display_name": "Itamar Raanan",
            "role": "analyst",
            "provider_id": provider["id"],
            "external_subject": "ITAMAR",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["email"] == "itamar@example.com"
    assert created.json()["provider_name"] == "Staff RADIUS"
    with SessionLocal() as db:
        provisioned = db.get(User, created.json()["id"])
        assert provisioned.external_subject == "itamar"
        assert provisioned.password_hash is None
        assert provisioned.role_source == "manual"


def test_preprovisioned_role_is_not_replaced_by_radius_mapping(client, monkeypatch):
    admin_headers = headers(client)
    provider = client.post(
        "/api/v1/settings/identity-providers",
        headers=admin_headers,
        json={
            "name": "Mapped RADIUS",
            "provider_type": "radius",
            "secret": "secret",
            "config": {"host": "radius.internal", "user_domain": "example.com"},
            "is_enabled": True,
        },
    ).json()
    client.post(
        "/api/v1/settings/users",
        headers=admin_headers,
        json={
            "email": "manual@example.com",
            "display_name": "Manual Role",
            "role": "admin",
            "provider_id": provider["id"],
            "external_subject": "manual",
        },
    )
    monkeypatch.setattr("lsa.api.auth.radius_authenticate", lambda *args: ("manual", "auditor"))
    response = client.post(
        "/api/v1/auth/radius/login", json={"username": "manual", "password": "password"}
    )
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "admin"


def test_logout_revokes_database_backed_session(client):
    token = login(client)
    auth = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/settings/users", headers=auth).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=auth).status_code == 204
    assert client.get("/api/v1/settings/users", headers=auth).status_code == 401


def certificate_pair(common_name: str = "lsa.example.com") -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = now_utc()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def test_tls_upload_validates_and_never_returns_private_key(client):
    certificate, private_key = certificate_pair()
    response = client.post(
        "/api/v1/settings/tls-certificate",
        headers=headers(client),
        files={
            "certificate": ("chain.pem", certificate, "application/x-pem-file"),
            "private_key": ("key.pem", private_key, "application/x-pem-file"),
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["hostnames"] == ["lsa.example.com"]
    assert "PRIVATE KEY" not in response.text
    _, other_key = certificate_pair("other.example.com")
    mismatch = client.post(
        "/api/v1/settings/tls-certificate",
        headers=headers(client),
        files={
            "certificate": ("chain.pem", certificate, "application/x-pem-file"),
            "private_key": ("key.pem", other_key, "application/x-pem-file"),
        },
    )
    assert mismatch.status_code == 422
    assert mismatch.json()["detail"] == "TLS certificate does not match the private key"


def test_tls_upload_accepts_der_encoded_crt_and_key(client):
    certificate_pem, private_key_pem = certificate_pair("der.lsa.example.com")
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    response = client.post(
        "/api/v1/settings/tls-certificate",
        headers=headers(client),
        files={
            "certificate": (
                "server.crt",
                certificate.public_bytes(serialization.Encoding.DER),
                "application/pkix-cert",
            ),
            "private_key": (
                "server.key",
                private_key.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                "application/octet-stream",
            ),
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["hostnames"] == ["der.lsa.example.com"]
