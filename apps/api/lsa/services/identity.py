import base64
import hashlib
import ipaddress
import io
import socket
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
import jwt
from fastapi import HTTPException, status
from jwt import PyJWKSet
from pyrad import dictionary, packet
from pyrad.client import Client, Timeout
from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.config import Settings
from lsa.models import IdentityProvider, User, now_utc
from lsa.security import decrypt_secret


RADIUS_DICTIONARY = """\
ATTRIBUTE User-Name 1 string
ATTRIBUTE User-Password 2 string
ATTRIBUTE NAS-Identifier 32 string
ATTRIBUTE Reply-Message 18 string
ATTRIBUTE Filter-Id 11 string
ATTRIBUTE Class 25 octets
"""


def validate_identity_url(url: str, allow_private: bool) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(status_code=422, detail="Identity provider URLs must be HTTPS URLs")
    if not allow_private:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, 443)}
        except socket.gaierror as exc:
            raise HTTPException(
                status_code=422, detail="Identity provider host cannot be resolved"
            ) from exc
        if any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise HTTPException(
                status_code=422,
                detail="Private identity provider addresses require LSA_ALLOW_PRIVATE_IDENTITY_PROVIDERS=true",
            )
    return url.rstrip("/")


def role_from_mapping(value: object, mapping: object, default_role: str = "auditor") -> str:
    valid = {"admin", "analyst", "auditor"}
    if not isinstance(mapping, dict):
        return default_role if default_role in valid else "auditor"
    values = value if isinstance(value, list) else [value]
    for candidate in values:
        mapped = mapping.get(str(candidate))
        if mapped in valid:
            return str(mapped)
    return default_role if default_role in valid else "auditor"


def jit_user(
    db: Session,
    provider: IdentityProvider,
    subject: str,
    email: str,
    display_name: str,
    role: str,
) -> User:
    user = db.scalar(
        select(User).where(
            User.tenant_id == provider.tenant_id,
            User.identity_provider_id == provider.id,
            User.external_subject == subject,
        )
    )
    email_owner = db.scalar(select(User).where(User.email.ilike(email)))
    if user is None and email_owner is not None:
        raise HTTPException(
            status_code=409, detail="The asserted email belongs to another identity"
        )
    if user is None:
        user = User(
            tenant_id=provider.tenant_id,
            email=email.lower(),
            display_name=display_name,
            password_hash=None,
            role=role,
            auth_source=provider.provider_type,
            identity_provider_id=provider.id,
            external_subject=subject,
        )
        db.add(user)
        db.flush()
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User access is disabled")
    user.email = email.lower()
    user.display_name = display_name
    user.role = role
    user.last_login_at = now_utc()
    return user


def radius_authenticate(
    provider: IdentityProvider, username: str, password: str, settings: Settings
) -> tuple[str, str]:
    config = provider.config or {}
    host = str(config.get("host", ""))
    if not host:
        raise HTTPException(status_code=503, detail="RADIUS is not fully configured")
    secret = decrypt_secret(
        provider.secret_ciphertext or "", settings.session_secret, settings.settings_encryption_key
    )
    radius_dictionary = dictionary.Dictionary(io.StringIO(RADIUS_DICTIONARY))
    client = Client(
        server=host,
        authport=int(config.get("port", 1812)),
        secret=secret.encode(),
        dict=radius_dictionary,
        timeout=float(config.get("timeout_seconds", 3)),
        retries=int(config.get("retries", 2)),
    )
    request = client.CreateAuthPacket(code=packet.AccessRequest, User_Name=username)
    request["User-Password"] = request.PwCrypt(password)
    if config.get("nas_identifier"):
        request["NAS-Identifier"] = str(config["nas_identifier"])
    try:
        reply = client.SendPacket(request)
    except Timeout as exc:
        raise HTTPException(status_code=503, detail="RADIUS service did not respond") from exc
    if reply.code != packet.AccessAccept:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    attribute = str(config.get("role_attribute", "Filter-Id"))
    raw_value = reply.get(attribute, [""])[0]
    if isinstance(raw_value, bytes):
        raw_value = raw_value.decode(errors="replace")
    return username.casefold(), role_from_mapping(
        raw_value, config.get("role_mapping"), str(config.get("default_role", "auditor"))
    )


async def fetch_discovery(provider: IdentityProvider, settings: Settings) -> dict[str, object]:
    issuer = validate_identity_url(
        provider.issuer_url or "", settings.allow_private_identity_providers
    )
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
    metadata = response.json()
    if str(metadata.get("issuer", "")).rstrip("/") != issuer:
        raise HTTPException(
            status_code=502, detail="Identity provider discovery returned a different issuer"
        )
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        validate_identity_url(
            str(metadata.get(field, "")), settings.allow_private_identity_providers
        )
    return metadata


async def exchange_oidc_code(
    provider: IdentityProvider,
    metadata: dict[str, object],
    code: str,
    redirect_uri: str,
    code_verifier: str,
    nonce: str,
    settings: Settings,
) -> dict[str, object]:
    secret = decrypt_secret(
        provider.secret_ciphertext or "", settings.session_secret, settings.settings_encryption_key
    )
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        token_response = await client.post(
            str(metadata["token_endpoint"]),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": provider.client_id,
                "client_secret": secret,
                "code_verifier": code_verifier,
            },
        )
        if token_response.status_code >= 400:
            raise HTTPException(
                status_code=401, detail="Identity provider rejected the authorization code"
            )
        token_payload = token_response.json()
        jwks_response = await client.get(str(metadata["jwks_uri"]))
        jwks_response.raise_for_status()
    return validate_id_token(
        str(token_payload.get("id_token", "")),
        jwks_response.json(),
        provider,
        metadata,
        nonce,
    )


def validate_id_token(
    id_token: str,
    jwks: dict[str, object],
    provider: IdentityProvider,
    metadata: dict[str, object],
    nonce: str,
) -> dict[str, object]:
    header = jwt.get_unverified_header(id_token)
    allowed_algorithms = {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
    algorithm = str(header.get("alg", ""))
    if algorithm not in allowed_algorithms:
        raise HTTPException(
            status_code=401, detail="Identity token signing algorithm is not allowed"
        )
    jwk_set = PyJWKSet.from_dict(jwks)
    signing_key = next((key for key in jwk_set.keys if key.key_id == header.get("kid")), None)
    if signing_key is None:
        raise HTTPException(status_code=401, detail="Identity token signing key is unknown")
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=[algorithm],
        audience=provider.client_id,
        issuer=str(metadata["issuer"]),
        options={"require": ["exp", "iat", "iss", "sub", "aud"]},
    )
    if claims.get("nonce") != nonce:
        raise HTTPException(status_code=401, detail="Identity token nonce is invalid")
    return claims


def pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def ensure_not_expired(value: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value > datetime.now(UTC)
