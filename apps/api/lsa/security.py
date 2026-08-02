import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _b64_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${_b64_encode(salt)}${_b64_encode(derived)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt_text, expected = encoded.split("$", 2)
        if algorithm != "scrypt":
            return False
        candidate = hash_password(password, _b64_decode(salt_text)).split("$", 2)[2]
        return hmac.compare_digest(candidate, expected)
    except (ValueError, TypeError):
        return False


def hash_ingestion_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session_token(
    user_id: str, tenant_id: str, role: str, secret: str, ttl_minutes: int
) -> str:
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "exp": int((datetime.now(UTC) + timedelta(minutes=ttl_minutes)).timestamp()),
    }
    encoded = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = _b64_encode(hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def decode_session_token(token: str, secret: str) -> dict[str, str | int]:
    try:
        encoded, signature = token.split(".", 1)
        expected = _b64_encode(hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid signature")
        payload = json.loads(_b64_decode(encoded))
        if int(payload["exp"]) < int(datetime.now(UTC).timestamp()):
            raise ValueError("expired token")
        return payload
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("invalid session") from exc

