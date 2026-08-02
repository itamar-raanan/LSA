import io
import json
import zipfile
from base64 import b64decode
from binascii import Error as BinasciiError
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from lsa.config import Settings, get_settings
from lsa.database import get_db
from lsa.dependencies import IngestionPrincipal, ingestion_principal
from lsa.models import SigningKey
from lsa.schemas import IngestResponse, ReportInput
from lsa.services.ingestion import ingest_report


router = APIRouter(prefix="/ingest", tags=["ingestion"])


@dataclass(frozen=True)
class VerifiedBundle:
    report_bytes: bytes
    manifest_bytes: bytes
    signing_key_id: str | None
    signature_bytes: bytes | None


def verify_bundle(
    bundle: zipfile.ZipFile,
    max_expanded_bytes: int,
    require_signature: bool = False,
) -> VerifiedBundle:
    names = set(bundle.namelist())
    required = {"report.json", "manifest.json", "checksums.sha256"}
    if not required.issubset(names):
        raise HTTPException(status_code=422, detail="Bundle is missing required files")
    if any(name.startswith("/") or ".." in name.split("/") for name in names):
        raise HTTPException(status_code=422, detail="Unsafe bundle path")
    if sum(item.file_size for item in bundle.infolist()) > max_expanded_bytes:
        raise HTTPException(status_code=422, detail="Bundle expands beyond the allowed size")

    manifest_bytes = bundle.read("manifest.json")
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict):
        raise HTTPException(status_code=422, detail="Invalid bundle manifest")
    declared_files = manifest.get("files")
    if not isinstance(declared_files, dict) or "report.json" not in declared_files:
        raise HTTPException(status_code=422, detail="Invalid bundle manifest")
    for name, expected in declared_files.items():
        if name not in names or not isinstance(expected, str):
            raise HTTPException(status_code=422, detail=f"Manifest entry is missing: {name}")
        if sha256(bundle.read(name)).hexdigest() != expected:
            raise HTTPException(status_code=422, detail=f"Checksum mismatch: {name}")

    checksum_entries: dict[str, str] = {}
    for line in bundle.read("checksums.sha256").decode().splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or len(digest) != 64:
            raise HTTPException(status_code=422, detail="Invalid checksums.sha256 format")
        checksum_entries[name] = digest
    if not set(declared_files).issubset(checksum_entries):
        raise HTTPException(status_code=422, detail="Checksum list is incomplete")
    for name, expected in checksum_entries.items():
        if name not in names or sha256(bundle.read(name)).hexdigest() != expected:
            raise HTTPException(status_code=422, detail=f"Checksum mismatch: {name}")

    signature = manifest.get("signature")
    if signature is None:
        if require_signature:
            raise HTTPException(status_code=422, detail="Signed bundle required")
        return VerifiedBundle(bundle.read("report.json"), manifest_bytes, None, None)
    if (
        not isinstance(signature, dict)
        or signature.get("algorithm") != "ed25519"
        or not isinstance(signature.get("key_id"), str)
        or not signature["key_id"]
        or "signature.sig" not in names
    ):
        raise HTTPException(status_code=422, detail="Invalid bundle signature metadata")
    if "signature.sig" not in checksum_entries:
        raise HTTPException(status_code=422, detail="Checksum list is incomplete")
    try:
        signature_bytes = b64decode(bundle.read("signature.sig"), validate=True)
    except (BinasciiError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Invalid bundle signature") from exc
    if len(signature_bytes) != 64:
        raise HTTPException(status_code=422, detail="Invalid bundle signature")
    return VerifiedBundle(
        bundle.read("report.json"),
        manifest_bytes,
        signature["key_id"],
        signature_bytes,
    )


def verify_signing_key(
    db: Session,
    principal: IngestionPrincipal,
    report: ReportInput,
    verified: VerifiedBundle,
) -> str | None:
    if verified.signing_key_id is None:
        return None
    key = db.get(SigningKey, verified.signing_key_id)
    if key is None or key.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=401, detail="Signing key is not trusted")
    if key.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Signing key is revoked")
    expires_at = key.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            raise HTTPException(status_code=401, detail="Signing key is expired")
    report_host_id = str(report.host.host_id)
    if key.host_id is not None and key.host_id != report_host_id:
        raise HTTPException(status_code=403, detail="Signing key cannot sign for this host")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64decode(key.public_key, validate=True))
        public_key.verify(verified.signature_bytes or b"", verified.manifest_bytes)
    except (BinasciiError, ValueError, InvalidSignature) as exc:
        raise HTTPException(status_code=422, detail="Bundle signature verification failed") from exc
    return key.id


@router.post("/reports", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
def submit_report(
    report: ReportInput,
    principal: IngestionPrincipal = Depends(ingestion_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> IngestResponse:
    if settings.require_signed_bundles:
        raise HTTPException(status_code=422, detail="Signed bundle required")
    return ingest_report(db, report, principal)


@router.post("/bundles", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_bundle(
    file: UploadFile = File(...),
    principal: IngestionPrincipal = Depends(ingestion_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> IngestResponse:
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Bundle too large")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            verified = verify_bundle(
                bundle,
                settings.max_upload_bytes * 5,
                settings.require_signed_bundles,
            )
        report = ReportInput.model_validate(json.loads(verified.report_bytes))
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=422, detail="Invalid ZIP bundle") from exc
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as exc:
        raise HTTPException(status_code=422, detail="Invalid report.json") from exc
    signing_key_id = verify_signing_key(db, principal, report, verified)
    return ingest_report(
        db,
        report,
        principal,
        file.filename,
        data,
        signing_key_id=signing_key_id,
        signature_verified=signing_key_id is not None,
    )
