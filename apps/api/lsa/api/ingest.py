import io
import json
import zipfile
from hashlib import sha256

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from lsa.config import Settings, get_settings
from lsa.database import get_db
from lsa.dependencies import IngestionPrincipal, ingestion_principal
from lsa.schemas import IngestResponse, ReportInput
from lsa.services.ingestion import ingest_report


router = APIRouter(prefix="/ingest", tags=["ingestion"])


def verify_bundle(bundle: zipfile.ZipFile, max_expanded_bytes: int) -> bytes:
    names = set(bundle.namelist())
    required = {"report.json", "manifest.json", "checksums.sha256"}
    if not required.issubset(names):
        raise HTTPException(status_code=422, detail="Bundle is missing required files")
    if any(name.startswith("/") or ".." in name.split("/") for name in names):
        raise HTTPException(status_code=422, detail="Unsafe bundle path")
    if sum(item.file_size for item in bundle.infolist()) > max_expanded_bytes:
        raise HTTPException(status_code=422, detail="Bundle expands beyond the allowed size")

    manifest = json.loads(bundle.read("manifest.json"))
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
    return bundle.read("report.json")


@router.post("/reports", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
def submit_report(
    report: ReportInput,
    principal: IngestionPrincipal = Depends(ingestion_principal),
    db: Session = Depends(get_db),
) -> IngestResponse:
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
            report_bytes = verify_bundle(bundle, settings.max_upload_bytes * 5)
        report = ReportInput.model_validate(json.loads(report_bytes))
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=422, detail="Invalid ZIP bundle") from exc
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as exc:
        raise HTTPException(status_code=422, detail="Invalid report.json") from exc
    return ingest_report(db, report, principal, file.filename, data)
