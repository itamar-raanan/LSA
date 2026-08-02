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
            names = set(bundle.namelist())
            required = {"report.json", "manifest.json", "checksums.sha256"}
            if not required.issubset(names):
                raise HTTPException(status_code=422, detail="Bundle is missing required files")
            if any(name.startswith("/") or ".." in name.split("/") for name in names):
                raise HTTPException(status_code=422, detail="Unsafe bundle path")
            if sum(item.file_size for item in bundle.infolist()) > settings.max_upload_bytes * 5:
                raise HTTPException(status_code=422, detail="Bundle expands beyond the allowed size")
            report_bytes = bundle.read("report.json")
            manifest = json.loads(bundle.read("manifest.json"))
            expected_checksum = manifest.get("files", {}).get("report.json")
            if expected_checksum != sha256(report_bytes).hexdigest():
                raise HTTPException(status_code=422, detail="Report checksum does not match manifest")
        report = ReportInput.model_validate(json.loads(report_bytes))
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=422, detail="Invalid ZIP bundle") from exc
    except (json.JSONDecodeError, ValidationError) as exc:
        raise HTTPException(status_code=422, detail="Invalid report.json") from exc
    return ingest_report(db, report, principal, file.filename, data)
