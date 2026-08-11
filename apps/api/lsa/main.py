from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from lsa.api import (
    agent_packages,
    admin,
    agents,
    artifacts,
    auth,
    change_sets,
    fleet,
    ingest,
    remediation_actions,
    remediations,
    settings as settings_api,
    vulnerabilities,
)
from lsa.config import get_settings
from lsa.database import Base, SessionLocal, engine, get_db
from lsa.seed import bootstrap
from lsa.services.artifacts import ArtifactStore, get_artifact_store
from lsa.services.certificates import bootstrap_tls
from lsa.services.remediation_catalog import load_remediation_catalog


settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    load_remediation_catalog()
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        bootstrap(db, settings)
        bootstrap_tls(db, settings)
    yield


app = FastAPI(
    title="Linux Security Auditor API",
    version="0.1.0",
    description="Ingestion-first Linux fleet security and compliance API.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["DELETE", "GET", "PATCH", "POST", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Total-Count", "X-Page", "X-Page-Size"],
)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(settings_api.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(agents.router, prefix="/api/v1")
app.include_router(agent_packages.router, prefix="/api/v1")
app.include_router(ingest.router, prefix="/api/v1")
app.include_router(artifacts.router, prefix="/api/v1")
app.include_router(fleet.router, prefix="/api/v1")
app.include_router(vulnerabilities.router, prefix="/api/v1")
app.include_router(remediation_actions.router, prefix="/api/v1")
app.include_router(remediations.router, prefix="/api/v1")
app.include_router(change_sets.router, prefix="/api/v1")


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "lsa-api", "version": "0.1.0"}


@app.get("/ready", tags=["operations"])
def readiness(
    db: Session = Depends(get_db),
    artifact_store: ArtifactStore = Depends(get_artifact_store),
) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    artifact_store.ensure_ready()
    return {"status": "ready", "database": "connected", "evidence_vault": "connected"}
