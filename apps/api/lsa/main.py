from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from lsa.api import auth, fleet, ingest
from lsa.config import get_settings
from lsa.database import Base, SessionLocal, engine
from lsa.seed import bootstrap


settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        bootstrap(db, settings)
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
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(ingest.router, prefix="/api/v1")
app.include_router(fleet.router, prefix="/api/v1")


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "lsa-api", "version": "0.1.0"}

