import os
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEST_AGENT_WHEELHOUSE = Path("/tmp/lsa-test-agent-wheelhouse")
TEST_AGENT_WHEELHOUSE.mkdir(parents=True, exist_ok=True)
(TEST_AGENT_WHEELHOUSE / "lsa_test_dependency-1.0-py3-none-any.whl").write_bytes(
    b"test-only-wheel-content"
)

os.environ.setdefault("LSA_DATABASE_URL", "sqlite:///./lsa-test.sqlite3")
os.environ.setdefault("LSA_SEED_DEMO", "false")
os.environ.setdefault("LSA_BOOTSTRAP_PASSWORD", "test-password")
os.environ.setdefault("LSA_SESSION_SECRET", "test-session-secret-with-more-than-32-chars")
os.environ.setdefault("LSA_ARTIFACT_PATH", "/tmp/lsa-test-artifacts")
os.environ.setdefault("LSA_AGENT_WHEELHOUSE_DIR", str(TEST_AGENT_WHEELHOUSE))

from lsa.database import Base, engine  # noqa: E402
from lsa.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_database():
    shutil.rmtree("/tmp/lsa-test-artifacts", ignore_errors=True)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    shutil.rmtree("/tmp/lsa-test-artifacts", ignore_errors=True)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
