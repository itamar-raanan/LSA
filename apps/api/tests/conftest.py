import os
import shutil

os.environ.setdefault("LSA_DATABASE_URL", "sqlite:///./lsa-test.sqlite3")
os.environ.setdefault("LSA_SEED_DEMO", "false")
os.environ.setdefault("LSA_BOOTSTRAP_PASSWORD", "test-password")
os.environ.setdefault("LSA_SESSION_SECRET", "test-session-secret-with-more-than-32-chars")
os.environ.setdefault("LSA_ARTIFACT_PATH", "/tmp/lsa-test-artifacts")

import pytest
from fastapi.testclient import TestClient

from lsa.database import Base, engine
from lsa.main import app


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
