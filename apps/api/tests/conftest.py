import os

os.environ["LSA_DATABASE_URL"] = "sqlite:///./lsa-test.sqlite3"
os.environ["LSA_SEED_DEMO"] = "false"
os.environ["LSA_BOOTSTRAP_PASSWORD"] = "test-password"
os.environ["LSA_SESSION_SECRET"] = "test-session-secret-with-more-than-32-chars"

import pytest
from fastapi.testclient import TestClient

from lsa.database import Base, engine
from lsa.main import app


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client

