from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from igiris.api import create_app
from igiris.config import Settings
from igiris.store import Store

@pytest.fixture
def store(tmp_path: Path) -> Store:
    db = Store(tmp_path / "igiris.db")
    db.initialize()
    yield db
    db.close()

@pytest.fixture
def client(store: Store) -> TestClient:
    settings = Settings(database_path=str(store.path), static_dir="missing", collector_enabled=False, allowed_hosts="testserver")
    return TestClient(create_app(settings=settings, store=store))
