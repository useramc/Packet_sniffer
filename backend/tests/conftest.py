import os
import pathlib
import sys

# Set a throwaway JWT secret for the whole test session BEFORE importing
# any app code, since auth.config reads it at import time.
os.environ.setdefault("PPS_JWT_SECRET", "test-only-secret-not-for-production")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Give every test its own throwaway SQLite file so tests never leak state."""
    db_path = tmp_path / "pps_auth_test.db"
    monkeypatch.setenv("PPS_AUTH_DB", str(db_path))
    from auth import config as auth_config
    monkeypatch.setattr(auth_config, "DB_PATH", str(db_path))
    from auth import store
    store.init_db()
    yield
