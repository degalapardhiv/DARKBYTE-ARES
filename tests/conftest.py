from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Configure an isolated, disposable environment before importing the app. The
# settings object is cached at import time, so these must be set first.
TEST_ROOT = Path(tempfile.mkdtemp(prefix="ares-pytest-"))
os.environ.update(
    {
        "APP_ENV": "test",
        "DEBUG": "false",
        "DEMO_MODE": "true",
        "ALLOW_REGISTRATION": "true",
        "SECRET_KEY": "ares-test-secret-key-0123456789-abcdefghijklmnopqrstuvwxyz",
        "DATABASE_URL": f"sqlite+aiosqlite:///{TEST_ROOT / 'ares-test.db'}",
        "REPORTS_DIR": str(TEST_ROOT / "reports"),
        "REDIS_URL": "",
        "RATE_LIMIT_PER_MINUTE": "5000",
        "ACTIVE_SCAN_RATE_LIMIT": "500",
        "MAX_CONCURRENT_ASSESSMENTS": "2",
        "CACHE_TTL_SECONDS": "900",
    }
)

from backend.main import app  # noqa: E402

ADMIN = {"email": "admin@ares.example.com", "password": "Ares!Admin2026"}
ANALYST = {"email": "analyst@ares.example.com", "password": "Ares!Analyst2026"}


@atexit.register
def _cleanup() -> None:
    shutil.rmtree(TEST_ROOT, ignore_errors=True)


@pytest.fixture(scope="session")
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def admin_headers(client: TestClient) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json=ADMIN)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="session")
def analyst_headers(client: TestClient) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json=ANALYST)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="session")
def demo_targets(client: TestClient, admin_headers: dict[str, str]) -> dict[str, dict]:
    response = client.get("/api/v1/targets", headers=admin_headers, params={"limit": 50})
    assert response.status_code == 200, response.text
    return {item["target_type"]: item for item in response.json()["items"]}


@pytest.fixture(scope="session")
def completed_assessment(client: TestClient, admin_headers: dict[str, str]) -> dict:
    response = client.get(
        "/api/v1/assessments",
        headers=admin_headers,
        params={"status": "completed", "limit": 50},
    )
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert items, "demo seed did not create completed assessments"
    return items[0]
