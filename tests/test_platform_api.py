from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from tests.conftest import ADMIN


def test_health_is_public_and_sets_security_headers(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["demo_mode"] is True
    assert body["environment"] == "test"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-request-id"]


def test_root_and_openapi_describe_authorized_use(client: TestClient) -> None:
    root = client.get("/")
    assert root.status_code == 200
    assert root.json()["tagline"] == "ONE FRAMEWORK. COMPLETE RED TEAM OPERATIONS."
    assert "authorized" in root.json()["notice"].lower()

    spec = client.get("/openapi.json")
    assert spec.status_code == 200
    assert "/api/v1/assessments" in spec.json()["paths"]
    assert spec.json()["info"]["license"]["name"] == "MIT"


def test_login_rejects_bad_password_and_accepts_demo_account(client: TestClient) -> None:
    bad = client.post(
        "/api/v1/auth/login",
        json={"email": ADMIN["email"], "password": "Wrong-Password-2026!"},
    )
    assert bad.status_code == 401
    assert bad.json()["error"]["code"] == "invalid_credentials"

    good = client.post("/api/v1/auth/login", json=ADMIN)
    assert good.status_code == 200
    payload = good.json()
    assert payload["token_type"] == "bearer"
    assert payload["user"]["role"] == "admin"
    assert len(payload["access_token"].split(".")) == 3

    me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {payload['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["email"] == ADMIN["email"]


def test_registration_and_duplicate_email(client: TestClient) -> None:
    email = f"operator-{uuid.uuid4().hex[:10]}@example.com"
    payload = {
        "email": email,
        "name": "Field Operator",
        "password": "Field!Operator2026",
    }
    created = client.post("/api/v1/auth/register", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["user"]["email"] == email
    assert created.json()["user"]["role"] == "analyst"

    duplicate = client.post("/api/v1/auth/register", json=payload)
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "email_exists"


def test_password_validation_never_echoes_the_submitted_secret(client: TestClient) -> None:
    secret = "NoSymbolsButLong2026"
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "weak@example.com", "name": "Weak Password", "password": secret},
    )
    assert response.status_code == 422
    assert secret not in response.text


def test_analyst_cannot_read_audit_but_admin_can_verify_chain(
    client: TestClient,
    admin_headers: dict[str, str],
    analyst_headers: dict[str, str],
) -> None:
    forbidden = client.get("/api/v1/audit", headers=analyst_headers)
    assert forbidden.status_code == 403

    audit = client.get("/api/v1/audit", headers=admin_headers, params={"limit": 20})
    assert audit.status_code == 200
    assert audit.json()["total"] > 0
    first = audit.json()["items"][0]
    assert {"action", "prev_hash", "entry_hash", "actor_email"} <= set(first)

    verification = client.get("/api/v1/audit/verify", headers=admin_headers)
    assert verification.status_code == 200
    assert verification.json()["valid"] is True
    assert verification.json()["checked"] > 0


def test_dashboard_modules_mitre_and_coverage(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    dashboard = client.get("/api/v1/dashboard", headers=admin_headers)
    assert dashboard.status_code == 200
    stats = dashboard.json()["stats"]
    assert stats["total_assessments"] >= 8
    assert stats["total_findings"] >= 18
    assert stats["verified_targets"] >= 4

    modules = client.get("/api/v1/modules", headers=admin_headers)
    assert modules.status_code == 200
    assert modules.json()["total"] == 10
    module_ids = {item["id"] for item in modules.json()["items"]}
    assert module_ids == {
        "recon",
        "network",
        "web",
        "vulnerability",
        "osint",
        "password",
        "active_directory",
        "cloud",
        "api_security",
        "red_team",
    }

    tactics = client.get("/api/v1/mitre/tactics", headers=admin_headers)
    assert tactics.status_code == 200
    assert tactics.json()["total"] == 15

    techniques = client.get(
        "/api/v1/mitre/techniques",
        headers=admin_headers,
        params={"query": "phishing", "limit": 10},
    )
    assert techniques.status_code == 200
    assert techniques.json()["total"] >= 1

    coverage = client.get("/api/v1/mitre/coverage", headers=admin_headers)
    assert coverage.status_code == 200
    assert coverage.json()["total"] > 200
    assert len(coverage.json()["tactics"]) == 15


def test_cvss_calculator_and_invalid_vector(
    client: TestClient,
    analyst_headers: dict[str, str],
) -> None:
    response = client.post(
        "/api/v1/tools/cvss",
        headers=analyst_headers,
        json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    )
    assert response.status_code == 200
    assert response.json()["score"] == 9.8
    assert response.json()["severity"] == "critical"

    invalid = client.post(
        "/api/v1/tools/cvss",
        headers=analyst_headers,
        json={"vector": "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "invalid_cvss_vector"


def test_report_generation_and_download(
    client: TestClient,
    admin_headers: dict[str, str],
    completed_assessment: dict,
) -> None:
    created = client.post(
        "/api/v1/reports",
        headers=admin_headers,
        json={"assessment_id": completed_assessment["id"], "format": "html"},
    )
    assert created.status_code == 201, created.text
    report = created.json()
    assert report["format"] == "html"
    assert report["size_bytes"] > 1000

    download = client.get(f"/api/v1/reports/{report['id']}/download", headers=admin_headers)
    assert download.status_code == 200
    assert "attachment" in download.headers["content-disposition"]
    assert download.text.lower().startswith("<!doctype html>")
    assert completed_assessment["name"] in download.text

    deleted = client.delete(f"/api/v1/reports/{report['id']}", headers=admin_headers)
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/reports/{report['id']}", headers=admin_headers).status_code == 404


def test_notifications_and_settings_are_user_scoped(
    client: TestClient,
    analyst_headers: dict[str, str],
) -> None:
    notifications = client.get("/api/v1/notifications", headers=analyst_headers)
    assert notifications.status_code == 200
    assert notifications.json()["total"] >= 1

    settings = client.get("/api/v1/settings", headers=analyst_headers)
    assert settings.status_code == 200
    preferences = settings.json()["user"]["preferences"]
    original = preferences.get("compactMode", False)
    updated = client.patch(
        "/api/v1/settings",
        headers=analyst_headers,
        json={"preferences": {**preferences, "compactMode": not original}},
    )
    assert updated.status_code == 200
    assert updated.json()["preferences"]["compactMode"] is (not original)

    restored = client.patch(
        "/api/v1/settings",
        headers=analyst_headers,
        json={"preferences": {**preferences, "compactMode": original}},
    )
    assert restored.status_code == 200


def test_viewer_role_cannot_create_targets(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    email = f"viewer-{uuid.uuid4().hex[:10]}@example.com"
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": email, "name": "Read Only", "password": "ReadOnly!2026"},
    )
    assert registered.status_code == 201, registered.text
    viewer_id = registered.json()["user"]["id"]
    viewer_headers = {"Authorization": f"Bearer {registered.json()['access_token']}"}

    promoted = client.patch(
        f"/api/v1/users/{viewer_id}",
        headers=admin_headers,
        json={"role": "viewer"},
    )
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "viewer"

    readable = client.get("/api/v1/dashboard", headers=viewer_headers)
    assert readable.status_code == 200

    denied = client.post(
        "/api/v1/targets",
        headers=viewer_headers,
        json={
            "name": "Viewer Attempt",
            "target_type": "domain",
            "value": "viewer-attempt.example.com",
            "environment": "lab",
            "authorization_ref": "VIEWER-TEST-001",
            "authorized_by": "Test Operator",
            "allowed_actions": ["recon"],
        },
    )
    assert denied.status_code == 403
