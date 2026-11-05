from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient


def _target_payload(value: str, actions: list[str]) -> dict:
    return {
        "name": f"Scope Test {uuid.uuid4().hex[:6]}",
        "target_type": "domain",
        "value": value,
        "environment": "lab",
        "authorization_ref": f"TEST-AUTH-{uuid.uuid4().hex[:8]}",
        "authorized_by": "Automated Test Operator",
        "authorization_expires": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
        "allowed_actions": actions,
        "notes": "Created by the automated test suite.",
    }


def test_target_creation_requires_admin_verification(
    client: TestClient,
    admin_headers: dict[str, str],
    analyst_headers: dict[str, str],
) -> None:
    value = f"scope-{uuid.uuid4().hex[:8]}.example.com"
    created = client.post(
        "/api/v1/targets",
        headers=analyst_headers,
        json=_target_payload(value, ["recon"]),
    )
    assert created.status_code == 201, created.text
    target = created.json()
    assert target["status"] == "pending"
    assert target["verified_by"] is None

    analyst_verify = client.post(
        f"/api/v1/targets/{target['id']}/verify",
        headers=analyst_headers,
        json={"allowed_actions": ["recon"]},
    )
    assert analyst_verify.status_code == 403

    verified = client.post(
        f"/api/v1/targets/{target['id']}/verify",
        headers=admin_headers,
        json={
            "allowed_actions": ["recon", "simulation"],
            "authorization_expires": (datetime.now(UTC) + timedelta(days=3)).isoformat(),
            "note": "Authorization evidence reviewed.",
        },
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "verified"
    assert verified.json()["verified_by"] == "admin@ares.example.com"
    assert verified.json()["allowed_actions"] == ["recon", "simulation"]

    detail = client.get(f"/api/v1/targets/{target['id']}", headers=analyst_headers)
    assert detail.status_code == 200
    assert detail.json()["status"] == "verified"


def test_rejected_target_cannot_be_used(
    client: TestClient,
    admin_headers: dict[str, str],
    analyst_headers: dict[str, str],
) -> None:
    value = f"rejected-{uuid.uuid4().hex[:8]}.example.com"
    created = client.post(
        "/api/v1/targets",
        headers=analyst_headers,
        json=_target_payload(value, ["recon"]),
    )
    assert created.status_code == 201
    target_id = created.json()["id"]

    rejected = client.post(
        f"/api/v1/targets/{target_id}/reject",
        headers=admin_headers,
        json={"reason": "Authorization evidence could not be validated."},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

    assessment = client.post(
        "/api/v1/assessments",
        headers=analyst_headers,
        json={
            "module": "recon",
            "target_id": target_id,
            "config": {"max_subdomains": 5},
            "start": False,
        },
    )
    assert assessment.status_code == 403
    assert assessment.json()["error"]["code"] == "target_not_authorized"


def test_module_action_must_be_in_target_allowlist(
    client: TestClient,
    admin_headers: dict[str, str],
    analyst_headers: dict[str, str],
    demo_targets: dict[str, dict],
) -> None:
    web_target = demo_targets["domain"]
    assert "network_scan" not in web_target["allowed_actions"]

    denied = client.post(
        "/api/v1/assessments",
        headers=analyst_headers,
        json={
            "module": "network",
            "target_id": web_target["id"],
            "config": {"ports": [80, 443], "max_hosts": 1},
            "start": False,
        },
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "target_not_authorized"

    allowed = client.post(
        "/api/v1/assessments",
        headers=analyst_headers,
        json={
            "module": "recon",
            "target_id": web_target["id"],
            "config": {"include_subdomains": False, "include_whois": False, "include_tls": False, "include_http": False},
            "start": False,
        },
    )
    assert allowed.status_code == 201, allowed.text
    assert allowed.json()["status"] == "draft"
    assert allowed.json()["module"] == "recon"

    denied_delete = client.delete(f"/api/v1/assessments/{allowed.json()['id']}", headers=analyst_headers)
    assert denied_delete.status_code == 403

    deleted = client.delete(f"/api/v1/assessments/{allowed.json()['id']}", headers=admin_headers)
    assert deleted.status_code == 204


def test_expired_authorization_is_denied(
    client: TestClient,
    admin_headers: dict[str, str],
    analyst_headers: dict[str, str],
) -> None:
    value = f"expired-{uuid.uuid4().hex[:8]}.example.com"
    payload = _target_payload(value, ["recon"])
    payload["authorization_expires"] = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    created = client.post("/api/v1/targets", headers=analyst_headers, json=payload)
    assert created.status_code == 201
    target_id = created.json()["id"]

    verified = client.post(
        f"/api/v1/targets/{target_id}/verify",
        headers=admin_headers,
        json={
            "allowed_actions": ["recon"],
            "authorization_expires": (datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
        },
    )
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified"

    denied = client.post(
        "/api/v1/assessments",
        headers=analyst_headers,
        json={"module": "recon", "target_id": target_id, "config": {}, "start": False},
    )
    assert denied.status_code == 403
    assert "expired" in denied.json()["error"]["message"].lower()


def test_assessment_config_is_validated_before_queueing(
    client: TestClient,
    analyst_headers: dict[str, str],
    demo_targets: dict[str, dict],
) -> None:
    target = demo_targets["cidr"]
    invalid = client.post(
        "/api/v1/assessments",
        headers=analyst_headers,
        json={
            "module": "network",
            "target_id": target["id"],
            "config": {"ports": [70000], "max_hosts": 9999},
            "start": False,
        },
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"

    password_route = client.post(
        "/api/v1/assessments",
        headers=analyst_headers,
        json={"module": "password", "target_id": target["id"], "config": {}, "start": False},
    )
    assert password_route.status_code == 400
    assert password_route.json()["error"]["code"] == "password_endpoint_required"


def test_analyst_cannot_verify_or_delete_targets(
    client: TestClient,
    admin_headers: dict[str, str],
    analyst_headers: dict[str, str],
) -> None:
    value = f"rbac-{uuid.uuid4().hex[:8]}.example.com"
    created = client.post(
        "/api/v1/targets",
        headers=analyst_headers,
        json=_target_payload(value, ["recon"]),
    )
    assert created.status_code == 201
    target_id = created.json()["id"]

    denied = client.delete(f"/api/v1/targets/{target_id}", headers=analyst_headers)
    assert denied.status_code == 403

    allowed = client.delete(f"/api/v1/targets/{target_id}", headers=admin_headers)
    assert allowed.status_code == 204
