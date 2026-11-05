from __future__ import annotations

from fastapi.testclient import TestClient


def test_password_audit_returns_only_safe_aggregates(
    client: TestClient,
    admin_headers: dict[str, str],
    demo_targets: dict[str, dict],
) -> None:
    target = demo_targets["local"]
    plaintext = "Correct-Horse-Battery-Staple-42!"
    md5_password = "5f4dcc3b5aa765d61d8327deb882cf99"
    request = {
        "target_id": target["id"],
        "policy": {
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digit": True,
            "require_symbol": True,
            "max_reuse": 5,
            "lockout_after": 5,
            "lockout_minutes": 15,
            "mfa_required": True,
        },
        "test_passwords": [plaintext, "password"],
        "hashes": [md5_password],
        "hash_algorithm": "auto",
        "wordlist": ["password", "welcome", "letmein"],
    }

    response = client.post("/api/v1/tools/password-audit", headers=admin_headers, json=request)
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["assessment"]["module"] == "password"
    assert payload["assessment"]["status"] == "completed"
    assert len(payload["strength"]) == 2
    assert payload["hash_audit"]["hashes_audited"] == 1
    assert payload["hash_audit"]["match_count"] == 1
    assert payload["hash_audit"]["plaintext_returned"] is False
    assert isinstance(payload["policy_findings"], list)

    serialized = response.text
    assert plaintext not in serialized
    assert md5_password not in serialized

    detail = client.get(
        f"/api/v1/assessments/{payload['assessment']['id']}",
        headers=admin_headers,
    )
    assert detail.status_code == 200
    config = detail.json()["config"]
    assert config["test_password_count"] == 2
    assert config["hash_count"] == 1
    assert config["wordlist_count"] == 3
    assert "test_passwords" not in config
    assert "hashes" not in config
    assert "wordlist" not in config
    assert plaintext not in detail.text
    assert md5_password not in detail.text

    audit = client.get(
        "/api/v1/audit",
        headers=admin_headers,
        params={"action": "password.audit_completed", "limit": 20},
    )
    assert audit.status_code == 200
    assert audit.json()["total"] >= 1
    entry = audit.json()["items"][0]
    assert entry["details"]["plaintext_persisted"] is False
    assert entry["details"]["test_password_count"] == 2
    assert entry["details"]["hash_count"] == 1
    assert plaintext not in audit.text
    assert md5_password not in audit.text


def test_password_audit_validation_does_not_echo_secrets(
    client: TestClient,
    analyst_headers: dict[str, str],
    demo_targets: dict[str, dict],
) -> None:
    target = demo_targets["local"]
    secret = "A-Secret-That-Must-Not-Be-Echoed-2026!"
    response = client.post(
        "/api/v1/tools/password-audit",
        headers=analyst_headers,
        json={"target_id": target["id"], "test_passwords": [secret], "unexpected": secret},
    )
    assert response.status_code == 422
    assert secret not in response.text


def test_password_audit_requires_authorized_target(
    client: TestClient,
    analyst_headers: dict[str, str],
    demo_targets: dict[str, dict],
) -> None:
    wrong_target = demo_targets["domain"]
    response = client.post(
        "/api/v1/tools/password-audit",
        headers=analyst_headers,
        json={"target_id": wrong_target["id"], "test_passwords": ["some-password"]},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "target_not_authorized"
