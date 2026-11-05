from __future__ import annotations

import time

from fastapi.testclient import TestClient


def test_queued_tabletop_assessment_completes(
    client: TestClient,
    analyst_headers: dict[str, str],
    demo_targets: dict[str, dict],
) -> None:
    target = demo_targets["domain"]
    created = client.post(
        "/api/v1/assessments",
        headers=analyst_headers,
        json={
            "name": "Queue Test · Tabletop",
            "module": "red_team",
            "target_id": target["id"],
            "config": {
                "scenario": "discovery",
                "technique_ids": ["T1046", "T1087"],
                "objective": "Automated queue verification only.",
            },
            "start": True,
        },
    )
    assert created.status_code == 201, created.text
    assessment_id = created.json()["id"]
    assert created.json()["status"] == "queued"

    deadline = time.monotonic() + 20
    assessment = created.json()
    while time.monotonic() < deadline:
        detail = client.get(f"/api/v1/assessments/{assessment_id}", headers=analyst_headers)
        assert detail.status_code == 200
        assessment = detail.json()
        if assessment["status"] not in {"queued", "running", "draft"}:
            break
        time.sleep(0.2)

    assert assessment["status"] == "completed", assessment
    assert assessment["progress"] == 100
    assert assessment["finished_at"] is not None
    assert assessment["summary"]
    assert assessment["summary"]["evidence"][0]["executed"] is False
    assert "no malware" in assessment["summary"]["notice"].lower()

    findings = client.get(
        "/api/v1/findings",
        headers=analyst_headers,
        params={"assessment_id": assessment_id},
    )
    assert findings.status_code == 200
    assert findings.json()["total"] >= 1

    queued = client.post(f"/api/v1/assessments/{assessment_id}/run", headers=analyst_headers)
    assert queued.status_code == 200
    assert queued.json()["status"] == "queued"
