import pytest

from app.repositories.policy_audit_entry import PolicyAuditRepository


def _rule_dict(rule_id: str) -> dict:
    return {
        "rule_id": rule_id, "name": rule_id, "description": "",
        "finding_type": "crypto_weak_algorithm",
        "default_severity": "HIGH",
        "source": "custom",
        "match_name_patterns": ["X"],
        "enabled": True,
    }


@pytest.mark.asyncio
async def test_put_system_policy_writes_audit_entry(
    client, db, admin_auth_headers,
):
    resp = await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("new-rule")], "comment": "Q2 audit"},
        headers=admin_auth_headers,
    )
    assert resp.status_code == 200
    version = resp.json()["version"]

    entries = await PolicyAuditRepository(db).list(
        policy_scope="system", limit=10,
    )
    assert any(e.version == version for e in entries)
    latest = entries[0]
    assert latest.version == version
    assert latest.comment == "Q2 audit"


@pytest.mark.asyncio
async def test_put_project_policy_writes_audit_entry(
    client, db, owner_auth_headers_proj,
):
    resp = await client.put(
        "/api/v1/projects/p/crypto-policy",
        json={"rules": [_rule_dict("proj-rule")], "comment": "override"},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200

    entries = await PolicyAuditRepository(db).list(
        policy_scope="project", project_id="p", limit=10,
    )
    assert len(entries) >= 1
    assert entries[0].project_id == "p"


@pytest.mark.asyncio
async def test_delete_project_policy_writes_audit_entry(
    client, db, owner_auth_headers_proj_p2,
):
    # Seed a project policy first
    await client.put(
        "/api/v1/projects/p2/crypto-policy",
        json={"rules": [_rule_dict("x")]},
        headers=owner_auth_headers_proj_p2,
    )
    # Delete it
    resp = await client.delete(
        "/api/v1/projects/p2/crypto-policy",
        headers=owner_auth_headers_proj_p2,
    )
    assert resp.status_code in (200, 204)

    entries = await PolicyAuditRepository(db).list(
        policy_scope="project", project_id="p2", limit=10,
    )
    actions = [
        (e.action.value if hasattr(e.action, "value") else e.action)
        for e in entries
    ]
    assert "delete" in actions
