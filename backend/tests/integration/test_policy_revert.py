import pytest

from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.policy_audit_entry import PolicyAuditRepository


def _rule_dict(rule_id: str) -> dict:
    return {
        "rule_id": rule_id,
        "name": rule_id,
        "description": "",
        "finding_type": "crypto_weak_algorithm",
        "default_severity": "HIGH",
        "source": "custom",
        "enabled": True,
    }


@pytest.mark.asyncio
async def test_revert_system_policy_creates_new_version(
    client,
    db,
    admin_auth_headers,
):
    # v1: rules=[alpha]
    await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("alpha")]},
        headers=admin_auth_headers,
    )
    # v2: rules=[beta]
    await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("beta")]},
        headers=admin_auth_headers,
    )
    system = await CryptoPolicyRepository(db).get_system_policy()
    v2 = system.version
    entries = await PolicyAuditRepository(db).list(policy_scope="system", limit=10)
    # Find the version with the "alpha" rule
    target_version = next(
        e.version for e in entries if any(r.get("rule_id") == "alpha" for r in e.snapshot.get("rules", []))
    )

    resp = await client.post(
        "/api/v1/crypto-policies/system/revert",
        json={"target_version": target_version, "comment": "rollback"},
        headers=admin_auth_headers,
    )
    assert resp.status_code == 200

    current = await CryptoPolicyRepository(db).get_system_policy()
    assert current.version > v2
    assert any(r.rule_id == "alpha" for r in current.rules)
    assert not any(r.rule_id == "beta" for r in current.rules)

    entries = await PolicyAuditRepository(db).list(policy_scope="system", limit=10)
    latest = entries[0]
    action = latest.action.value if hasattr(latest.action, "value") else latest.action
    assert action == "revert"
    assert latest.reverted_from_version == target_version


@pytest.mark.asyncio
async def test_list_audit_entries_endpoint(
    client,
    db,
    admin_auth_headers,
):
    await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("x")]},
        headers=admin_auth_headers,
    )
    resp = await client.get(
        "/api/v1/crypto-policies/system/audit?limit=20",
        headers=admin_auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "entries" in body
    assert len(body["entries"]) >= 1


@pytest.mark.asyncio
async def test_get_single_audit_entry(
    client,
    db,
    admin_auth_headers,
):
    await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("y")]},
        headers=admin_auth_headers,
    )
    system_policy = await CryptoPolicyRepository(db).get_system_policy()
    target_version = system_policy.version
    resp = await client.get(
        f"/api/v1/crypto-policies/system/audit/{target_version}",
        headers=admin_auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == target_version
    assert "snapshot" in body


@pytest.mark.asyncio
async def test_revert_denied_for_non_admin(
    client,
    db,
    member_auth_headers,
):
    resp = await client.post(
        "/api/v1/crypto-policies/system/revert",
        json={"target_version": 1, "comment": "no"},
        headers=member_auth_headers,
    )
    assert resp.status_code in (401, 403)
