from unittest.mock import patch

import pytest

from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.services.crypto_policy.seeder import CURRENT_SEED_VERSION, seed_crypto_policies


def _rule_dict(rule_id: str) -> dict:
    return {
        "rule_id": rule_id,
        "name": rule_id,
        "description": "",
        "finding_type": "crypto_weak_algorithm",
        "default_severity": "HIGH",
        "source": "custom",
        "match_name_patterns": ["X"],
        "enabled": True,
    }


@pytest.mark.asyncio
async def test_revert_system_policy_creates_new_version(
    client,
    db,
    admin_auth_headers,
):
    await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("alpha")]},
        headers=admin_auth_headers,
    )
    await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("beta")]},
        headers=admin_auth_headers,
    )
    system = await CryptoPolicyRepository(db).get_system_policy()
    v2 = system.version
    entries = await PolicyAuditRepository(db).list(policy_scope="system", limit=10)
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/crypto-policies/system/audit"),
        ("GET", "/api/v1/crypto-policies/system/audit/1"),
        ("DELETE", "/api/v1/crypto-policies/system/audit?before=2020-01-01T00:00:00Z"),
    ],
)
async def test_the_system_audit_is_refused_to_a_non_admin(client, db, member_auth_headers, method, path):
    resp = await client.request(method, path, headers=member_auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"target_version": "abc"}, id="non-numeric-version"),
        pytest.param({"target_version": 1, "comment": "x" * 1001}, id="over-long-comment"),
        pytest.param({"target_version": 1, "targt_version": 2}, id="unknown-key"),
    ],
)
async def test_revert_answers_422_not_500(client, db, admin_auth_headers, body):
    """`int(target_raw)` and the audit entry's comment limit both raised below the route, where the
    catch-all handler turned them into a 500."""
    await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("alpha")]},
        headers=admin_auth_headers,
    )

    resp = await client.post("/api/v1/crypto-policies/system/revert", json=body, headers=admin_auth_headers)

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_revert_without_target_version_is_rejected(client, db, admin_auth_headers):
    resp = await client.post("/api/v1/crypto-policies/system/revert", json={}, headers=admin_auth_headers)

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_a_revert_names_the_admin_who_made_it(client, db, admin_auth_headers):
    """The policy page shows 'last edited by' from updated_by."""
    for rule_id in ("alpha", "beta"):
        await client.put(
            "/api/v1/crypto-policies/system", json={"rules": [_rule_dict(rule_id)]}, headers=admin_auth_headers
        )

    resp = await client.post(
        "/api/v1/crypto-policies/system/revert", json={"target_version": 1}, headers=admin_auth_headers
    )

    assert resp.status_code == 200, resp.text
    assert (resp.json()["version"], resp.json()["updated_by"]) == (3, "admin-user")
    stored = await CryptoPolicyRepository(db).get_system_policy()
    assert ([r.rule_id for r in stored.rules], stored.updated_by) == (["alpha"], "admin-user")


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_legacy_policy_last_changed_by_a_revert_keeps_its_rules_through_the_seed_bumps(
    client, db, admin_auth_headers
):
    """Reverts once stored no updated_by, so only the audit history records that a person chose these rules."""
    for rule_id in ("alpha", "beta"):
        await client.put(
            "/api/v1/crypto-policies/system", json={"rules": [_rule_dict(rule_id)]}, headers=admin_auth_headers
        )
    await client.post("/api/v1/crypto-policies/system/revert", json={"target_version": 1}, headers=admin_auth_headers)
    await db.crypto_policies.update_one(
        {"scope": "system"}, {"$set": {"updated_by": None}, "$unset": {"seed_version": ""}}
    )

    await seed_crypto_policies(db)
    with patch("app.services.crypto_policy.seeder.CURRENT_SEED_VERSION", CURRENT_SEED_VERSION + 1):
        await seed_crypto_policies(db)

    stored = await CryptoPolicyRepository(db).get_system_policy()
    assert (stored.rules[0].rule_id, stored.updated_by) == ("alpha", "admin-user")
    assert (stored.version, stored.seed_version) == (5, CURRENT_SEED_VERSION + 1)
