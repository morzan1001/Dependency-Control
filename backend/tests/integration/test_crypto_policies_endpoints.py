import pytest

from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule


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
async def test_get_system_policy_admin_only(client, db, admin_auth_headers, member_auth_headers):
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[]))
    resp = await client.get("/api/v1/crypto-policies/system", headers=admin_auth_headers)
    assert resp.status_code == 200
    resp2 = await client.get("/api/v1/crypto-policies/system", headers=member_auth_headers)
    assert resp2.status_code in (401, 403)


@pytest.mark.asyncio
async def test_put_system_policy_bumps_version(client, db, admin_auth_headers):
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[]))
    resp = await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("new-rule")]},
        headers=admin_auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["version"] == 2
    assert len(body["rules"]) == 1


@pytest.mark.asyncio
async def test_project_policy_roundtrip(client, db, owner_auth_headers_proj):
    # Seed a system policy so the resolver can merge project overrides into it
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[]))

    resp = await client.get("/api/v1/projects/p/crypto-policy", headers=owner_auth_headers_proj)
    assert resp.status_code == 200
    assert resp.json()["rules"] == []

    put = await client.put(
        "/api/v1/projects/p/crypto-policy",
        json={"rules": [_rule_dict("override-me")]},
        headers=owner_auth_headers_proj,
    )
    assert put.status_code == 200, put.text

    eff = await client.get(
        "/api/v1/projects/p/crypto-policy/effective",
        headers=owner_auth_headers_proj,
    )
    assert eff.status_code == 200
    rules = eff.json()["rules"]
    assert any(r["rule_id"] == "override-me" for r in rules)


@pytest.mark.asyncio
async def test_delete_project_policy(client, db, owner_auth_headers_proj):
    await CryptoPolicyRepository(db).upsert_project_policy(
        CryptoPolicy(
            scope="project",
            project_id="p",
            version=1,
            rules=[
                CryptoRule(
                    rule_id="r",
                    name="r",
                    description="",
                    finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
                    default_severity=Severity.HIGH,
                    source=CryptoPolicySource.CUSTOM,
                )
            ],
        )
    )
    resp = await client.delete(
        "/api/v1/projects/p/crypto-policy",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code in (200, 204)
    got = await CryptoPolicyRepository(db).get_project_policy("p")
    assert got is None


async def _seeded_system_policy(db) -> CryptoPolicyRepository:
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[CryptoRule.model_validate(_rule_dict("keep-me"))])
    )
    return repo


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"Rules": [_rule_dict("r1")]}, id="misspelled-rules-key"),
        pytest.param({"rulez": [_rule_dict("r1")]}, id="unknown-key"),
        pytest.param({}, id="empty-body"),
    ],
)
async def test_put_system_policy_rejects_bodies_that_carry_no_rules(client, db, admin_auth_headers, body):
    """A body whose rules never arrive used to return 200 and leave the policy empty, which
    disarms every crypto analyzer. It must not be possible to wipe the policy by accident."""
    repo = await _seeded_system_policy(db)

    resp = await client.put("/api/v1/crypto-policies/system", json=body, headers=admin_auth_headers)

    assert resp.status_code == 422
    stored = await repo.get_system_policy()
    assert stored is not None
    assert [r.rule_id for r in stored.rules] == ["keep-me"]
    assert stored.version == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"rules": [{"rule_id": 5, "n": "x"}]}, id="malformed-rule"),
        pytest.param({"rules": [_rule_dict("r1")], "comment": "x" * 1001}, id="over-long-comment"),
    ],
)
async def test_put_system_policy_answers_422_not_500(client, db, admin_auth_headers, body):
    """These raised ValidationError below the route, which the catch-all handler turned into a 500."""
    await _seeded_system_policy(db)

    resp = await client.put("/api/v1/crypto-policies/system", json=body, headers=admin_auth_headers)

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_put_system_policy_still_allows_an_explicit_empty_rule_set(client, db, admin_auth_headers):
    """Clearing the policy on purpose stays possible — only the accidental wipe is closed."""
    repo = await _seeded_system_policy(db)

    resp = await client.put("/api/v1/crypto-policies/system", json={"rules": []}, headers=admin_auth_headers)

    assert resp.status_code == 200
    stored = await repo.get_system_policy()
    assert stored is not None
    assert stored.rules == []
    assert stored.version == 2


@pytest.mark.asyncio
async def test_put_project_policy_is_refused_for_a_project_viewer(client, db, member_auth_headers):
    resp = await client.put(
        "/api/v1/projects/test-project-id/crypto-policy",
        json={"rules": [_rule_dict("viewer-wrote-this")]},
        headers=member_auth_headers,
    )

    assert resp.status_code == 403, resp.text
    assert await CryptoPolicyRepository(db).get_project_policy("test-project-id") is None


@pytest.mark.asyncio
async def test_delete_project_policy_is_refused_for_a_project_viewer(client, db, member_auth_headers):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_project_policy(
        CryptoPolicy(
            scope="project",
            project_id="test-project-id",
            version=1,
            rules=[CryptoRule.model_validate(_rule_dict("keep-me"))],
        )
    )

    resp = await client.delete(
        "/api/v1/projects/test-project-id/crypto-policy",
        headers=member_auth_headers,
    )

    assert resp.status_code == 403, resp.text
    stored = await repo.get_project_policy("test-project-id")
    assert stored is not None
    assert [r.rule_id for r in stored.rules] == ["keep-me"]


@pytest.mark.asyncio
async def test_put_project_policy_is_locked_out_while_the_system_enforces_a_global_policy(
    client,
    db,
    owner_auth_headers_proj,
):
    """The resolver discards project overrides in this mode, so accepting the write would store a
    policy that never takes effect."""
    await SystemSettingsRepository(db).update({"crypto_policy_mode": "global"})

    resp = await client.put(
        "/api/v1/projects/p/crypto-policy",
        json={"rules": [_rule_dict("override-me")]},
        headers=owner_auth_headers_proj,
    )

    assert resp.status_code == 403, resp.text
    assert await CryptoPolicyRepository(db).get_project_policy("p") is None


@pytest.mark.asyncio
async def test_put_project_policy_bumps_the_stored_version(client, db, owner_auth_headers_proj):
    """Policy audit entries and reverts address a revision by version, so two writes must not
    collapse onto one number."""
    first = await client.put(
        "/api/v1/projects/p/crypto-policy",
        json={"rules": [_rule_dict("r1")]},
        headers=owner_auth_headers_proj,
    )
    assert first.status_code == 200, first.text
    assert first.json()["version"] == 1

    second = await client.put(
        "/api/v1/projects/p/crypto-policy",
        json={"rules": [_rule_dict("r2")]},
        headers=owner_auth_headers_proj,
    )
    assert second.status_code == 200, second.text
    assert second.json()["version"] == 2

    stored = await CryptoPolicyRepository(db).get_project_policy("p")
    assert stored is not None
    assert stored.version == 2


@pytest.mark.asyncio
async def test_put_system_policy_refuses_a_misspelled_rule_key(client, db, admin_auth_headers):
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[]))

    resp = await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [{**_rule_dict("typo"), "match_name_pattern": ["md5"]}]},
        headers=admin_auth_headers,
    )

    assert resp.status_code == 422
    assert "match_name_pattern" in resp.text
    assert (await CryptoPolicyRepository(db).get_system_policy()).version == 1


@pytest.mark.asyncio
async def test_a_revert_refuses_a_snapshot_holding_a_rule_a_write_would_refuse(client, db, admin_auth_headers):
    from app.models.policy_audit_entry import PolicyAuditEntry
    from app.repositories.policy_audit_entry import PolicyAuditRepository
    from app.schemas.policy_audit import PolicyAuditAction

    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=2, rules=[]))
    unscoped = {**_rule_dict("fires-on-everything"), "match_name_patterns": []}
    await PolicyAuditRepository(db).create(
        PolicyAuditEntry(
            policy_scope="system",
            version=1,
            action=PolicyAuditAction.UPDATE,
            snapshot={"rules": [unscoped]},
            change_summary="",
        )
    )

    resp = await client.post(
        "/api/v1/crypto-policies/system/revert", json={"target_version": 1}, headers=admin_auth_headers
    )

    assert resp.status_code == 422
    assert resp.json()["detail"].startswith("Version 1 holds rules a write would refuse: rule 'fires-on-everything'")
    assert (await CryptoPolicyRepository(db).get_system_policy()).version == 2


@pytest.mark.asyncio
async def test_get_system_policy_answers_404_instead_of_seeding(client, db, admin_auth_headers):
    """Startup seeds the system policy; a read must not write a policy and a SEED audit entry."""
    resp = await client.get("/api/v1/crypto-policies/system", headers=admin_auth_headers)

    assert resp.status_code == 404
    assert await CryptoPolicyRepository(db).get_system_policy() is None
    assert await db.crypto_policy_history.count_documents({}) == 0


@pytest.mark.asyncio
async def test_deleting_an_absent_override_records_nothing(client, db, owner_auth_headers_proj):
    resp = await client.delete("/api/v1/projects/p/crypto-policy", headers=owner_auth_headers_proj)

    assert resp.status_code == 204
    assert await db.crypto_policy_history.count_documents({}) == 0


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_override_recreated_after_a_delete_continues_the_version_count(client, db, owner_auth_headers_proj):
    """A revert addresses a revision by version, so a recreated override must not reuse the deleted one's numbers."""
    from app.repositories.policy_audit_entry import PolicyAuditRepository

    path = "/api/v1/projects/p/crypto-policy"
    await client.put(path, json={"rules": [_rule_dict("first")]}, headers=owner_auth_headers_proj)
    await client.delete(path, headers=owner_auth_headers_proj)

    recreated = await client.put(path, json={"rules": [_rule_dict("second")]}, headers=owner_auth_headers_proj)

    assert recreated.json()["version"] == 3
    entries = await PolicyAuditRepository(db).list(policy_scope="project", project_id="p")
    assert [(e.version, e.action) for e in entries] == [(3, "create"), (2, "delete"), (1, "create")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        pytest.param("DELETE", "/api/v1/projects/p/crypto-policy", None, id="delete"),
        pytest.param("POST", "/api/v1/projects/p/crypto-policy/revert", {"target_version": 1}, id="revert"),
    ],
)
async def test_the_global_lock_refuses_every_write_to_an_override(
    client, db, owner_auth_headers_proj, method, path, body
):
    await client.put(
        "/api/v1/projects/p/crypto-policy", json={"rules": [_rule_dict("stored")]}, headers=owner_auth_headers_proj
    )
    await SystemSettingsRepository(db).update({"crypto_policy_mode": "global"})

    resp = await client.request(method, path, json=body, headers=owner_auth_headers_proj)

    assert resp.status_code == 403, resp.text
    stored = await CryptoPolicyRepository(db).get_project_policy("p")
    assert stored is not None
    assert (stored.version, [r.rule_id for r in stored.rules]) == (1, ["stored"])
    assert await db.crypto_policy_history.count_documents({}) == 1


@pytest.mark.asyncio
async def test_an_admin_save_keeps_the_seed_version_so_the_next_start_does_not_reseed(client, db, admin_auth_headers):
    from app.services.crypto_policy.seeder import CURRENT_SEED_VERSION, seed_crypto_policies

    await seed_crypto_policies(db)
    await client.put("/api/v1/crypto-policies/system", json={"rules": [_rule_dict("mine")]}, headers=admin_auth_headers)

    await seed_crypto_policies(db)

    stored = await CryptoPolicyRepository(db).get_system_policy()
    assert [r.rule_id for r in stored.rules] == ["mine"]
    assert (stored.seed_version, stored.updated_by) == (CURRENT_SEED_VERSION, "admin-user")
