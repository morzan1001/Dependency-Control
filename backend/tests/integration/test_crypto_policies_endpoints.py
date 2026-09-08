import pytest

from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_policy import CryptoPolicyRepository
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
