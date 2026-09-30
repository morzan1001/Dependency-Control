"""PUT /api/v1/projects/{id} records a license-policy audit entry when the effective license policy changes."""

import pytest

from app.repositories.policy_audit_entry import PolicyAuditRepository


def _license_settings(**entry):
    return {"analyzer_settings": {"license_compliance": entry}}


async def _license_entries(db):
    return await PolicyAuditRepository(db).list(policy_scope="project", project_id="p", policy_type="license", limit=10)


@pytest.mark.asyncio
async def test_project_update_records_license_policy_change(client, db, owner_auth_headers_proj):
    resp = await client.put(
        "/api/v1/projects/p",
        json=_license_settings(distribution_model="internal_only"),
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text

    [first] = await _license_entries(db)
    assert (first.version, first.action, first.change_summary) == (
        1,
        "create",
        "distribution_model: distributed -> internal_only",
    )

    resp = await client.put(
        "/api/v1/projects/p",
        json=_license_settings(distribution_model="internal_only", allow_strong_copyleft=True),
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200

    latest, _ = await _license_entries(db)
    assert (latest.version, latest.action, latest.change_summary) == (
        2,
        "update",
        "allow_strong_copyleft: False -> True",
    )


@pytest.mark.asyncio
async def test_restating_the_default_policy_creates_no_audit_entry(client, db, owner_auth_headers_proj):
    """The scan grades exactly as before, so there is nothing to audit."""
    resp = await client.put(
        "/api/v1/projects/p",
        json=_license_settings(distribution_model="distributed", allow_strong_copyleft=False),
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200

    assert await _license_entries(db) == []


@pytest.mark.asyncio
async def test_project_update_without_license_change_creates_no_audit_entry(client, db, owner_auth_headers_proj):
    resp = await client.put(
        "/api/v1/projects/p",
        json={"retention_days": 60},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200

    assert await _license_entries(db) == []


@pytest.mark.asyncio
async def test_license_policy_audit_list_endpoint(client, db, owner_auth_headers_proj):
    await client.put(
        "/api/v1/projects/p",
        json=_license_settings(distribution_model="internal_only"),
        headers=owner_auth_headers_proj,
    )
    resp = await client.get(
        "/api/v1/projects/p/license-policy/audit",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "entries" in body
    assert len(body["entries"]) == 1
    assert body["entries"][0]["policy_type"] == "license"
    assert body["entries"][0]["version"] == 1


@pytest.mark.asyncio
async def test_license_policy_audit_get_by_version_endpoint(client, db, owner_auth_headers_proj):
    await client.put(
        "/api/v1/projects/p",
        json=_license_settings(distribution_model="internal_only"),
        headers=owner_auth_headers_proj,
    )
    resp = await client.get(
        "/api/v1/projects/p/license-policy/audit/1",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["policy_type"] == "license"
    assert body["version"] == 1


@pytest.mark.asyncio
async def test_license_policy_audit_404_on_unknown_version(client, db, owner_auth_headers_proj):
    resp = await client.get(
        "/api/v1/projects/p/license-policy/audit/99",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_license_policy_entries_isolated_from_crypto(client, db, owner_auth_headers_proj):
    resp = await client.put(
        "/api/v1/projects/p",
        json=_license_settings(distribution_model="internal_only", deployment_model="cli_batch"),
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200

    repo = PolicyAuditRepository(db)
    license_entries = await repo.list(policy_scope="project", project_id="p", policy_type="license", limit=10)
    crypto_entries = await repo.list(policy_scope="project", project_id="p", policy_type="crypto", limit=10)
    assert len(license_entries) == 1
    assert crypto_entries == []


@pytest.mark.asyncio
async def test_a_license_change_after_a_prune_takes_a_fresh_version(client, db, owner_auth_headers_proj):
    """Counting the surviving entries handed out a number an existing entry already holds."""
    for model in ("internal_only", "distributed", "internal_only"):
        resp = await client.put(
            "/api/v1/projects/p", json=_license_settings(distribution_model=model), headers=owner_auth_headers_proj
        )
        assert resp.status_code == 200, resp.text
    await db.crypto_policy_history.delete_one({"policy_type": "license", "version": 1})

    await client.put(
        "/api/v1/projects/p", json=_license_settings(distribution_model="distributed"), headers=owner_auth_headers_proj
    )

    assert [e.version for e in await _license_entries(db)] == [4, 3, 2]
