"""Integration test: PUT /api/v1/projects/{id} records a license-policy
audit entry when license_policy or analyzer_settings.license_compliance
changes."""

import pytest

from app.repositories.policy_audit_entry import PolicyAuditRepository


@pytest.mark.asyncio
async def test_project_update_records_license_policy_change(client, db, owner_auth_headers_proj):
    # Initial update sets license policy — counts as CREATE.
    resp = await client.put(
        "/api/v1/projects/p",
        json={
            "license_policy": {
                "distribution_model": "distributed",
                "deployment_model": "network_facing",
                "library_usage": "mixed",
                "allow_strong_copyleft": False,
                "allow_network_copyleft": False,
            }
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text

    entries = await PolicyAuditRepository(db).list(
        policy_scope="project", project_id="p", policy_type="license", limit=10
    )
    assert len(entries) == 1, f"expected 1 entry, got {len(entries)}"
    first = entries[0]
    assert first.policy_type == "license"
    assert first.version == 1
    assert "Initial license policy" in first.change_summary

    # Second update flips allow_strong_copyleft — counts as UPDATE.
    resp = await client.put(
        "/api/v1/projects/p",
        json={
            "license_policy": {
                "distribution_model": "distributed",
                "deployment_model": "network_facing",
                "library_usage": "mixed",
                "allow_strong_copyleft": True,
                "allow_network_copyleft": False,
            }
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200

    entries = await PolicyAuditRepository(db).list(
        policy_scope="project", project_id="p", policy_type="license", limit=10
    )
    assert len(entries) == 2
    latest = entries[0]  # sorted desc
    assert latest.version == 2
    assert "allow_strong_copyleft: False -> True" in latest.change_summary


@pytest.mark.asyncio
async def test_project_update_without_license_change_creates_no_audit_entry(client, db, owner_auth_headers_proj):
    # Update a non-license field — audit repo should be unchanged.
    resp = await client.put(
        "/api/v1/projects/p",
        json={"retention_days": 60},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200

    entries = await PolicyAuditRepository(db).list(
        policy_scope="project", project_id="p", policy_type="license", limit=10
    )
    assert entries == []


@pytest.mark.asyncio
async def test_license_policy_audit_list_endpoint(client, db, owner_auth_headers_proj):
    """GET /projects/{id}/license-policy/audit returns the entries."""
    # Seed via project update
    await client.put(
        "/api/v1/projects/p",
        json={"license_policy": {"distribution_model": "distributed"}},
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
    """GET /projects/{id}/license-policy/audit/{version} returns one entry."""
    await client.put(
        "/api/v1/projects/p",
        json={"license_policy": {"distribution_model": "distributed"}},
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
    """A license-policy write must NOT appear in the crypto-policy audit
    timeline and vice versa."""
    resp = await client.put(
        "/api/v1/projects/p",
        json={
            "license_policy": {
                "distribution_model": "internal_only",
                "deployment_model": "cli_batch",
                "library_usage": "unmodified",
                "allow_strong_copyleft": False,
                "allow_network_copyleft": False,
            }
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200

    repo = PolicyAuditRepository(db)
    license_entries = await repo.list(policy_scope="project", project_id="p", policy_type="license", limit=10)
    crypto_entries = await repo.list(policy_scope="project", project_id="p", policy_type="crypto", limit=10)
    assert len(license_entries) == 1
    assert crypto_entries == []
