"""The settings form's payload must arrive intact.

`ProjectUpdate` declared none of the re-scan or GitLab-link fields the form sends, so those five
keys were dropped by the schema: toggling per-project re-scanning returned 200 and changed nothing,
and two consumers read keys that could never be present.
"""

import pytest

# Exactly what ProjectSettings.tsx handleUpdate() sends.
_FORM_PAYLOAD = {
    "name": "project-p",
    "team_id": None,
    "retention_days": 30,
    "retention_action": "archive",
    "active_analyzers": ["trivy"],
    "default_branch": "main",
    "rescan_enabled": True,
    "rescan_interval": 12,
    "gitlab_mr_comments_enabled": True,
    "gitlab_instance_id": "gl-1",
    "gitlab_project_id": 4242,
    "gitlab_project_path": "group/sub/project",
}


@pytest.mark.asyncio
async def test_every_field_the_form_sends_is_persisted(client, db, owner_auth_headers_proj):
    resp = await client.put("/api/v1/projects/p", json=_FORM_PAYLOAD, headers=owner_auth_headers_proj)
    assert resp.status_code == 200, resp.text

    stored = await db.projects.find_one({"_id": "p"})
    missing = {k: v for k, v in _FORM_PAYLOAD.items() if k != "team_id" and stored.get(k) != v}
    assert not missing, f"dropped or altered on the way to the database: {missing}"


@pytest.mark.asyncio
async def test_toggling_rescan_off_takes_effect(client, db, owner_auth_headers_proj):
    """The scheduler reads Project.rescan_enabled, so a 200 that changes nothing is a silent no-op."""
    await client.put(
        "/api/v1/projects/p", json={"rescan_enabled": True, "rescan_interval": 6}, headers=owner_auth_headers_proj
    )
    assert (await db.projects.find_one({"_id": "p"}))["rescan_enabled"] is True

    resp = await client.put("/api/v1/projects/p", json={"rescan_enabled": False}, headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    stored = await db.projects.find_one({"_id": "p"})
    assert stored["rescan_enabled"] is False
    assert stored["rescan_interval"] == 6
