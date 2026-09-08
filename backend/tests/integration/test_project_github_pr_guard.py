"""PR decoration may only be enabled on a GitHub instance that can actually post."""

import pytest

# Shape of a github_instances document as written by VcsInstanceRepository.create.
_INSTANCE_BASE = {
    "_id": "gh-1",
    "name": "GitHub.com",
    "url": "https://token.actions.githubusercontent.com",
    "github_url": "https://github.com",
    "oidc_audience": "dependency-control",
    "is_active": True,
    "auto_create_projects": True,
    "created_by": "admin-user",
}


async def _link_github(db, *, access_token, instance_id="gh-1"):
    await db.github_instances.insert_one({**_INSTANCE_BASE, "access_token": access_token})
    await db.projects.update_one(
        {"_id": "p"},
        {
            "$set": {
                "github_instance_id": instance_id,
                "github_repository_id": "42",
                "github_repository_path": "acme/widget",
            }
        },
    )


@pytest.mark.asyncio
async def test_enabling_is_refused_when_the_instance_has_no_token(client, db, owner_auth_headers_proj):
    await _link_github(db, access_token=None)

    resp = await client.put(
        "/api/v1/projects/p", json={"github_pr_comments_enabled": True}, headers=owner_auth_headers_proj
    )

    assert resp.status_code == 400, resp.text
    assert "no access token" in resp.json()["detail"]
    assert (await db.projects.find_one({"_id": "p"})).get("github_pr_comments_enabled") is not True


@pytest.mark.asyncio
async def test_enabling_is_allowed_and_persisted_when_the_instance_has_a_token(client, db, owner_auth_headers_proj):
    await _link_github(db, access_token="ghp-real")

    resp = await client.put(
        "/api/v1/projects/p", json={"github_pr_comments_enabled": True}, headers=owner_auth_headers_proj
    )

    assert resp.status_code == 200, resp.text
    assert (await db.projects.find_one({"_id": "p"}))["github_pr_comments_enabled"] is True


@pytest.mark.asyncio
async def test_disabling_is_never_refused(client, db, owner_auth_headers_proj):
    await _link_github(db, access_token=None)

    resp = await client.put(
        "/api/v1/projects/p", json={"github_pr_comments_enabled": False}, headers=owner_auth_headers_proj
    )

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_unlinked_project_is_not_blocked(client, db, owner_auth_headers_proj):
    """Project "p" has no github_instance_id, so no instance's token can be missing."""
    await db.github_instances.insert_one({**_INSTANCE_BASE, "access_token": None})

    resp = await client.put(
        "/api/v1/projects/p", json={"github_pr_comments_enabled": True}, headers=owner_auth_headers_proj
    )

    assert resp.status_code == 200, resp.text
    assert (await db.projects.find_one({"_id": "p"}))["github_pr_comments_enabled"] is True


@pytest.mark.asyncio
async def test_dangling_instance_reference_is_not_blocked(client, db, owner_auth_headers_proj):
    """A link to a deleted instance is a data problem for decoration to log, not a reason to refuse the toggle."""
    await _link_github(db, access_token=None, instance_id="gh-deleted")

    resp = await client.put(
        "/api/v1/projects/p", json={"github_pr_comments_enabled": True}, headers=owner_auth_headers_proj
    )

    assert resp.status_code == 200, resp.text
    assert (await db.projects.find_one({"_id": "p"}))["github_pr_comments_enabled"] is True
