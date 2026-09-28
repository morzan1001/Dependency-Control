"""An advisory reaches the projects whose head scan carries a covered version of the package."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.core.permissions import Permissions
from tests.helpers.auth import bearer_headers

_NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)


def _dependency(project_id: str, name: str, version: str, purl: str | None, type_: str, **extra) -> dict:
    return {
        "_id": f"{project_id}:{name}:{version}:{purl}",
        "scan_id": f"head-{project_id}",
        "project_id": project_id,
        "name": name,
        "version": version,
        "purl": purl,
        "type": type_,
        **extra,
    }


_INVENTORY = {
    "py": [_dependency("py", "PyYAML", "5.1", "pkg:pypi/PyYAML@5.1", "pypi")],
    "zope": [_dependency("zope", "zope-interface", "5.0", "pkg:pypi/zope-interface@5.0", "pypi")],
    "java": [
        _dependency("java", "log4j-core", "2.12.0", "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.0", "maven"),
        _dependency("java", "core", "3.4.0", "pkg:maven/com.google.zxing/core@3.4.0", "maven"),
    ],
    "netty": [_dependency("netty", "netty-codec-http", "4.1.100.Final", None, "java-archive")],
    "js": [_dependency("js", "lodash", "4.17.15", "pkg:npm/lodash@4.17.15", "npm")],
    "scoped": [_dependency("scoped", "utils", "1.0.0", None, "npm", group="@acme")],
}


@pytest_asyncio.fixture
async def headers(db, client):
    for project_id, dependencies in _INVENTORY.items():
        admin = f"admin-{project_id}"
        await db.users.insert_one({"_id": admin, "username": admin, "email": f"{admin}@x.io", "is_active": True})
        await db.projects.insert_one(
            {
                "_id": project_id,
                "name": project_id,
                "default_branch": "main",
                "latest_scan_id": f"head-{project_id}",
                "members": [{"user_id": admin, "role": "admin"}],
            }
        )
        await db.scans.insert_many(
            [
                {
                    "_id": f"old-{project_id}",
                    "project_id": project_id,
                    "branch": "main",
                    "status": "completed",
                    "created_at": _NOW - timedelta(days=30),
                },
                {
                    "_id": f"head-{project_id}",
                    "project_id": project_id,
                    "branch": "main",
                    "status": "completed",
                    "created_at": _NOW,
                },
            ]
        )
        await db.dependencies.insert_many(dependencies)
    superseded = _dependency("js", "left-pad", "1.0.0", "pkg:npm/left-pad@1.0.0", "npm", scan_id="old-js")
    await db.dependencies.insert_one({**superseded, "_id": "old-left-pad"})
    return bearer_headers("broadcaster", [Permissions.NOTIFICATIONS_BROADCAST])


async def _affected(client, headers, *packages: dict) -> int:
    resp = await client.post(
        "/api/v1/notifications/broadcast",
        json={
            "type": "advisory",
            "target_type": "advisory",
            "packages": list(packages),
            "subject": "s",
            "message": "m",
            "dry_run": True,
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["project_count"]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_pip_typed_advisory_reaches_a_differently_spelled_pypi_package(client, headers):
    assert await _affected(client, headers, {"name": "pyyaml", "version": "5.3", "type": "pip"}) == 1


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["zope.interface", "Zope_Interface"])
async def test_a_pypi_rule_folds_every_separator(client, headers, name):
    assert await _affected(client, headers, {"name": name, "version": "5.1", "type": "pypi"}) == 1


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_one_typed_package_does_not_hide_the_untyped_ones(client, headers):
    assert await _affected(client, headers, {"name": "lodash", "type": "npm"}, {"name": "log4j-core"}) == 2


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_every_rule_for_a_package_is_checked(client, headers):
    rules = [{"name": "log4j-core", "version": "2.3.1"}, {"name": "log4j-core", "version": "2.12.1"}]
    assert await _affected(client, headers, *rules) == 1


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_unversioned_rule_after_a_versioned_one_still_covers(client, headers):
    rules = [{"name": "log4j-core", "version": "2.3.1"}, {"name": "log4j-core"}]
    assert await _affected(client, headers, *rules) == 1


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_group_qualified_rule_skips_other_groups_artifacts(client, headers):
    assert await _affected(client, headers, {"name": "org.eclipse.jdt:core"}) == 0
    assert await _affected(client, headers, {"name": "com.google.zxing:core", "type": "maven"}) == 1


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_scoped_rule_reads_a_purl_less_row_by_its_group(client, headers):
    assert await _affected(client, headers, {"name": "@acme/utils", "type": "npm"}) == 1
    assert await _affected(client, headers, {"name": "@other/utils", "type": "npm"}) == 0


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_maven_final_release_above_the_bound_is_not_affected(client, headers):
    assert await _affected(client, headers, {"name": "netty-codec-http", "version": "4.1.99", "type": "maven"}) == 0
    assert await _affected(client, headers, {"name": "netty-codec-http", "version": "4.1.100", "type": "maven"}) == 1


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_superseded_scan_is_neither_suggested_nor_notified(client, headers):
    resp = await client.get("/api/v1/notifications/packages/suggest", params={"q": "pad"}, headers=headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["names"] == []
    assert await _affected(client, headers, {"name": "left-pad"}) == 0


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_wildcard_bound_is_rejected(client, headers):
    resp = await client.post(
        "/api/v1/notifications/broadcast",
        json={
            "type": "advisory",
            "target_type": "advisory",
            "packages": [{"name": "log4j-core", "version": "2.14.x"}],
            "subject": "s",
            "message": "m",
            "dry_run": True,
        },
        headers=headers,
    )

    assert resp.status_code == 422
