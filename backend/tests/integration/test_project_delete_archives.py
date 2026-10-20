from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import ORPHAN_MIN_AGE_HOURS
from app.services import archive
from app.services.archive import reap_orphan_s3_objects

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_DELETED_PROJECT = "test-project-id"
_SURVIVING_PROJECT = "proj-kept"


def _archive(project_id: str, scan_id: str) -> dict:
    return {
        "_id": f"meta-{scan_id}",
        "project_id": project_id,
        "scan_id": scan_id,
        "s3_key": f"{project_id}/{scan_id}-1700000000.bundle",
        "s3_bucket": "archives",
        "archived_at": datetime.now(timezone.utc) - timedelta(days=30),
    }


async def test_project_delete_lets_the_reaper_remove_its_archive_bundles(client, db, admin_auth_headers, monkeypatch):
    await db.archive_metadata.insert_many(
        [_archive(_DELETED_PROJECT, "scan-archived"), _archive(_SURVIVING_PROJECT, "scan-kept")]
    )
    old_enough = datetime.now(timezone.utc) - timedelta(hours=ORPHAN_MIN_AGE_HOURS + 1)
    bundles = [{"Key": meta["s3_key"], "LastModified": old_enough} async for meta in db.archive_metadata.find()]
    reaped: list[str] = []

    async def list_objects(_prefix=""):
        yield bundles

    async def delete_object(key):
        reaped.append(key)

    monkeypatch.setattr(archive, "is_archive_enabled", lambda: True)
    monkeypatch.setattr(archive, "list_objects", list_objects)
    monkeypatch.setattr(archive, "delete_object", delete_object)

    resp = await client.delete(f"/api/v1/projects/{_DELETED_PROJECT}", headers=admin_auth_headers)
    assert resp.status_code == 204
    await reap_orphan_s3_objects(db)

    assert reaped == [f"{_DELETED_PROJECT}/scan-archived-1700000000.bundle"]
    assert await db.archive_metadata.distinct("project_id") == [_SURVIVING_PROJECT]
