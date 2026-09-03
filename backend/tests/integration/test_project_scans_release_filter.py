"""A manual rescan repeats the source's analyzer selection."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_A_DAY = timedelta(days=1)
_PROJECT = "test-project-id"

_RELEASE_SCAN = "rel"
_PLAIN_SCAN = "plain"

_BRANCH = "main"
_COMMIT_HASH = "a" * 40
_GRIDFS_ID = "g1"
_SCAN_STATUS = "completed"
_CBOM_SCAN_TYPE = "cbom"

_EDITOR_USERNAME = "editoruser"
_EDITOR_ROLE = "editor"

# The module-level worker_manager owns an asyncio.Queue bound to the import-time loop.
_WORKER_MANAGER = "app.api.v1.endpoints.projects.worker_manager"


@pytest_asyncio.fixture
async def editor_headers(client, db):
    """trigger_rescan needs role=editor; member_auth_headers only grants viewer."""
    from jose import jwt

    from app.core.config import settings
    from app.core.permissions import Permissions
    from app.models.project import ProjectMember

    # _fake_get_current_user derives current_user.id from the JWT "sub", so membership
    # must key off the username.
    member = ProjectMember(user_id=_EDITOR_USERNAME, role=_EDITOR_ROLE)
    await db.projects.update_one(
        {"_id": _PROJECT},
        {"$set": {"members": [member.model_dump(by_alias=True)]}},
        upsert=True,
    )

    payload = {"sub": _EDITOR_USERNAME, "permissions": [Permissions.PROJECT_READ]}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}


async def _seed(db) -> None:
    await db.scans.insert_one(
        {
            "_id": _RELEASE_SCAN,
            "project_id": _PROJECT,
            "branch": _BRANCH,
            "commit_hash": _COMMIT_HASH,
            "status": _SCAN_STATUS,
            "created_at": _NOW,
            "sbom_refs": [{"gridfs_id": _GRIDFS_ID}],
            "scan_type": _CBOM_SCAN_TYPE,
            "is_release": True,
            "last_rescanned_at": _NOW,
        }
    )
    await db.scans.insert_one(
        {
            "_id": _PLAIN_SCAN,
            "project_id": _PROJECT,
            "branch": _BRANCH,
            "status": _SCAN_STATUS,
            "created_at": _NOW - _A_DAY,
        }
    )


async def _rescan(client, headers, scan_id: str = _RELEASE_SCAN):
    with patch(_WORKER_MANAGER, new=AsyncMock()):
        return await client.post(f"/api/v1/projects/{_PROJECT}/scans/{scan_id}/rescan", headers=headers)


@pytest.mark.asyncio
async def test_a_manual_rescan_of_a_cbom_scan_stays_a_cbom_scan(client, db, editor_headers):
    """The engine gates the crypto analyzers on this field, so dropping it changes the analysis."""
    await _seed(db)

    resp = await _rescan(client, editor_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_rescan"] is True
    assert body["original_scan_id"] == _RELEASE_SCAN
    assert body["scan_type"] == _CBOM_SCAN_TYPE
