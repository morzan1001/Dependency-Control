"""Every release list page is read off an index in RELEASES_LATEST_SORT order, with or without an environment."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints.releases import list_releases
from app.core.init_db import create_indexes
from app.models.user import User
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_USER = User(id="u", username="u", email="u@corp.com", permissions=[])
_T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize("environment", [None, "env-1"])
async def test_no_release_list_page_needs_an_in_memory_sort(db, environment):
    await create_indexes(db)
    await db.releases.insert_many(
        [
            {
                "_id": f"rel-{i:02d}",
                "project_id": "p",
                "environment": f"env-{i % 3}",
                "scan_id": f"scan-{i:02d}",
                "released_at": _T0 + timedelta(hours=i // 2),
            }
            for i in range(30)
        ]
    )

    with patch("app.api.v1.endpoints.releases.check_project_access", AsyncMock()):
        page, entries = await profiled(db, list_releases("p", _USER, db, skip=4, limit=4, environment=environment))

    assert len(page.items) == 4
    finds = [e for e in entries if e["ns"].endswith(".releases") and e["command"].get("find")]
    assert [bool(e.get("hasSortStage")) for e in finds] == [False]
