"""A callgraph is stored as one document: an upload at the entry cap fits, one too large for it is refused with 413."""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import CALLGRAPH_MAX_ENTRIES
from app.models.project import Project

_PROJECT_ID = "test-project-id"
_DEPENDENCIES_PER_FILE = 10


def _madge(files: int, path_length: int) -> dict[str, list[str]]:
    """madge `--json --include-npm` output in which every dependency is a package no other file of it imports."""
    return {
        f"src/features/f{i}/".ljust(path_length - 4, "x") + ".tsx": [
            f"../node_modules/pkg-{(i * _DEPENDENCIES_PER_FILE + j) % 2000}/index.js"
            for j in range(_DEPENDENCIES_PER_FILE)
        ]
        for i in range(files)
    }


async def _upload(client, data: dict[str, list[str]]):
    with patch(
        "app.api.deps.get_project_for_ingest",
        new_callable=AsyncMock,
        return_value=Project(id=_PROJECT_ID, name="test-project"),
    ):
        return await client.post(
            f"/api/v1/projects/{_PROJECT_ID}/callgraph",
            json={"format": "madge", "pipeline_id": 1, "commit_hash": "e" * 40, "data": data},
            headers={"Job-Token": "gitlab.oidc.token"},
        )


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_upload_at_the_entry_cap_with_100_character_paths_is_stored(client, db):
    resp = await _upload(client, _madge(CALLGRAPH_MAX_ENTRIES // _DEPENDENCIES_PER_FILE, 100))

    assert resp.status_code == 200, resp.text
    assert resp.json()["imports_parsed"] == CALLGRAPH_MAX_ENTRIES
    assert await db.callgraphs.count_documents({}) == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_callgraph_too_large_for_one_document_is_refused_with_413(client, db):
    resp = await _upload(client, _madge(2000, 1000))

    assert resp.status_code == 413, resp.text
    assert await db.callgraphs.count_documents({}) == 0
