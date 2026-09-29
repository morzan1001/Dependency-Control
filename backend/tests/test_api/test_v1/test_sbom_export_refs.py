"""The SBOM export reads the stored GridFS references by the same key the analysis does."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.v1.endpoints.projects import export_project_sbom

_PROJECTS = "app.api.v1.endpoints.projects"
_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}


@pytest.mark.asyncio
async def test_a_reference_carrying_only_its_gridfs_id_exports():
    scan = SimpleNamespace(sbom_refs=[{"type": "gridfs_reference", "gridfs_id": "66f0c0ffee", "filename": "sbom.json"}])
    scan_repo = MagicMock()
    scan_repo.get_latest_active_scan = AsyncMock(return_value=scan)
    load = AsyncMock(return_value=_SBOM)
    with (
        patch(f"{_PROJECTS}.check_project_access", new=AsyncMock(return_value=SimpleNamespace(name="app"))),
        patch(f"{_PROJECTS}.ScanRepository", return_value=scan_repo),
        patch(f"{_PROJECTS}.load_from_gridfs", new=load),
    ):
        response = await export_project_sbom("p1", current_user=MagicMock(), db=MagicMock())

    assert response.status_code == 200
    assert json.loads(response.body) == _SBOM
    load.assert_awaited_once_with(load.await_args.args[0], "66f0c0ffee")
