"""A chat finding link opens the finding: FindingsTable searches the findings API with the link's value."""

import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.auth import make_admin
from tests.helpers.databases import DATABASES

pytestmark = pytest.mark.asyncio

_PROJECT = "p-deeplink"
_SCAN = "scan-deeplink"
_COMPONENT = "github.com/docker/docker"
_VERSION = "v20.10.7+incompatible"
_FINDING_ID = f"{_COMPONENT}:{_VERSION}"


async def _seed(db) -> None:
    await db.projects.insert_one(
        {"_id": _PROJECT, "name": "deeplink-project", "default_branch": "main", "latest_scan_id": _SCAN}
    )
    await db.scans.insert_one(
        {
            "_id": _SCAN,
            "project_id": _PROJECT,
            "branch": "main",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.findings.insert_one(
        {
            "_id": str(uuid.uuid4()),
            "finding_id": _FINDING_ID,
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "type": "vulnerability",
            "severity": "HIGH",
            "component": _COMPONENT,
            "version": _VERSION,
            "description": "",
            "waived": False,
            "details": {"vulnerabilities": [{"id": "CVE-2021-41091", "severity": "HIGH"}]},
        }
    )


@pytest.mark.parametrize("database", DATABASES)
async def test_a_chat_finding_link_resolves_through_the_findings_search(db, database, client, admin_auth_headers):
    await _seed(db)

    result = await ChatToolRegistry().execute_tool("search_findings", {"query": "docker"}, make_admin(), db)
    link = parse_qs(urlsplit(result["findings"][0]["url"]).query)["finding"][0]
    resp = await client.get(
        f"/api/v1/projects/scans/{_SCAN}/findings", params={"search": link, "limit": 200}, headers=admin_auth_headers
    )

    assert [f["id"] for f in resp.json()["items"] if f["id"] == link] == [_FINDING_ID]
