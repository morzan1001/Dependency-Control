"""compare_scans answers every scan-delta category through the REST dispatcher, pageable and filterable by change."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.crypto_asset import CryptoAsset
from app.models.finding import Finding, FindingType, Severity
from app.models.project import Scan
from app.models.user import User
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.scans import ScanRepository
from app.schemas.cbom import CryptoAssetType
from app.services.analysis.engine import _prepare_finding_records
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN

pytestmark = pytest.mark.asyncio

_PROJECT = "p1"
_FROM = "s-from"
_TO = "s-to"
_NOW = datetime.now(timezone.utc)

_LOG4J = Finding(
    id="log4j-core:2.14.1",
    type=FindingType.VULNERABILITY,
    severity=Severity.CRITICAL,
    component="log4j-core",
    version="2.14.1",
    description="remote code execution",
    scanners=["trivy"],
)
_LODASH = Finding(
    id="lodash:4.17.20",
    type=FindingType.VULNERABILITY,
    severity=Severity.HIGH,
    component="lodash",
    version="4.17.20",
    description="prototype pollution",
    scanners=["trivy"],
)


async def _build(db, scan_id: str, created_at: datetime, finding: Finding, algorithm: str, project_id=_PROJECT):
    await ScanRepository(db).create(
        Scan(id=scan_id, project_id=project_id, branch="main", status=SCAN_STATUS_COMPLETED, created_at=created_at)
    )
    records, _ = _prepare_finding_records([finding], scan_id, project_id, created_at)
    await db.findings.insert_many(records)
    asset = CryptoAsset(
        project_id=project_id, scan_id=scan_id, bom_ref=algorithm, name=algorithm, asset_type=CryptoAssetType.ALGORITHM
    )
    await CryptoAssetRepository(db).bulk_upsert(project_id, scan_id, [asset])


@pytest_asyncio.fixture
async def seeded(db):
    """Upgrading log4j away and pulling lodash in, while the code moves from MD5 to SHA-256."""
    await db.projects.insert_one({"_id": _PROJECT, "name": "test-project", "team_id": None})
    await _build(db, _FROM, _NOW - timedelta(days=1), _LOG4J, "MD5")
    await _build(db, _TO, _NOW, _LODASH, "SHA-256")
    return db


async def _compare(db, **args) -> dict:
    admin = User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))
    return await ChatToolRegistry().execute_tool(
        "compare_scans", {"project_id": _PROJECT, "from_scan_id": _FROM, "to_scan_id": _TO, **args}, admin, db
    )


async def test_the_resolved_findings_are_asked_for_by_change(seeded):
    result = await _compare(seeded, change="removed")

    assert [(i["change"], i["finding_id"]) for i in result["items"]] == [("removed", _LOG4J.id)]
    assert (result["totals"]["added"], result["totals"]["removed"]) == (1, 1)


async def test_a_later_page_reaches_the_items_after_the_added_ones(seeded):
    result = await _compare(seeded, page_size=1, page=2)

    assert [(i["change"], i["finding_id"]) for i in result["items"]] == [("removed", _LOG4J.id)]


async def test_a_lone_severity_filters_the_findings(seeded):
    result = await _compare(seeded, severity="critical")

    assert [i["finding_id"] for i in result["items"]] == [_LOG4J.id]


async def test_the_crypto_category_compares_the_cbom(seeded):
    result = await _compare(seeded, category="crypto")

    assert result["category"] == "crypto"
    assert {(i["change"], i["name"]) for i in result["items"]} == {("removed", "MD5"), ("added", "SHA-256")}


async def test_a_page_larger_than_the_answer_budget_is_held_to_it(seeded):
    result = await _compare(seeded, page_size=200)

    assert result["page_size"] == 25
    assert result["_limit_clamped"] is True


async def test_the_dispatchers_refusal_is_the_tool_error(seeded):
    result = await _compare(seeded, category="crypto", severity="critical")

    assert result == {"error": "severity and finding_type are only valid with category=findings"}


async def test_one_scan_named_as_both_sides_is_refused(seeded):
    result = await _compare(seeded, from_scan_id=_TO)

    assert result == {"error": "from_scan_id and to_scan_id must differ"}


async def test_a_scan_of_another_project_is_refused(seeded):
    await _build(seeded, "s-foreign", _NOW, _LODASH, "RC4", project_id="p2")

    result = await _compare(seeded, from_scan_id="s-foreign")

    assert result == {"error": "Scan not found in this project"}


async def test_a_lone_to_scan_of_another_project_is_refused_as_foreign(seeded):
    await _build(seeded, "s-foreign", _NOW, _LODASH, "RC4", project_id="p2")

    result = await _compare(seeded, from_scan_id=None, to_scan_id="s-foreign")

    assert result == {"error": "Scan not found in this project"}


async def test_an_unknown_project_is_refused(seeded):
    result = await _compare(seeded, project_id="missing")

    assert result == {"error": "Project not found or access denied"}
