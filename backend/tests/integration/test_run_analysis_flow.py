"""run_analysis on a FakeDatabase: analyzer set, GitHub token, final status and what reaches notifications."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.project import Scan
from app.models.stats import Stats
from app.services.analysis import engine

_PROJECT_ID = "notify-project"
_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


async def _seed_scan(db) -> str:
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=[], status="processing")
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    return scan.id


@pytest.fixture(autouse=True)
def _no_gridfs(monkeypatch):
    monkeypatch.setattr(engine, "primary_gridfs_bucket", lambda _db: None)


@pytest.fixture
def notified(monkeypatch) -> list[Stats]:
    sent: list[Stats] = []

    async def _capture(project_id, scan_id, scan_doc, stats, findings, results_summary, db):
        sent.append(stats)

    monkeypatch.setattr(engine, "_send_integrations_and_notifications", _capture)
    return sent


def _waivers_active(monkeypatch, active: bool) -> None:
    async def _has_active_waivers(project_id, db):
        return active

    monkeypatch.setattr(engine, "_project_has_active_waivers", _has_active_waivers)


def _recalc_returns(monkeypatch, result: Stats | None) -> list[str]:
    calls: list[str] = []

    async def _recalculate(project_id, db):
        calls.append(project_id)
        return result

    monkeypatch.setattr("app.services.stats.recalculate_project_stats", _recalculate)
    return calls


@pytest.mark.asyncio
async def test_active_waivers_route_the_recalculated_stats_to_notifications(db, notified, monkeypatch):
    recalculated = Stats(critical=7)
    _waivers_active(monkeypatch, True)
    calls = _recalc_returns(monkeypatch, recalculated)

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is True

    assert calls == [_PROJECT_ID]
    assert notified == [recalculated]


@pytest.mark.asyncio
async def test_a_recalc_that_yields_nothing_leaves_the_scan_stats_for_notifications(db, notified, monkeypatch):
    _waivers_active(monkeypatch, True)
    calls = _recalc_returns(monkeypatch, None)

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is True

    assert calls == [_PROJECT_ID]
    assert notified == [Stats()]


@pytest.mark.asyncio
async def test_without_active_waivers_no_recalc_runs(db, notified, monkeypatch):
    _waivers_active(monkeypatch, False)
    calls = _recalc_returns(monkeypatch, Stats(critical=7))

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is True

    assert calls == []
    assert notified == [Stats()]


@pytest.mark.asyncio
async def test_a_scan_that_is_not_finalized_is_not_notified(db, notified, monkeypatch):
    async def _not_finalized(*args, **kwargs):
        return False

    monkeypatch.setattr(engine, "_finalize_scan_and_project", _not_finalized)

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is False

    assert notified == []


@pytest.mark.asyncio
async def test_a_race_with_a_late_result_stops_before_finalizing(db, notified, monkeypatch):
    finalized: list[str] = []

    async def _raced(scan_id, external_load_start, scan_repo):
        return True

    async def _finalize(scan_id, *args, **kwargs):
        finalized.append(scan_id)
        return True

    monkeypatch.setattr(engine, "_check_race_condition", _raced)
    monkeypatch.setattr(engine, "_finalize_scan_and_project", _finalize)

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is False

    assert finalized == []
    assert notified == []


@pytest.fixture
def enrichment_inputs(monkeypatch) -> dict:
    seen: dict = {}

    async def _capture(active_analyzers, *args):
        seen["analyzers"] = active_analyzers
        seen["github_token"] = args[-2]

    monkeypatch.setattr(engine, "_run_vuln_enrichments", _capture)
    return seen


@pytest.mark.asyncio
async def test_a_cbom_scan_runs_the_crypto_analyzers_on_top_of_the_configured_ones(db, notified, enrichment_inputs):
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=[], status="processing", scan_type="cbom")
    await db.scans.insert_one(scan.model_dump(by_alias=True))

    assert await engine.run_analysis(scan.id, [], ["osv"], db) is True

    assert enrichment_inputs["analyzers"] == sorted({"osv"} | engine.CRYPTO_ANALYZERS)


@pytest.mark.asyncio
async def test_the_settings_github_token_is_used_before_any_instance_token(db, notified, enrichment_inputs):
    await db.system_settings.insert_one({"_id": "current", "github_token": "settings-token"})
    await db.github_instances.insert_one({"_id": "gh", "is_active": True, "access_token": "instance-token"})

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is True

    assert enrichment_inputs["github_token"] == "settings-token"


_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
_GHES_ISSUER = "https://ghes.corp.example/_services/token"


def _github_instance(_id: str, created_at: datetime, **fields) -> dict:
    return {
        "_id": _id,
        "is_active": True,
        "url": _ACTIONS_ISSUER,
        "github_url": "https://github.com",
        "created_at": created_at,
        **fields,
    }


@pytest.mark.asyncio
async def test_without_a_settings_token_the_github_com_instance_token_is_used(db, notified, enrichment_inputs):
    await db.github_instances.insert_one(_github_instance("gh", _T0, access_token="instance-token"))

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is True

    assert enrichment_inputs["github_token"] == "instance-token"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ghes_fields",
    [
        pytest.param({"url": _GHES_ISSUER, "github_url": "https://ghes.corp.example"}, id="ghes-web-url"),
        pytest.param({"url": _GHES_ISSUER, "github_url": None}, id="ghes-without-web-url"),
        pytest.param({"url": _GHES_ISSUER}, id="ghes-web-url-absent"),
    ],
)
async def test_a_ghes_instance_token_is_never_sent_to_github_com(db, notified, enrichment_inputs, ghes_fields):
    await db.github_instances.insert_one(
        {"_id": "ghes", "is_active": True, "created_at": _T0, "access_token": "ghes-pat", **ghes_fields}
    )

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is True

    assert enrichment_inputs["github_token"] is None


@pytest.mark.asyncio
async def test_the_github_com_token_is_chosen_over_an_older_ghes_instance(db, notified, enrichment_inputs):
    await db.github_instances.insert_one(
        _github_instance("ghes", _T0, url=_GHES_ISSUER, github_url="https://ghes.corp.example", access_token="ghes-pat")
    )
    await db.github_instances.insert_one(_github_instance("gh", _T0 + timedelta(days=1), access_token="gh-token"))

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is True

    assert enrichment_inputs["github_token"] == "gh-token"


@pytest.mark.asyncio
async def test_of_several_github_com_instances_the_oldest_token_is_used(db, notified, enrichment_inputs):
    await db.github_instances.insert_one(_github_instance("newer", _T0 + timedelta(days=1), access_token="newer"))
    await db.github_instances.insert_one(_github_instance("older", _T0, access_token="older"))

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is True

    assert enrichment_inputs["github_token"] == "older"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        pytest.param({"access_token": ""}, id="empty-token"),
        pytest.param({"access_token": "gh-token", "is_active": False}, id="inactive"),
    ],
)
async def test_without_a_usable_instance_token_ghsa_runs_unauthenticated(db, notified, enrichment_inputs, fields):
    await db.github_instances.insert_one(_github_instance("gh", _T0, **fields))

    assert await engine.run_analysis(await _seed_scan(db), [], [], db) is True

    assert enrichment_inputs["github_token"] is None


@pytest.mark.asyncio
async def test_a_run_whose_sboms_all_fail_to_load_is_failed_and_not_notified(db, notified, monkeypatch):
    async def _gridfs_outage(fs, file_id, **_kwargs):
        raise OSError("gridfs outage")

    monkeypatch.setattr(engine, "open_gridfs_download_with_retry", _gridfs_outage)
    file_id = "69d5332257c8763c8d8c82d7"
    ref = {"storage": "gridfs", "file_id": file_id, "type": "gridfs_reference", "gridfs_id": file_id}
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=[ref], status="processing")
    await db.scans.insert_one(scan.model_dump(by_alias=True))

    assert await engine.run_analysis(scan.id, [ref], [], db) is True

    stored = await db.scans.find_one({"_id": scan.id})
    assert (stored["status"], stored["error"]) == ("failed", "SBOM could not be loaded for analysis")
    assert notified == []
