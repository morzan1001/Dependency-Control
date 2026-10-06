"""Persisting a scan's findings writes them over the stored copies and only then deletes the ones the run no longer has."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import bson
import pytest
from pymongo.errors import DocumentTooLarge

from app.core import ensure_utc
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis import engine
from app.services.analysis.engine import _partial_run_reasons, _persist_findings_and_waivers, _prepare_finding_records
from tests.helpers.profiler import inserts_and_upserts, profiled

pytestmark = pytest.mark.asyncio

_PROJECT = "p-rewrite"
_SCAN = "scan-rewrite"
_SCAN_CREATED = datetime(2026, 9, 1, tzinfo=timezone.utc)
_EARLIER_RUN = datetime(2026, 9, 2, tzinfo=timezone.utc)
_MAX_DOCUMENT = 16 * 1024 * 1024
_BEARER_OUTPUT = json.loads((Path(__file__).parents[1] / "fixtures/sast/bearer_2.1.1_findings.json").read_text())

_DATABASES = [
    pytest.param("attrappe", id="attrappe"),
    pytest.param("real-mongo", marks=pytest.mark.live_mongo, id="real-mongo"),
]


def _trivy_vulnerability(cve: str, pkg: str) -> dict:
    return {
        "VulnerabilityID": cve,
        "PkgID": f"{pkg}@v0.17.0",
        "PkgName": pkg,
        "InstalledVersion": "v0.17.0",
        "FixedVersion": "0.23.0",
        "Status": "fixed",
        "SeveritySource": "ghsa",
        "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve.lower()}",
        "Title": "parser: excessive resource consumption",
        "Description": "A flaw in the parser.",
        "Severity": "HIGH",
        "CweIDs": ["CWE-400"],
        "CVSS": {"ghsa": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "V3Score": 7.5}},
        "References": [f"https://nvd.nist.gov/vuln/detail/{cve}", "https://go.dev/issue/65051"],
        "PublishedDate": "2024-04-04T21:15:16.113Z",
        "LastModifiedDate": "2024-06-07T14:15:12.577Z",
    }


def _findings(scanner: str, report: dict) -> list:
    aggregator = ResultAggregator()
    aggregator.aggregate(scanner, report)
    return aggregator.get_findings()


def _trivy_records(*vulnerabilities: dict) -> list[dict]:
    report = {
        "Results": [{"Target": "go.mod", "Class": "lang-pkgs", "Type": "gomod", "Vulnerabilities": [*vulnerabilities]}]
    }
    records, _ = _prepare_finding_records(_findings("trivy", report), _SCAN, _PROJECT, _SCAN_CREATED)
    return records


async def _persist(db, records: list[dict]) -> int:
    return await _persist_findings_and_waivers(records, _SCAN, _PROJECT, FindingRepository(db), db)


async def _stored_ids(db) -> list[str]:
    return sorted(doc["_id"] for doc in await db.findings.find({"scan_id": _SCAN}, {"_id": 1}).to_list(None))


@pytest.mark.parametrize("database", _DATABASES)
async def test_reanalysis_drops_rows_the_run_no_longer_found_and_rewrites_the_rest(db, database, monkeypatch):
    first = _trivy_records(
        _trivy_vulnerability("CVE-2023-45288", "golang.org/x/net"),
        _trivy_vulnerability("CVE-2024-24790", "golang.org/x/text"),
    )
    await _persist(db, first)
    kept = next(r for r in first if r["component"] == "golang.org/x/net")
    await db.findings.update_many({"scan_id": _SCAN}, {"$set": {"created_at": _EARLIER_RUN}})
    await db.findings.update_one({"_id": kept["_id"]}, {"$set": {"waived": True, "waiver_reason": "stale"}})
    waiver = Waiver(project_id=_PROJECT, finding_id=kept["finding_id"], reason="accepted", created_by="u")
    await db.waivers.insert_one(waiver.model_dump(by_alias=True))
    state_when_the_waiver_pass_ran: list[tuple] = []
    restamp = engine.restamp_waivers

    async def _observe_restamp(finding_repo, *args):
        row = await db.findings.find_one({"_id": kept["_id"]})
        state_when_the_waiver_pass_ran.append((row["waived"], row["waiver_reason"]))
        return await restamp(finding_repo, *args)

    monkeypatch.setattr(engine, "restamp_waivers", _observe_restamp)

    persisted = await _persist(db, _trivy_records(_trivy_vulnerability("CVE-2023-45288", "golang.org/x/net")))

    stored = await db.findings.find_one({"_id": kept["_id"]})
    assert persisted == 1
    assert await _stored_ids(db) == [kept["_id"]]
    assert ensure_utc(stored["created_at"]) > _EARLIER_RUN
    assert state_when_the_waiver_pass_ran == [(False, None)]
    assert (stored["waived"], stored["waiver_reason"]) == (True, "accepted")


@pytest.mark.live_mongo
async def test_a_scan_without_findings_takes_inserts_and_a_rewrite_replaces(db):
    records = _trivy_records(
        _trivy_vulnerability("CVE-2023-45288", "golang.org/x/net"),
        _trivy_vulnerability("CVE-2024-24790", "golang.org/x/text"),
    )

    _, first = await profiled(db, _persist(db, [dict(r) for r in records]))
    _, again = await profiled(db, _persist(db, [dict(r) for r in records]))

    assert (inserts_and_upserts(first, "findings"), inserts_and_upserts(again, "findings")) == ((1, 0), (0, 2))


def _padded_to(record: dict, size: int) -> dict:
    record["description"] += " " * (size - len(bson.encode(record)))
    return record


def _vulnerability_with_advisories(size_at_least: int) -> tuple[dict, dict, list[str]]:
    """One trivy finding whose 6,000 advisories carry descriptions long enough to reach ``size_at_least`` BSON bytes."""
    [record] = _trivy_records(_trivy_vulnerability("CVE-2016-2779", "linux-libc-dev"))
    advisory = record["details"]["vulnerabilities"][0]
    cves = [f"CVE-2024-{n:05d}" for n in range(6000)]
    record["details"]["vulnerabilities"] = [{**advisory, "id": cve, "description": ""} for cve in cves]
    length = -(-(size_at_least - len(bson.encode(record))) // len(cves))
    for entry in record["details"]["vulnerabilities"]:
        entry["description"] = "d" * length
    return record, advisory, cves


@pytest.mark.live_mongo
@pytest.mark.parametrize(
    "size_at_least", [_MAX_DOCUMENT + 4096, _MAX_DOCUMENT + 4_000_000], ids=["just-over", "far-over"]
)
async def test_a_vulnerability_finding_over_16_mib_is_stored_with_slim_advisories(db, caplog, size_at_least):
    record, advisory, cves = _vulnerability_with_advisories(size_at_least)
    assert len(bson.encode(record)) > _MAX_DOCUMENT

    with caplog.at_level(logging.WARNING, logger="app.services.analysis.engine"):
        persisted = await _persist(db, [record])

    stored = await db.findings.find_one({"_id": record["_id"]})
    entries = stored["details"]["vulnerabilities"]
    assert persisted == 1
    assert _partial_run_reasons([], 0, 0, 1, persisted, 1) == []
    assert [e["id"] for e in entries] == cves
    assert all(e["severity"] == advisory["severity"] and e["fixed_version"] == "0.23.0" for e in entries)
    assert not [e for e in entries if {"description", "references", "details"} & e.keys()]
    assert record["finding_id"] in caplog.text


def _sast_record() -> dict:
    sast, _ = _prepare_finding_records(
        _findings("bearer", {"findings": _BEARER_OUTPUT})[:1], _SCAN, _PROJECT, _SCAN_CREATED
    )
    return sast[0]


@pytest.mark.live_mongo
@pytest.mark.parametrize(
    ("oversized", "size"),
    [
        pytest.param(_sast_record, _MAX_DOCUMENT + 4096, id="sast-just-over"),
        pytest.param(_sast_record, _MAX_DOCUMENT + 4_000_000, id="sast-far-over"),
        pytest.param(
            lambda: _trivy_records(_trivy_vulnerability("CVE-2016-2779", "linux-libc-dev"))[0],
            _MAX_DOCUMENT + 4096,
            id="vulnerability-over-even-when-slim",
        ),
    ],
)
async def test_a_finding_slimming_cannot_fit_fails_and_keeps_the_previous_findings(db, oversized, size):
    previous = _trivy_records(
        _trivy_vulnerability("CVE-2023-45288", "golang.org/x/net"),
        _trivy_vulnerability("CVE-2024-24790", "golang.org/x/text"),
    )
    await _persist(db, previous)
    record = _padded_to(oversized(), size)

    with pytest.raises(DocumentTooLarge, match=record["finding_id"]):
        await _persist(db, [*_trivy_records(_trivy_vulnerability("CVE-2023-45288", "golang.org/x/net")), record])

    assert await _stored_ids(db) == sorted(r["_id"] for r in previous)
