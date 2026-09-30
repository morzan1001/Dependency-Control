"""Persisting a scan's findings writes them over the stored copies and only then deletes the ones the run no longer has."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import bson
import pytest
from pymongo.errors import OperationFailure

from app.core import ensure_utc
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis import engine
from app.services.analysis.engine import _partial_run_reasons, _persist_findings_and_waivers, _prepare_finding_records

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
async def test_a_vulnerability_finding_over_16_mib_is_stored_with_slim_advisories(db, caplog):
    [record] = _trivy_records(_trivy_vulnerability("CVE-2016-2779", "linux-libc-dev"))
    advisory = record["details"]["vulnerabilities"][0]
    cves = [f"CVE-2024-{n:05d}" for n in range(6000)]
    record["details"]["vulnerabilities"] = [{**advisory, "id": cve, "description": "d" * 3000} for cve in cves]
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


@pytest.mark.live_mongo
async def test_a_non_vulnerability_finding_over_16_mib_fails_and_keeps_the_previous_findings(db):
    previous = _trivy_records(
        _trivy_vulnerability("CVE-2023-45288", "golang.org/x/net"),
        _trivy_vulnerability("CVE-2024-24790", "golang.org/x/text"),
    )
    await _persist(db, previous)
    sast, _ = _prepare_finding_records(
        _findings("bearer", {"findings": _BEARER_OUTPUT})[:1], _SCAN, _PROJECT, _SCAN_CREATED
    )
    sast[0]["details"]["sast_findings"] *= 40_000
    assert len(bson.encode(sast[0])) > _MAX_DOCUMENT

    with pytest.raises(OperationFailure):
        await _persist(db, [*_trivy_records(_trivy_vulnerability("CVE-2023-45288", "golang.org/x/net")), *sast])

    assert await _stored_ids(db) == sorted(r["_id"] for r in previous)
