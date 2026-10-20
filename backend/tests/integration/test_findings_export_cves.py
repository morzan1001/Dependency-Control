import csv
import io

import pytest

from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _prepare_finding_records
from app.services.analyzers.deps_dev import DepsDevAnalyzer
from app.services.inventory.csv_stream import iter_csv
from app.services.inventory.findings_export import FINDINGS_COLUMNS, ExportedScan, iter_findings_rows
from tests.helpers.findings import grype_findings

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_SCAN = ExportedScan("s-export", "main", None, None)


async def _exported_rows(db) -> list[dict[str, str]]:
    text = "".join([chunk async for chunk in iter_csv(FINDINGS_COLUMNS, iter_findings_rows(db, [_SCAN]))])
    return list(csv.DictReader(io.StringIO(text.lstrip("\ufeff"))))


async def test_a_vulnerability_row_carries_its_cves_and_a_title(db):
    # The fixture's own advisory is GHSA-v6h2-p8h4-qcjw, which grype relates to CVE-2025-5889.
    findings = grype_findings([("lodash", "4.17.20", None), ("lodash", "4.17.20", "CVE-2021-23337")])
    records, _ = _prepare_finding_records(findings, _SCAN.id, "p-export", None)
    await db.findings.insert_many(records)

    [row] = await _exported_rows(db)

    assert (row["finding_id"], row["title"], row.get("cves")) == (
        "lodash:4.17.20",
        "CVE-2021-23337",
        "CVE-2021-23337; CVE-2025-5889",
    )


async def test_a_ghsa_finding_is_titled_and_listed_by_the_cves_its_advisories_name(db):
    await db.findings.insert_one(
        {
            "_id": "f-ghsa",
            "finding_id": "minimist:1.2.5",
            "scan_id": _SCAN.id,
            "project_id": "p-export",
            "type": "vulnerability",
            "severity": "HIGH",
            "component": "minimist",
            "version": "1.2.5",
            "description": "",
            "details": {
                "vulnerabilities": [
                    {"id": "GHSA-zzzz-zzzz-zzzz", "aliases": []},
                    {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2024-0001"]},
                    {"id": "GHSA-dddd-eeee-ffff", "aliases": [], "resolved_cve": "CVE-2024-0002"},
                ]
            },
        }
    )

    [row] = await _exported_rows(db)

    assert (row["title"], row["cves"]) == ("CVE-2024-0001", "GHSA-zzzz-zzzz-zzzz; CVE-2024-0001; CVE-2024-0002")


async def test_a_scorecard_row_carries_the_advice_for_its_failed_checks(db):
    scorecard = {
        "overallScore": 2.4,
        "date": "2026-08-01",
        "checks": [{"name": "Maintained", "score": 0}, {"name": "Fuzzing", "score": 0}],
        "repository": "github.com/example/left-pad",
    }
    issue = DepsDevAnalyzer._create_scorecard_issue("https://github.com/example/left-pad", scorecard)
    aggregator = ResultAggregator()
    scorecard_issue = {**issue, "component": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}
    aggregator.aggregate("deps_dev", {"scorecard_issues": [scorecard_issue], "package_metadata": {}})
    records, _ = _prepare_finding_records(aggregator.get_findings(), _SCAN.id, "p-export", None)
    await db.findings.insert_many(records)

    [row] = await _exported_rows(db)

    assert (row["type"], row["recommendation"]) == (
        "quality",
        "Consider finding an actively maintained alternative • No fuzzing - potential undiscovered bugs",
    )


async def test_a_partly_waived_finding_is_titled_by_a_live_cve_and_names_its_waived_ones(db):
    await db.findings.insert_one(
        {
            "_id": "f-partly-waived",
            "finding_id": "lodash:4.17.20",
            "scan_id": _SCAN.id,
            "project_id": "p-export",
            "type": "vulnerability",
            "severity": "HIGH",
            "component": "lodash",
            "version": "4.17.20",
            "description": "",
            "details": {
                "vulnerabilities": [
                    {"id": "CVE-2024-0001", "aliases": [], "waived": True, "waiver_reason": "not reachable"},
                    {"id": "CVE-2024-0002", "aliases": []},
                ]
            },
        }
    )

    [row] = await _exported_rows(db)

    assert (row["title"], row["cves"], row["waived"], row.get("waived_cves")) == (
        "CVE-2024-0002",
        "CVE-2024-0001; CVE-2024-0002",
        "false",
        "CVE-2024-0001",
    )
