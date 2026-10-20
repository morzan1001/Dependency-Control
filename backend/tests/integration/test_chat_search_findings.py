from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.db.mongodb import DEFAULT_MAX_TIME_MS
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._helpers import _inject_urls, _serialize_finding_for_llm
from tests.helpers.auth import make_admin
from tests.helpers.databases import DATABASES
from tests.helpers.profiler import profiled

pytestmark = pytest.mark.asyncio

_PROJECT = "p-search"
_SCAN = "scan-search"


def _finding(key: str, **fields) -> dict:
    return {
        "_id": key,
        "finding_id": f"{key}:1.0.0",
        "scan_id": _SCAN,
        "project_id": _PROJECT,
        "type": "vulnerability",
        "severity": "HIGH",
        "component": key,
        "version": "1.0.0",
        "description": "",
        "waived": False,
        "details": {"vulnerabilities": []},
        **fields,
    }


def _advisories(*advisories: dict) -> dict:
    return {"details": {"vulnerabilities": [{"severity": "HIGH", **advisory} for advisory in advisories]}}


_FINDINGS = [
    _finding("by-component", component="org.apache.logging.log4j:log4j-core"),
    _finding("by-spaced-component", component="Microsoft Visual C++ 2019 Redistributable"),
    _finding("by-finding-id", type="sast", finding_id="SAST-hardcoded-key-0042"),
    _finding("by-description", type="secret", description="AWS secret access key committed to the repository"),
    _finding("by-advisory-id", **_advisories({"id": "CVE-2021-44228"})),
    _finding("by-spaced-advisory-id", **_advisories({"id": "VULN-Acme Widget Runtime"})),
    _finding("by-alias", **_advisories({"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-45046"]})),
    _finding("by-resolved-cve", **_advisories({"id": "GHSA-7rjr-3q55-vv33", "resolved_cve": "CVE-2021-45105"})),
    _finding(
        "by-second-advisory",
        waiver_reason="accepted for the release",
        **_advisories(
            {
                "id": "CVE-2020-0001",
                "cvss_score": 7.5,
                "epss_score": 0.2,
                "epss_percentile": 0.9,
                "fixed_version": "1.0.1",
                "references": ["https://example.test/a", "https://example.test/b"],
                "in_kev": True,
            },
            {"id": "PYSEC-2021-19", "epss_score": 0.4, "risk_score": 55.0},
        ),
    ),
]


async def _seed(db) -> None:
    await db.projects.insert_one(
        {"_id": _PROJECT, "name": "search-project", "default_branch": "main", "latest_scan_id": _SCAN}
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
    await db.findings.insert_many(_FINDINGS)


@pytest.mark.parametrize("database", DATABASES)
@pytest.mark.parametrize(
    ("term", "found"),
    [
        ("LOG4J-CORE", "by-component"),
        ("visual c++ 2019", "by-spaced-component"),
        ("hardcoded-key", "by-finding-id"),
        ("Secret Access KEY", "by-description"),
        ("cve-2021-44228", "by-advisory-id"),
        ("vuln-acme widget", "by-spaced-advisory-id"),
        ("2021-45046", "by-alias"),
        ("JFH8-C2JP", "by-alias"),
        ("CVE-2021-45105", "by-resolved-cve"),
        ("pysec-2021", "by-second-advisory"),
    ],
)
async def test_a_term_finds_the_finding_whose_field_holds_it(db, database, term, found):
    await _seed(db)

    result = await ChatToolRegistry().execute_tool("search_findings", {"query": term}, make_admin(), db)

    assert [f["id"] for f in result["findings"]] == [found]
    assert result["findings_total"] == 1


@pytest.mark.parametrize("database", DATABASES)
async def test_a_search_row_shows_all_the_stored_finding_holds(db, database):
    await _seed(db)

    result = await ChatToolRegistry().execute_tool("search_findings", {"query": "PYSEC"}, make_admin(), db)

    stored = next(f for f in _FINDINGS if f["_id"] == "by-second-advisory")
    expected = {**_serialize_finding_for_llm(stored), "project_name": "search-project"}
    _inject_urls(expected)
    assert result["findings"] == [expected]


@pytest.mark.live_mongo
async def test_the_search_and_its_total_stop_on_the_server_before_the_client_socket_gives_up(db):
    await _seed(db)

    _, entries = await profiled(
        db, ChatToolRegistry().execute_tool("search_findings", {"query": "CVE-2021", "limit": 1}, make_admin(), db)
    )

    reads = [e["command"] for e in entries if e["ns"].endswith(".findings") and e["op"] in ("query", "command")]
    assert [("find" in c, c.get("maxTimeMS")) for c in reads] == [
        (True, DEFAULT_MAX_TIME_MS),
        (False, DEFAULT_MAX_TIME_MS),
    ]
