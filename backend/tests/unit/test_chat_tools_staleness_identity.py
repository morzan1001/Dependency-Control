"""How long a finding has been open is a property of the advisory, not of the document.

Matching head against history on the stored ``finding_id`` restarts the clock on a version bump,
so a vulnerability open for a year reads as fresh the moment an unrelated upgrade lands.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._helpers import staleness_identities
from tests.helpers.permission_presets import PRESET_ADMIN

_NOW = datetime.now(timezone.utc)
_LONG_AGO = _NOW - timedelta(days=400)
_PROJECT = "checkout-service"
_OLD_SCAN = "scan-old"
_HEAD_SCAN = "scan-head"
_CVE = "CVE-2021-44228"
_OTHER_CVE = "CVE-2021-45046"
_COMPONENT = "log4j-core"
_OLD_VERSION = "2.14.1"
_NEW_VERSION = "2.17.0"
_QUALIFIED = "org.apache.logging.log4j:log4j-core"
_DAYS_OPEN = 30
_ONE_FINDING = 1
_NOTHING = 0


@pytest.fixture
def admin_user():
    return User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


def _vulnerability(scan_id, version, created_at, *, component=_COMPONENT, cves=(_CVE,)):
    return {
        "_id": f"{scan_id}:{component}:{version}",
        "project_id": _PROJECT,
        "scan_id": scan_id,
        "finding_id": f"{component}:{version}",
        "type": "vulnerability",
        "severity": "CRITICAL",
        "component": component,
        "version": version,
        "description": "Log4Shell",
        "found_in": ["pom.xml"],
        "details": {"vulnerabilities": [{"id": cve} for cve in cves]},
        "created_at": created_at,
    }


@pytest.fixture
def seeded(db):
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": _PROJECT,
        "team_id": None,
        "latest_scan_id": _HEAD_SCAN,
        "default_branch": "main",
    }
    for scan_id, created_at in ((_OLD_SCAN, _LONG_AGO), (_HEAD_SCAN, _NOW)):
        db.scans._docs[scan_id] = {
            "_id": scan_id,
            "project_id": _PROJECT,
            "branch": "main",
            "status": "completed",
            "created_at": created_at,
            "stats": {},
        }
    return db


def _store(db, *findings):
    for finding in findings:
        db.findings._docs[finding["_id"]] = finding


class TestIdentity:
    def test_a_version_bump_does_not_change_a_vulnerability_s_identity(self):
        old = _vulnerability(_OLD_SCAN, _OLD_VERSION, _LONG_AGO)
        new = _vulnerability(_HEAD_SCAN, _NEW_VERSION, _NOW)

        assert staleness_identities(old) == staleness_identities(new)

    def test_a_requalified_component_keeps_its_identity(self):
        """Scanners disagree on how far a package name is qualified; the delta folds the same case."""
        bare = _vulnerability(_OLD_SCAN, _OLD_VERSION, _LONG_AGO)
        qualified = _vulnerability(_HEAD_SCAN, _OLD_VERSION, _NOW, component=_QUALIFIED)

        assert staleness_identities(bare) == staleness_identities(qualified)

    def test_each_advisory_carries_its_own_clock(self):
        grouped = _vulnerability(_HEAD_SCAN, _NEW_VERSION, _NOW, cves=(_CVE, _OTHER_CVE))
        one = _vulnerability(_OLD_SCAN, _OLD_VERSION, _LONG_AGO)

        assert one.get("details")
        assert staleness_identities(one) < staleness_identities(grouped)

    def test_a_different_advisory_is_a_different_finding(self):
        first = _vulnerability(_OLD_SCAN, _OLD_VERSION, _LONG_AGO)
        second = _vulnerability(_HEAD_SCAN, _OLD_VERSION, _NOW, cves=(_OTHER_CVE,))

        assert staleness_identities(first).isdisjoint(staleness_identities(second))

    def test_a_non_vulnerability_keeps_the_delta_s_identity(self):
        secret = {"type": "secret", "component": "app.py", "finding_id": "SECRET-abc", "details": {}}

        assert staleness_identities(secret) == {("secret", "app.py", "SECRET-abc")}


@pytest.mark.asyncio
async def test_an_advisory_open_for_a_year_survives_a_version_bump(seeded, admin_user):
    _store(
        seeded,
        _vulnerability(_OLD_SCAN, _OLD_VERSION, _LONG_AGO),
        _vulnerability(_HEAD_SCAN, _NEW_VERSION, _NOW),
    )

    result = await ChatToolRegistry().execute_tool(
        "get_stale_findings", {"project_id": _PROJECT, "days_open": _DAYS_OPEN}, admin_user, seeded
    )

    assert result["count"] == _ONE_FINDING
    assert result["findings"][0]["cve"] == _CVE


@pytest.mark.asyncio
async def test_an_advisory_first_seen_today_is_not_stale(seeded, admin_user):
    _store(seeded, _vulnerability(_HEAD_SCAN, _NEW_VERSION, _NOW))

    result = await ChatToolRegistry().execute_tool(
        "get_stale_findings", {"project_id": _PROJECT, "days_open": _DAYS_OPEN}, admin_user, seeded
    )

    assert result["findings"] == []
    assert result.get("count", _NOTHING) == _NOTHING


@pytest.mark.asyncio
async def test_a_new_advisory_on_a_long_standing_component_is_not_stale(seeded, admin_user):
    """The component has been vulnerable for a year; this particular advisory has not."""
    _store(
        seeded,
        _vulnerability(_OLD_SCAN, _OLD_VERSION, _LONG_AGO),
        _vulnerability(_HEAD_SCAN, _NEW_VERSION, _NOW, cves=(_OTHER_CVE,)),
    )

    result = await ChatToolRegistry().execute_tool(
        "get_stale_findings", {"project_id": _PROJECT, "days_open": _DAYS_OPEN}, admin_user, seeded
    )

    assert result["findings"] == []
