"""Every chat/MCP tool that answers "how is this project doing" must answer from the head build.

The consumer is a language model relaying the answer to a human, so a wrong scan surfaces as a
confident sentence with no branch name or chart beside it to contradict. The two shapes that used
to divert a tool are both here: the cached pointer naming a scan that is not readable yet, and the
pointer naming a branch the VCS no longer has.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED, SCAN_STATUS_PENDING
from app.models.user import User
from app.schemas.enrichment import KEVEntry
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._arguments import checked_arguments
from app.services.enrichment.service import _build_enrichment, apply_enrichments
from tests.helpers.permission_presets import PRESET_ADMIN

_NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)

_PROJECT = "checkout-service"
_PROJECT_NAME = "checkout-service"
_DEFAULT_BRANCH = "main"
_DELETED_BRANCH = "feature/spike"

_HEAD_SCAN = "scan-head"
_OLDER_SCAN = "scan-older"
_OLDEST_SCAN = "scan-oldest"
_RESCAN_OF_HEAD = "scan-head-rescan"
_QUEUED_SCAN = "scan-queued"
_FAILED_SCAN = "scan-failed"
_DELETED_BRANCH_SCAN = "scan-on-deleted-branch"

_HEAD_CVE = "CVE-2026-40001"
_OPEN_HIGH_CVE = "CVE-2026-40002"
_KEV_CVE = "CVE-2026-40003"
_OLDER_CVE = "CVE-2026-40008"
_DELETED_BRANCH_CVE = "CVE-2026-40009"
_WAIVED_FINDING_ID = "LICENSE:libcheckout:2.4.0"

_HEAD_COMPONENT = "libcheckout"
_DELETED_BRANCH_COMPONENT = "libspike"

_SEV_CRITICAL = "CRITICAL"
_SEV_HIGH = "HIGH"
_SEV_MEDIUM = "MEDIUM"
_SEV_LOW = "LOW"

_TYPE_VULNERABILITY = "vulnerability"
_TYPE_LICENSE = "license"
_TYPE_CRYPTO = "crypto_weak_algorithm"

_CRYPTO_ASSET_TYPE = "algorithm"
_HEAD_CRYPTO_ASSET = "MD5"
_DELETED_BRANCH_CRYPTO_ASSET = "RC4"
_HEAD_CRYPTO_RULE = "crypto.weak-hash"
_HEAD_CRYPTO_FINDING_ID = "CRYPTO:MD5"
_HEAD_CRYPTO_ASSET_COUNT = 1
_HEAD_CRYPTO_RULE_HITS = 1
_FOREIGN_SCAN = "scan-of-another-project"

_HEAD_CRITICAL_COUNT = 1
_ERR_NO_SCAN_DATA = "No scan data available"
_FIX_VERSION = "1.0.1"

# Each is a pointer a live project really carried: re-ingest sent the head build back to pending,
# and branch deletion left the pointer on a branch the VCS dropped.
_MISLEADING_POINTERS = [_QUEUED_SCAN, _DELETED_BRANCH_SCAN]
_POINTER_IDS = ["pointer-names-a-queued-scan", "pointer-names-a-deleted-branch"]


@pytest.fixture
def admin_user():
    return User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


def _scan(scan_id, branch, status, age_days, critical=0, **extra):
    doc = {
        "_id": scan_id,
        "project_id": _PROJECT,
        "branch": branch,
        "status": status,
        "created_at": _NOW - timedelta(days=age_days),
        "stats": {"critical": critical, "high": 0, "medium": 0, "low": 0},
    }
    doc.update(extra)
    return doc


def _vulnerability(scan_id, cve, severity, component):
    return {
        "_id": f"{scan_id}:{cve}",
        "finding_id": cve,
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "type": _TYPE_VULNERABILITY,
        "severity": severity,
        "component": component,
        "version": "1.0.0",
        "first_seen_at": _NOW - timedelta(days=300),
        "waived": False,
        "details": {
            "fixed_version": _FIX_VERSION,
            "vulnerabilities": [{"id": cve, "severity": severity, "fixed_version": _FIX_VERSION}],
        },
    }


def _dependency(scan_id, name):
    return {
        "_id": f"{scan_id}:{name}",
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "name": name,
        "version": "1.0.0",
        "purl": f"pkg:pypi/{name}@1.0.0",
        "type": "pypi",
        "direct": True,
    }


@pytest.fixture
def seeded(db):
    """A project whose head is `_HEAD_SCAN`, with every distraction the resolver has to rank below it."""
    for doc in (
        _scan(_OLDER_SCAN, _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 20),
        _scan(_HEAD_SCAN, _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 5, critical=_HEAD_CRITICAL_COUNT),
        _scan(_DELETED_BRANCH_SCAN, _DELETED_BRANCH, SCAN_STATUS_COMPLETED, 1),
        _scan(_QUEUED_SCAN, _DEFAULT_BRANCH, SCAN_STATUS_PENDING, 0),
        _scan(_FAILED_SCAN, _DEFAULT_BRANCH, SCAN_STATUS_FAILED, 0),
    ):
        db.scans._docs[doc["_id"]] = doc

    for doc in (
        _vulnerability(_OLDER_SCAN, _OLDER_CVE, _SEV_MEDIUM, _HEAD_COMPONENT),
        _vulnerability(_HEAD_SCAN, _HEAD_CVE, _SEV_CRITICAL, _HEAD_COMPONENT),
        _vulnerability(_DELETED_BRANCH_SCAN, _DELETED_BRANCH_CVE, _SEV_LOW, _DELETED_BRANCH_COMPONENT),
        {
            "_id": f"{_HEAD_SCAN}:license",
            "finding_id": _WAIVED_FINDING_ID,
            "scan_id": _HEAD_SCAN,
            "project_id": _PROJECT,
            "type": _TYPE_LICENSE,
            "severity": _SEV_HIGH,
            "component": _HEAD_COMPONENT,
            "version": "2.4.0",
            "first_seen_at": _NOW - timedelta(days=300),
            "waived": True,
            "waiver_reason": "legal signed off",
            "details": {},
        },
    ):
        db.findings._docs[doc["_id"]] = doc

    for doc in (
        _dependency(_HEAD_SCAN, _HEAD_COMPONENT),
        _dependency(_OLDER_SCAN, _HEAD_COMPONENT),
        _dependency(_DELETED_BRANCH_SCAN, _DELETED_BRANCH_COMPONENT),
    ):
        db.dependencies._docs[doc["_id"]] = doc

    db.waivers._docs["w-1"] = {
        "_id": "w-1",
        "project_id": _PROJECT,
        "finding_id": _WAIVED_FINDING_ID,
        "package_name": _HEAD_COMPONENT,
        "package_version": "2.4.0",
        "finding_type": _TYPE_LICENSE,
        "scope": "finding",
        "reason": "legal signed off",
        "status": "accepted_risk",
        "expiration_date": _NOW + timedelta(days=90),
        "created_by": "tester",
        "created_at": _NOW - timedelta(days=10),
    }
    return db


def _point_at(db, scan_id):
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": _PROJECT_NAME,
        "team_id": None,
        "default_branch": _DEFAULT_BRANCH,
        "deleted_branches": [_DELETED_BRANCH],
        "latest_scan_id": scan_id,
    }


async def _call(db, user, tool_name, args=None):
    return await ChatToolRegistry()._dispatch(tool_name, checked_arguments(tool_name, args or {}), user, db)


@pytest.mark.parametrize("pointer", _MISLEADING_POINTERS, ids=_POINTER_IDS)
class TestPerProjectToolsAnswerFromHead:
    @pytest.mark.asyncio
    async def test_findings_are_the_head_builds(self, seeded, admin_user, pointer):
        """A listing keeps the waived finding, flagged, as REST's finding list does."""
        _point_at(seeded, pointer)

        result = await _call(seeded, admin_user, "get_scan_findings", {"project_id": _PROJECT})

        assert {f["finding_id"] for f in result["findings"]} == {_HEAD_CVE, _WAIVED_FINDING_ID}
        assert result["project_name"] == _PROJECT_NAME

    @pytest.mark.asyncio
    async def test_severity_breakdown_is_the_head_builds(self, seeded, admin_user, pointer):
        _point_at(seeded, pointer)

        result = await _call(seeded, admin_user, "get_findings_by_severity", {"project_id": _PROJECT})

        assert result["breakdown"] == {_SEV_CRITICAL: 1}

    @pytest.mark.asyncio
    async def test_type_breakdown_is_the_head_builds(self, seeded, admin_user, pointer):
        _point_at(seeded, pointer)

        result = await _call(seeded, admin_user, "get_findings_by_type", {"project_id": _PROJECT})

        assert result["breakdown"] == {_TYPE_VULNERABILITY: 1}

    @pytest.mark.asyncio
    async def test_dependency_tree_is_the_head_builds(self, seeded, admin_user, pointer):
        _point_at(seeded, pointer)

        result = await _call(seeded, admin_user, "get_dependency_tree", {"project_id": _PROJECT})

        assert [d["name"] for d in result["dependencies"]] == [_HEAD_COMPONENT]

    @pytest.mark.asyncio
    async def test_waiver_status_reads_the_head_builds_finding(self, seeded, admin_user, pointer):
        """Off head the finding document is absent, and the tool then calls a live waiver dormant."""
        _point_at(seeded, pointer)

        result = await _call(
            seeded, admin_user, "get_waiver_status", {"project_id": _PROJECT, "finding_id": _WAIVED_FINDING_ID}
        )

        assert result["waived"] is True

    @pytest.mark.asyncio
    async def test_top_priority_findings_are_the_head_builds(self, seeded, admin_user, pointer):
        _point_at(seeded, pointer)

        result = await _call(seeded, admin_user, "get_top_priority_findings", {"project_id": _PROJECT})

        assert [f["finding_id"] for f in result["findings"]] == [_HEAD_CVE]

    @pytest.mark.asyncio
    async def test_remediation_plan_is_built_from_the_head_build(self, seeded, admin_user, pointer):
        _point_at(seeded, pointer)

        result = await _call(seeded, admin_user, "generate_remediation_plan", {"project_id": _PROJECT})

        assert [step["component"] for step in result["plan"]] == [_HEAD_COMPONENT]
        assert result["plan"][0]["target_version"] == _FIX_VERSION


@pytest.mark.parametrize("pointer", _MISLEADING_POINTERS, ids=_POINTER_IDS)
class TestCrossProjectToolsAnswerFromHead:
    @pytest.mark.asyncio
    async def test_analytics_summary_counts_the_head_build(self, seeded, admin_user, pointer):
        _point_at(seeded, pointer)

        result = await _call(seeded, admin_user, "get_analytics_summary")

        assert result["severity_breakdown"] == {_SEV_CRITICAL: 1}
        assert result["total_findings"] == 1
        assert result["top_risky_projects"][0]["critical"] == _HEAD_CRITICAL_COUNT

    @pytest.mark.asyncio
    async def test_hotspots_name_the_head_build_and_its_stats(self, seeded, admin_user, pointer):
        _point_at(seeded, pointer)

        result = await _call(seeded, admin_user, "get_hotspots")

        (hotspot,) = result["hotspots"]
        assert hotspot["head_scan_id"] == _HEAD_SCAN
        assert hotspot["stats"]["critical"] == _HEAD_CRITICAL_COUNT

    @pytest.mark.asyncio
    async def test_org_wide_top_priority_findings_are_the_head_builds(self, seeded, admin_user, pointer):
        _point_at(seeded, pointer)

        result = await _call(seeded, admin_user, "get_top_priority_findings")

        assert [f["finding_id"] for f in result["findings"]] == [_HEAD_CVE]


class TestWaivedFindingsAreNotReportedOpen:
    """The waived HIGH license finding sits beside an open HIGH vulnerability of the same build."""

    @pytest.fixture
    def with_open_high(self, seeded):
        _point_at(seeded, _HEAD_SCAN)
        doc = _vulnerability(_HEAD_SCAN, _OPEN_HIGH_CVE, _SEV_HIGH, _HEAD_COMPONENT)
        seeded.findings._docs[doc["_id"]] = doc
        return seeded

    @pytest.mark.asyncio
    async def test_the_severity_answers_count_only_the_open_finding(self, with_open_high, admin_user):
        per_project = await _call(with_open_high, admin_user, "get_findings_by_severity", {"project_id": _PROJECT})
        summary = await _call(with_open_high, admin_user, "get_analytics_summary")

        assert per_project["breakdown"] == summary["severity_breakdown"] == {_SEV_CRITICAL: 1, _SEV_HIGH: 1}

    @pytest.mark.asyncio
    async def test_the_type_answer_counts_only_open_findings(self, with_open_high, admin_user):
        result = await _call(with_open_high, admin_user, "get_findings_by_type", {"project_id": _PROJECT})

        assert result["breakdown"] == {_TYPE_VULNERABILITY: 2}

    @pytest.mark.asyncio
    async def test_the_priority_list_names_only_open_findings(self, with_open_high, admin_user):
        result = await _call(with_open_high, admin_user, "get_top_priority_findings")

        assert [f["finding_id"] for f in result["findings"]] == [_HEAD_CVE, _OPEN_HIGH_CVE]
        assert "fixed_version" in result["hint"]

    @pytest.mark.asyncio
    async def test_the_stale_list_does_not_ask_for_a_waiver_that_exists(self, with_open_high, admin_user):
        result = await _call(with_open_high, admin_user, "get_stale_findings")

        assert {f["finding_id"] for f in result["findings"]} == {_HEAD_CVE, _OPEN_HIGH_CVE}
        assert "waiv" not in result["hint"]

    @pytest.mark.asyncio
    async def test_a_waived_license_finding_is_no_violation(self, with_open_high, admin_user):
        result = await _call(with_open_high, admin_user, "get_license_violations")

        assert result["findings"] == []


class TestTopPriorityPutsActiveExploitationFirst:
    @pytest.fixture
    def with_kev_high(self, seeded):
        """A HIGH finding whose advisory CISA lists as exploited, enriched the way ingest enriches it."""
        _point_at(seeded, _HEAD_SCAN)
        doc = _vulnerability(_HEAD_SCAN, _KEV_CVE, _SEV_HIGH, _HEAD_COMPONENT)
        kev = KEVEntry(
            cve=_KEV_CVE, date_added="2026-08-01", required_action="Apply the update.", due_date="2026-08-22"
        )
        apply_enrichments(doc["details"], {_KEV_CVE: _build_enrichment(_KEV_CVE, kev, None)})
        seeded.findings._docs[doc["_id"]] = doc
        return seeded

    @pytest.mark.asyncio
    async def test_an_exploited_high_outranks_an_unexploited_critical(self, with_kev_high, admin_user):
        result = await _call(with_kev_high, admin_user, "get_top_priority_findings")

        assert [f["finding_id"] for f in result["findings"]] == [_KEV_CVE, _HEAD_CVE]

    @pytest.mark.asyncio
    async def test_a_single_slot_goes_to_the_exploited_finding(self, with_kev_high, admin_user):
        result = await _call(with_kev_high, admin_user, "get_top_priority_findings", {"limit": 1})

        assert [f["finding_id"] for f in result["findings"]] == [_KEV_CVE]


class TestCompareScansDefaultPair:
    @pytest.mark.asyncio
    async def test_defaults_to_head_against_the_build_before_it(self, seeded, admin_user):
        """The newest scan is queued and holds nothing, so comparing against it reports the head
        build's CRITICAL as resolved."""
        _point_at(seeded, _QUEUED_SCAN)

        result = await _call(seeded, admin_user, "compare_scans", {"project_id": _PROJECT})

        assert result["from_scan_id"] == _OLDER_SCAN
        assert result["to_scan_id"] == _HEAD_SCAN

    @pytest.mark.asyncio
    async def test_a_single_build_on_the_head_branch_cannot_be_compared(self, seeded, admin_user):
        _point_at(seeded, _HEAD_SCAN)
        del seeded.scans._docs[_OLDER_SCAN]

        result = await _call(seeded, admin_user, "compare_scans", {"project_id": _PROJECT})

        assert "error" in result

    @pytest.mark.asyncio
    async def test_explicit_scan_ids_are_still_honoured(self, seeded, admin_user):
        _point_at(seeded, _QUEUED_SCAN)

        result = await _call(
            seeded,
            admin_user,
            "compare_scans",
            {"project_id": _PROJECT, "from_scan_id": _OLDER_SCAN, "to_scan_id": _DELETED_BRANCH_SCAN},
        )

        assert result["to_scan_id"] == _DELETED_BRANCH_SCAN

    @pytest.fixture
    def with_oldest(self, seeded):
        doc = _scan(_OLDEST_SCAN, _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 40)
        seeded.scans._docs[doc["_id"]] = doc
        _point_at(seeded, _HEAD_SCAN)
        return seeded

    @pytest.mark.asyncio
    async def test_a_lone_from_scan_is_compared_with_head(self, with_oldest, admin_user):
        """'What changed since build X' names X alone."""
        result = await _call(
            with_oldest, admin_user, "compare_scans", {"project_id": _PROJECT, "from_scan_id": _OLDEST_SCAN}
        )

        assert (result["from_scan_id"], result["to_scan_id"]) == (_OLDEST_SCAN, _HEAD_SCAN)

    @pytest.mark.asyncio
    async def test_a_lone_to_scan_is_compared_with_the_build_before_it(self, with_oldest, admin_user):
        result = await _call(
            with_oldest, admin_user, "compare_scans", {"project_id": _PROJECT, "to_scan_id": _OLDER_SCAN}
        )

        assert (result["from_scan_id"], result["to_scan_id"]) == (_OLDEST_SCAN, _OLDER_SCAN)

    @pytest.mark.asyncio
    async def test_a_rescanned_head_is_compared_with_the_build_before_its_commit(self, seeded, admin_user):
        """The rescan re-analyses head's own commit, so the build before is the one before that commit."""
        rescan = _scan(_RESCAN_OF_HEAD, _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 0)
        rescan.update(is_rescan=True, original_scan_id=_HEAD_SCAN)
        seeded.scans._docs[_RESCAN_OF_HEAD] = rescan
        seeded.scans._docs[_HEAD_SCAN]["latest_rescan_id"] = _RESCAN_OF_HEAD
        _point_at(seeded, _HEAD_SCAN)

        result = await _call(seeded, admin_user, "compare_scans", {"project_id": _PROJECT})

        assert (result["from_scan_id"], result["to_scan_id"]) == (_OLDER_SCAN, _RESCAN_OF_HEAD)

    @pytest.mark.asyncio
    async def test_a_scan_of_another_project_is_refused(self, seeded, admin_user):
        seeded.scans._docs[_FOREIGN_SCAN] = _scan(
            _FOREIGN_SCAN, _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 0, project_id="another-project"
        )
        _point_at(seeded, _HEAD_SCAN)

        result = await _call(
            seeded, admin_user, "compare_scans", {"project_id": _PROJECT, "from_scan_id": _FOREIGN_SCAN}
        )

        assert result == {"error": "Scan not found in this project"}


def _crypto_asset(scan_id, name):
    return {
        "_id": f"{scan_id}:{name}",
        "project_id": _PROJECT,
        "scan_id": scan_id,
        "bom_ref": f"crypto/{name}",
        "name": name,
        "asset_type": _CRYPTO_ASSET_TYPE,
    }


@pytest.fixture
def seeded_with_crypto(seeded):
    """The CBOM and the crypto findings the scan-scoped tools read, on head and on the branch the
    VCS dropped."""
    for doc in (
        _crypto_asset(_HEAD_SCAN, _HEAD_CRYPTO_ASSET),
        _crypto_asset(_DELETED_BRANCH_SCAN, _DELETED_BRANCH_CRYPTO_ASSET),
    ):
        seeded.crypto_assets._docs[doc["_id"]] = doc
    seeded.findings._docs[f"{_HEAD_SCAN}:crypto"] = {
        "_id": f"{_HEAD_SCAN}:crypto",
        "finding_id": _HEAD_CRYPTO_FINDING_ID,
        "scan_id": _HEAD_SCAN,
        "project_id": _PROJECT,
        "type": _TYPE_CRYPTO,
        "severity": _SEV_HIGH,
        "component": _HEAD_CRYPTO_ASSET,
        "created_at": _NOW,
        "waived": False,
        "details": {"rule_id": _HEAD_CRYPTO_RULE},
    }
    _point_at(seeded, _QUEUED_SCAN)
    return seeded


class TestScanScopedToolsDefaultToHead:
    """An omitted scan_id is the obvious call, and it has to be the correct one: the model's only
    source for an id is get_scan_history, whose newest row is a queued run on any branch."""

    @pytest.mark.asyncio
    async def test_crypto_summary_counts_the_head_builds_assets(self, seeded_with_crypto, admin_user):
        result = await _call(seeded_with_crypto, admin_user, "get_crypto_summary", {"project_id": _PROJECT})

        assert result["total"] == _HEAD_CRYPTO_ASSET_COUNT
        assert result["scan"]["scan_id"] == _HEAD_SCAN

    @pytest.mark.asyncio
    async def test_crypto_assets_are_the_head_builds(self, seeded_with_crypto, admin_user):
        result = await _call(seeded_with_crypto, admin_user, "list_crypto_assets", {"project_id": _PROJECT})

        assert [i["name"] for i in result["items"]] == [_HEAD_CRYPTO_ASSET]

    @pytest.mark.asyncio
    async def test_policy_override_advice_reads_the_head_build(self, seeded_with_crypto, admin_user):
        result = await _call(seeded_with_crypto, admin_user, "suggest_crypto_policy_override", {"project_id": _PROJECT})

        assert result["top_noisy_rules"] == [{"rule_id": _HEAD_CRYPTO_RULE, "findings": _HEAD_CRYPTO_RULE_HITS}]

    @pytest.mark.asyncio
    async def test_scan_findings_are_the_head_builds(self, seeded_with_crypto, admin_user):
        result = await _call(seeded_with_crypto, admin_user, "get_scan_findings", {"project_id": _PROJECT})

        assert {f["finding_id"] for f in result["findings"]} == {
            _HEAD_CVE,
            _WAIVED_FINDING_ID,
            _HEAD_CRYPTO_FINDING_ID,
        }

    @pytest.mark.asyncio
    async def test_scan_details_describe_the_head_build(self, seeded_with_crypto, admin_user):
        result = await _call(seeded_with_crypto, admin_user, "get_scan_details", {"project_id": _PROJECT})

        assert result["scan"]["id"] == _HEAD_SCAN
        assert result["scan"]["is_head"] is True


class TestScanScopedAnswersNameTheirBuild:
    @pytest.mark.asyncio
    async def test_an_explicit_scan_id_is_still_answered(self, seeded_with_crypto, admin_user):
        result = await _call(
            seeded_with_crypto,
            admin_user,
            "list_crypto_assets",
            {"project_id": _PROJECT, "scan_id": _DELETED_BRANCH_SCAN},
        )

        assert [i["name"] for i in result["items"]] == [_DELETED_BRANCH_CRYPTO_ASSET]

    @pytest.mark.asyncio
    async def test_an_explicit_scan_id_is_labelled_against_head(self, seeded_with_crypto, admin_user):
        """A relayed answer carries no chart beside it, so the build has to be in the answer."""
        result = await _call(
            seeded_with_crypto,
            admin_user,
            "get_scan_findings",
            {"project_id": _PROJECT, "scan_id": _DELETED_BRANCH_SCAN},
        )

        assert result["scan"]["is_head"] is False
        assert result["scan"]["branch"] == _DELETED_BRANCH

    @pytest.mark.asyncio
    async def test_a_queued_build_reports_the_status_that_explains_its_emptiness(self, seeded_with_crypto, admin_user):
        result = await _call(
            seeded_with_crypto,
            admin_user,
            "get_crypto_summary",
            {"project_id": _PROJECT, "scan_id": _QUEUED_SCAN},
        )

        assert result["total"] == 0
        assert result["scan"]["status"] == SCAN_STATUS_PENDING
        assert result["scan"]["is_head"] is False

    @pytest.mark.asyncio
    async def test_a_scan_outside_the_project_is_refused(self, seeded_with_crypto, admin_user):
        seeded_with_crypto.scans._docs[_FOREIGN_SCAN] = _scan(
            _FOREIGN_SCAN, _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 0, project_id="another-project"
        )

        result = await _call(
            seeded_with_crypto,
            admin_user,
            "get_crypto_summary",
            {"project_id": _PROJECT, "scan_id": _FOREIGN_SCAN},
        )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_a_project_with_no_usable_build_says_so_rather_than_reporting_zero(self, seeded, admin_user):
        _point_at(seeded, _QUEUED_SCAN)
        for scan_id in (_HEAD_SCAN, _OLDER_SCAN, _DELETED_BRANCH_SCAN):
            del seeded.scans._docs[scan_id]

        result = await _call(seeded, admin_user, "get_crypto_summary", {"project_id": _PROJECT})

        assert "error" in result


class TestScanHistoryNamesHead:
    @pytest.mark.asyncio
    async def test_the_head_row_is_labelled_and_the_newest_row_is_not(self, seeded, admin_user):
        _point_at(seeded, _QUEUED_SCAN)

        result = await _call(seeded, admin_user, "get_scan_history", {"project_id": _PROJECT})

        assert result["head_scan_id"] == _HEAD_SCAN
        assert [row["id"] for row in result["scans"] if row["is_head"]] == [_HEAD_SCAN]
        assert result["scans"][0]["is_head"] is False


class TestUnresolvableHead:
    @pytest.mark.asyncio
    async def test_a_project_whose_only_builds_are_unusable_reports_no_scan(self, seeded, admin_user):
        """Answering from a failed or queued scan would report an unanalysed build as clean."""
        _point_at(seeded, _QUEUED_SCAN)
        for scan_id in (_HEAD_SCAN, _OLDER_SCAN, _DELETED_BRANCH_SCAN):
            del seeded.scans._docs[scan_id]

        result = await _call(seeded, admin_user, "get_scan_findings", {"project_id": _PROJECT})

        assert result == {"error": _ERR_NO_SCAN_DATA}

    @pytest.mark.parametrize("tool_name", ["get_findings_by_severity", "get_findings_by_type", "get_dependency_tree"])
    @pytest.mark.asyncio
    async def test_a_project_without_a_head_is_not_reported_empty(self, seeded, admin_user, tool_name):
        """An empty breakdown or tree reads as a clean project; nothing has been analysed yet."""
        _point_at(seeded, _QUEUED_SCAN)
        for scan_id in (_HEAD_SCAN, _OLDER_SCAN, _DELETED_BRANCH_SCAN):
            del seeded.scans._docs[scan_id]

        result = await _call(seeded, admin_user, tool_name, {"project_id": _PROJECT})

        assert result == {"error": _ERR_NO_SCAN_DATA}
