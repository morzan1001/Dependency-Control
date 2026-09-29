from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.schemas.waiver import WaiverCreate
from app.services.stats import recalculate_project_stats
from app.services.waivers.matching import may_bind_signature, route_waiver
from tests.mocks.fake_mongo import FakeDatabase


_SIG = MatchSignature(rule_key="OPENGREP:r", file_key="a.py", anchor="fp1", anchor_kind="scanner_fp")


def _waiver(finding_type=None, match=None, scope="finding", **fields):
    return Waiver(reason="r", created_by="u", finding_type=finding_type, match=match, scope=scope, **fields)


class TestRouteWaiver:
    def test_a_waiver_without_a_signature_goes_by_its_criteria(self):
        assert route_waiver(_waiver(finding_type="sast", finding_id="OPENGREP-r-a.py-1")) == "query"
        assert route_waiver(_waiver(finding_type="license")) == "query"

    def test_a_finding_scope_waiver_with_a_signature_goes_by_signature(self):
        assert route_waiver(_waiver(match=_SIG)) == "signature"

    def test_a_widened_scope_keeps_its_criteria_whatever_signature_it_carries(self):
        assert route_waiver(_waiver(finding_type="sast", match=_SIG, scope="file")) == "query"
        assert route_waiver(_waiver(finding_type="sast", match=_SIG, scope="rule")) == "query"

    def test_a_vulnerability_id_wins_over_a_signature(self):
        assert route_waiver(_waiver(match=_SIG, vulnerability_id="CVE-1")) == "vulnerability"


class TestMayBindSignature:
    def test_an_unsigned_location_waiver_naming_a_finding_may_bind(self):
        assert may_bind_signature(_waiver(finding_type="secret", finding_id="SECRET-AWS-ab12")) is True
        assert may_bind_signature(_waiver(finding_id="SECRET-AWS-ab12")) is True

    def test_a_waiver_naming_no_finding_or_no_location_type_may_not(self):
        assert may_bind_signature(_waiver(finding_type="secret", package_name="a.yaml")) is False
        assert may_bind_signature(_waiver(finding_type="license", finding_id="LIC-GPL")) is False
        assert may_bind_signature(_waiver(finding_type="sast", finding_id="X", scope="file")) is False


# ---------------------------------------------------------------------------
# recalculate_project_stats must produce the same authoritative Stats as
# calculate_comprehensive_stats (severity counts excluding waived, saturating
# severity-weighted risk_score, populated enrichment fields).
# ---------------------------------------------------------------------------

PROJECT_ID = "proj-w4"
SCAN_ID = "scan-w4"


def _finding(
    _id,
    severity,
    *,
    cvss_score=None,
    risk_score=None,
    epss_score=None,
    is_kev=False,
    reachable=None,
    reachability_level="unknown",
    waived=False,
):
    details = {}
    if cvss_score is not None:
        details["cvss_score"] = cvss_score
    if risk_score is not None:
        details["risk_score"] = risk_score
    if epss_score is not None:
        details["epss_score"] = epss_score
    if is_kev:
        details["in_kev"] = True
    doc = {
        "_id": _id,
        "finding_id": _id,
        "scan_id": SCAN_ID,
        "type": "vulnerability",
        "severity": severity,
        "component": "pkg",
        "version": "1.0.0",
        "details": details,
        "waived": waived,
    }
    if reachable is not None:
        doc["reachable"] = reachable
        doc["reachability_level"] = reachability_level
    return doc


@pytest_asyncio.fixture
async def seeded_db():
    """A fake DB with a project, scan, and enriched findings (one waived)."""
    db = FakeDatabase()
    await db.projects.insert_one(
        {"_id": PROJECT_ID, "name": "proj-w4", "latest_scan_id": SCAN_ID, "deleted_branches": []}
    )
    await db.scans.insert_one({"_id": SCAN_ID, "project_id": PROJECT_ID, "status": "completed"})
    findings = [
        _finding(
            "f-crit",
            "CRITICAL",
            cvss_score=9.8,
            risk_score=95.0,
            epss_score=0.8,
            is_kev=True,
            reachable=True,
            reachability_level="confirmed",
        ),
        _finding("f-high", "HIGH", cvss_score=7.5, risk_score=60.0, epss_score=0.2, reachable=False),
        _finding("f-med", "MEDIUM", cvss_score=4.0, risk_score=20.0),
        # Covered by an active finding-level waiver below -> excluded from counts/scores.
        _finding("f-waived", "CRITICAL", cvss_score=9.0, risk_score=90.0),
    ]
    for f in findings:
        await db.findings.insert_one(f)
    # Active finding-scope waiver for f-waived; recalc resets+re-applies it.
    await db.waivers.insert_one(
        {
            "_id": "w-1",
            "project_id": PROJECT_ID,
            "finding_id": "f-waived",
            "scope": "finding",
            "finding_type": "vulnerability",
            "reason": "accepted",
            "created_by": "tester",
        }
    )
    return db


class TestRecalculateUnifiedStats:
    @pytest.mark.asyncio
    async def test_recalc_matches_comprehensive_stats(self, seeded_db):
        """recalc persists the SAME Stats as calculate_comprehensive_stats."""
        from app.services.analysis.stats import calculate_comprehensive_stats
        from app.services.stats import recalculate_project_stats

        # recalc resets + re-applies waivers, then computes stats. Comparing
        # comprehensive on the SAME post-recalc state proves identical filtering.
        result = await recalculate_project_stats(PROJECT_ID, seeded_db)
        comprehensive = await calculate_comprehensive_stats(seeded_db, SCAN_ID)

        assert result is not None
        # Severity counts identical and exclude the waived CRITICAL finding.
        assert result.critical == comprehensive.critical == 1
        assert result.high == comprehensive.high == 1
        assert result.medium == comprehensive.medium == 1
        assert result.risk_score == comprehensive.risk_score

    @pytest.mark.asyncio
    async def test_recalc_populates_enrichment_fields(self, seeded_db):
        """The unified path must populate the enrichment fields, not leave them at defaults."""
        from app.services.stats import recalculate_project_stats

        result = await recalculate_project_stats(PROJECT_ID, seeded_db)

        assert result is not None
        assert result.adjusted_risk_score != 0.0
        assert result.threat_intel is not None
        assert result.reachability is not None
        assert result.prioritized is not None
        # KEV + reachability enrichment actually reflected.
        assert result.threat_intel.kev_count == 1
        assert result.reachability.reachable_count == 1

    @pytest.mark.asyncio
    async def test_recalc_persists_to_scan_and_project(self, seeded_db):
        """Persisted scan.stats / project.stats carry the enrichment fields, not zeros."""
        from app.services.stats import recalculate_project_stats

        await recalculate_project_stats(PROJECT_ID, seeded_db)

        scan_doc = await seeded_db.scans.find_one({"_id": SCAN_ID})
        project_doc = await seeded_db.projects.find_one({"_id": PROJECT_ID})
        assert scan_doc["stats"]["threat_intel"] is not None
        assert scan_doc["stats"]["adjusted_risk_score"] != 0.0
        assert project_doc["stats"]["reachability"] is not None
        assert scan_doc["ignored_count"] == 1


# ---------------------------------------------------------------------------
# A waiver is a decision that holds now rather than a property of the build it
# was written against, so revoking one has to reach the build that is in
# production as well as the one at head.
# ---------------------------------------------------------------------------

RELEASE_SCAN_ID = "scan-w4-released"
PRODUCTION = "production"
RELEASED_AT = datetime(2026, 8, 1, tzinfo=timezone.utc)
SHIPPED_FINDING_ID = "f-shipped"
STALE_WAIVER_REASON = "compensating control: egress firewall"
CRITICALS_ON_THE_SHIPPED_BUILD = 1
CRITICALS_AT_HEAD = 1


@pytest_asyncio.fixture
async def released_db(seeded_db):
    """The head scan plus a shipped build whose one live CRITICAL still carries the waived flag a
    waiver nobody holds any more left on it."""
    await seeded_db.scans.insert_one(
        {"_id": RELEASE_SCAN_ID, "project_id": PROJECT_ID, "status": "completed", "is_release": True}
    )
    shipped = _finding(SHIPPED_FINDING_ID, "CRITICAL", cvss_score=9.1, risk_score=91.0, waived=True)
    shipped["scan_id"] = RELEASE_SCAN_ID
    shipped["waiver_reason"] = STALE_WAIVER_REASON
    await seeded_db.findings.insert_one(shipped)
    await seeded_db.releases.insert_one(
        {
            "_id": "rel-1",
            "project_id": PROJECT_ID,
            "environment": PRODUCTION,
            "scan_id": RELEASE_SCAN_ID,
            "released_at": RELEASED_AT,
        }
    )
    return seeded_db


def _record_restamps(monkeypatch) -> list[str]:
    import app.services.stats as stats_module

    restamped: list[str] = []
    original = stats_module.restamp_waivers

    async def recording(finding_repo, waiver_repo, scan_id, waivers):
        restamped.append(scan_id)
        await original(finding_repo, waiver_repo, scan_id, waivers)

    monkeypatch.setattr(stats_module, "restamp_waivers", recording)
    return restamped


class TestRecalculateReachesTheReleasedBuild:
    @pytest.mark.asyncio
    async def test_an_unchanged_waiver_set_restamps_nothing(self, released_db, monkeypatch):
        """A second trigger for the same change, or a recalc after an analysis already stamped, is a no-op."""
        await recalculate_project_stats(PROJECT_ID, released_db)
        restamped = _record_restamps(monkeypatch)

        assert await recalculate_project_stats(PROJECT_ID, released_db) is None

        assert restamped == []

    @pytest.mark.asyncio
    async def test_an_expiry_moved_to_another_future_date_restamps_nothing(self, released_db, monkeypatch):
        await recalculate_project_stats(PROJECT_ID, released_db)
        await released_db.waivers.update_one(
            {"_id": "w-1"}, {"$set": {"expiration_date": datetime(2099, 1, 1, tzinfo=timezone.utc)}}
        )
        restamped = _record_restamps(monkeypatch)

        await recalculate_project_stats(PROJECT_ID, released_db)

        assert restamped == []

    @pytest.mark.asyncio
    async def test_head_is_restamped_until_each_project_waiver_was_evaluated_there(self, released_db, monkeypatch):
        await recalculate_project_stats(PROJECT_ID, released_db)
        await released_db.waivers.update_one({"_id": "w-1"}, {"$set": {"last_eval_scan_id": "scan-before"}})
        restamped = _record_restamps(monkeypatch)

        await recalculate_project_stats(PROJECT_ID, released_db)

        assert restamped == [SCAN_ID]
        assert (await released_db.waivers.find_one({"_id": "w-1"}))["last_eval_scan_id"] == SCAN_ID

    @pytest.mark.asyncio
    async def test_a_changed_waiver_restamps_the_released_build_again(self, released_db, monkeypatch):
        await recalculate_project_stats(PROJECT_ID, released_db)
        await released_db.waivers.update_one({"_id": "w-1"}, {"$set": {"reason": "reworded"}})
        restamped = _record_restamps(monkeypatch)

        await recalculate_project_stats(PROJECT_ID, released_db)

        assert restamped == [SCAN_ID, RELEASE_SCAN_ID]

    @pytest.mark.asyncio
    async def test_a_revoked_waiver_stops_hiding_a_critical_that_is_in_production(self, released_db):
        """Nothing waives this finding any more, so "what is in production" must stop reading zero."""
        from app.repositories import FindingRepository

        await recalculate_project_stats(PROJECT_ID, released_db)

        shipped = await released_db.findings.find_one({"_id": SHIPPED_FINDING_ID})
        assert (shipped["waived"], shipped["waiver_reason"]) == (False, None)
        assert await FindingRepository(released_db).get_severity_distribution([RELEASE_SCAN_ID]) == {
            "CRITICAL": CRITICALS_ON_THE_SHIPPED_BUILD
        }

    @pytest.mark.asyncio
    async def test_the_shipped_builds_own_stats_are_rewritten_too(self, released_db):
        await recalculate_project_stats(PROJECT_ID, released_db)

        released_scan = await released_db.scans.find_one({"_id": RELEASE_SCAN_ID})
        assert released_scan["stats"]["critical"] == CRITICALS_ON_THE_SHIPPED_BUILD
        assert released_scan["ignored_count"] == 0

    @pytest.mark.asyncio
    async def test_the_project_tile_still_carries_head_rather_than_the_release(self, released_db):
        """Project.stats is head's; reaching the shipped build must not redirect it."""
        result = await recalculate_project_stats(PROJECT_ID, released_db)

        project = await released_db.projects.find_one({"_id": PROJECT_ID})
        assert result is not None and result.critical == CRITICALS_AT_HEAD
        assert project["stats"]["critical"] == CRITICALS_AT_HEAD

    @pytest.mark.asyncio
    async def test_head_owns_the_waiver_outcome_the_ui_shows(self, released_db):
        """Every pass records what the waiver suppressed; the one the user reads is head's."""
        await recalculate_project_stats(PROJECT_ID, released_db)

        waiver = await released_db.waivers.find_one({"_id": "w-1"})
        assert waiver["last_eval_scan_id"] == SCAN_ID

    @pytest.mark.asyncio
    async def test_the_released_build_stamps_the_waiver_without_moving_its_signature(self, released_db):
        at_head = MatchSignature(
            rule_key="bearer:r", file_key="a.py", anchor="c", anchor_kind="content_hash", content_hash="c", last_line=10
        )
        await _insert_finding(released_db, {"_id": "loc-head", "type": "sast", "match": at_head.model_dump()})
        await _insert_finding(
            released_db,
            {
                "_id": "loc-shipped",
                "scan_id": RELEASE_SCAN_ID,
                "type": "sast",
                "match": {**at_head.model_dump(), "last_line": 40},
            },
        )
        await released_db.waivers.insert_one(
            {
                "_id": "w-loc",
                "project_id": PROJECT_ID,
                "finding_type": "sast",
                "match": at_head.model_dump(),
                "status": "false_positive",
                "reason": "reviewed",
                "created_by": "tester",
            }
        )

        await recalculate_project_stats(PROJECT_ID, released_db)

        assert (await released_db.findings.find_one({"_id": "loc-shipped"}))["waived"] is True
        assert MatchSignature(**(await released_db.waivers.find_one({"_id": "w-loc"}))["match"]) == at_head

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", ["accepted_risk", "false_positive"])
    async def test_a_released_build_lagging_head_by_more_than_the_window_keeps_the_waiver(self, released_db, status):
        """The waiver's last_line tracks head; a shipped build whose code sits 60 lines higher is still waived."""
        at_head = MatchSignature(
            rule_key="bearer:r",
            file_key="a.py",
            anchor="c",
            anchor_kind="content_hash",
            content_hash="c",
            last_line=200,
        )
        await _insert_finding(released_db, {"_id": "loc-head", "type": "sast", "match": at_head.model_dump()})
        await _insert_finding(
            released_db,
            {
                "_id": "loc-shipped",
                "scan_id": RELEASE_SCAN_ID,
                "type": "sast",
                "match": {**at_head.model_dump(), "last_line": 140},
            },
        )
        await released_db.waivers.insert_one(
            {
                "_id": "w-loc",
                "project_id": PROJECT_ID,
                "finding_type": "sast",
                "match": at_head.model_dump(),
                "status": status,
                "reason": "reviewed",
                "created_by": "tester",
            }
        )

        await recalculate_project_stats(PROJECT_ID, released_db)

        assert (await released_db.findings.find_one({"_id": "loc-shipped"}))["waived"] is True


# ---------------------------------------------------------------------------
# A waiver with no matching criteria must NOT waive every finding: an empty
# waiver query ({}) would match all findings, so the restamp must
# skip criteria-less waivers.
# ---------------------------------------------------------------------------


FEATURE_SCAN_ID = "scan-w4-feature"


class TestRecalculateReachesEveryBranchTip:
    @pytest_asyncio.fixture
    async def branch_db(self, seeded_db):
        """A feature branch whose tip still carries the flag of a waiver nobody holds any more."""
        await seeded_db.scans.insert_one(
            {
                "_id": FEATURE_SCAN_ID,
                "project_id": PROJECT_ID,
                "branch": "feature/login",
                "status": "completed",
                "created_at": datetime(2026, 9, 1, tzinfo=timezone.utc),
            }
        )
        stale = _finding("f-feature", "CRITICAL", cvss_score=9.1, waived=True)
        stale["scan_id"] = FEATURE_SCAN_ID
        stale["waiver_reason"] = STALE_WAIVER_REASON
        await seeded_db.findings.insert_one(stale)
        return seeded_db

    @pytest.mark.asyncio
    async def test_a_revoked_waiver_stops_hiding_a_finding_on_another_branch(self, branch_db):
        await recalculate_project_stats(PROJECT_ID, branch_db)

        tip_finding = await branch_db.findings.find_one({"_id": "f-feature"})
        assert (tip_finding["waived"], tip_finding["waiver_reason"]) == (False, None)
        assert (await branch_db.scans.find_one({"_id": FEATURE_SCAN_ID}))["stats"]["critical"] == 1

    @pytest.mark.asyncio
    async def test_the_tip_stamps_the_waivers_without_recording_their_outcome(self, branch_db):
        await recalculate_project_stats(PROJECT_ID, branch_db)

        assert (await branch_db.waivers.find_one({"_id": "w-1"}))["last_eval_scan_id"] == SCAN_ID


class TestEmptyCriteriaWaiverDoesNotWaiveEverything:
    @pytest.mark.asyncio
    async def test_criteria_less_waiver_is_skipped(self, seeded_db):
        # A criteria-less waiver: only reason/created_by set. Goes to the legacy
        # path (finding_type None -> not a signature waiver, no vulnerability_id).
        await seeded_db.waivers.insert_one(
            {
                "_id": "w-empty",
                "project_id": PROJECT_ID,
                "scope": "finding",
                "reason": "blank automation payload",
                "created_by": "tester",
            }
        )

        result = await recalculate_project_stats(PROJECT_ID, seeded_db)

        assert result is not None
        # Only the properly-targeted waiver (w-1 -> f-waived) suppresses a finding.
        # The empty-criteria waiver must be skipped, NOT applied as match-all.
        assert result.critical == 1
        assert result.high == 1
        assert result.medium == 1

        scan_doc = await seeded_db.scans.find_one({"_id": SCAN_ID})
        assert scan_doc["ignored_count"] == 1

        # The non-targeted findings stay un-waived.
        for fid in ("f-crit", "f-high", "f-med"):
            doc = await seeded_db.findings.find_one({"_id": fid})
            assert doc["waived"] is False, f"{fid} was wrongly waived by empty-criteria waiver"


# ---------------------------------------------------------------------------
# Lock contention must be retried (bounded backoff), not dropped.
# ---------------------------------------------------------------------------


class TestLockContentionRetry:
    @pytest.mark.asyncio
    async def test_recalc_retries_lock_then_succeeds(self, seeded_db, monkeypatch):
        from app.repositories import DistributedLocksRepository

        calls = {"n": 0}
        real_acquire = DistributedLocksRepository.acquire_lock

        async def flaky_acquire(self, lock_name, holder_id, ttl_seconds=30):
            calls["n"] += 1
            if calls["n"] < 3:  # fail the first two attempts, succeed on the third
                return False
            return await real_acquire(self, lock_name, holder_id, ttl_seconds)

        monkeypatch.setattr(DistributedLocksRepository, "acquire_lock", flaky_acquire)

        slept = []

        async def fake_sleep(delay):
            slept.append(delay)

        monkeypatch.setattr("app.services.stats.asyncio.sleep", fake_sleep)

        result = await recalculate_project_stats(PROJECT_ID, seeded_db)

        assert result is not None  # recalc completed despite initial contention
        assert calls["n"] == 3  # retried until it won the lock
        # Backed off between the two failed attempts with exponential delays. (Filter
        # to our backoff values: patching asyncio.sleep is process-wide, so unrelated
        # asyncio.sleep(0) calls during recalc may also be recorded.)
        backoff_delays = [d for d in slept if d in (0.2, 0.4, 0.8, 1.6, 3.2)]
        assert backoff_delays == [pytest.approx(0.2), pytest.approx(0.4)]

    @pytest.mark.asyncio
    async def test_recalc_returns_none_after_exhausting_retries(self, seeded_db, monkeypatch):
        from app.repositories import DistributedLocksRepository

        calls = {"n": 0}

        async def always_fail(self, lock_name, holder_id, ttl_seconds=30):
            calls["n"] += 1
            return False

        monkeypatch.setattr(DistributedLocksRepository, "acquire_lock", always_fail)

        async def fake_sleep(delay):
            return None

        monkeypatch.setattr("app.services.stats.asyncio.sleep", fake_sleep)

        result = await recalculate_project_stats(PROJECT_ID, seeded_db)

        assert result is None  # gives up gracefully
        # Initial attempt + _LOCK_MAX_RETRIES retries.
        from app.services.stats import _LOCK_MAX_RETRIES

        assert calls["n"] == _LOCK_MAX_RETRIES + 1


@pytest.mark.asyncio
async def test_stats_count_findings_that_carry_no_waived_field():
    """One predicate form everywhere: a document without the field must count as not waived."""
    from app.services.analysis.stats import calculate_comprehensive_stats

    db = FakeDatabase()
    doc = _finding("f-nofield", "CRITICAL", cvss_score=9.1)
    del doc["waived"]
    await db.findings.insert_one(doc)

    stats = await calculate_comprehensive_stats(db, SCAN_ID)

    assert stats.critical == 1


# ---------------------------------------------------------------------------
# What a waiver's own fields are allowed to narrow the finding query down to.
# ---------------------------------------------------------------------------


async def _insert_finding(db, doc):
    base = {
        "scan_id": SCAN_ID,
        "severity": "HIGH",
        "details": {},
        "waived": False,
    }
    base.update(doc)
    base.setdefault("finding_id", base["_id"])
    await db.findings.insert_one(base)


class TestWhatAWaiverMatchesOn:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("finding_type", ["sast", None])
    async def test_a_global_rule_waiver_waives_only_its_rule(self, seeded_db, finding_type):
        for fid, rule in (("f-rule-x", "X"), ("f-rule-y", "Y")):
            await _insert_finding(
                seeded_db,
                {"_id": fid, "type": "sast", "component": "a.py", "details": {"sast_findings": [{"id": rule}]}},
            )
        await seeded_db.waivers.insert_one(
            {
                "_id": "w-rule-x",
                "project_id": None,
                "scope": "rule",
                "rule_id": "X",
                "finding_type": finding_type,
                "reason": "rule X accepted everywhere",
                "created_by": "admin",
            }
        )

        await recalculate_project_stats(PROJECT_ID, seeded_db)

        assert (await seeded_db.findings.find_one({"_id": "f-rule-x"}))["waived"] is True
        assert (await seeded_db.findings.find_one({"_id": "f-rule-y"}))["waived"] is False

    @pytest.mark.asyncio
    async def test_an_unknown_package_version_is_a_placeholder_and_not_a_version_to_match(self, seeded_db):
        """Scanners write "Unknown" where they have no version; matching on it literally would
        leave the waiver suppressing nothing."""
        await _insert_finding(
            seeded_db,
            {"_id": "f-ghost", "type": "vulnerability", "component": "ghost-pkg", "version": "2.0.0"},
        )
        waiver_in = WaiverCreate(
            project_id=PROJECT_ID,
            finding_type="vulnerability",
            package_name="ghost-pkg",
            package_version="Unknown",
            reason="no version recorded by the scanner",
        )
        await seeded_db.waivers.insert_one(
            Waiver(**waiver_in.model_dump(), created_by="tester").model_dump(by_alias=True)
        )

        await recalculate_project_stats(PROJECT_ID, seeded_db)

        assert (await seeded_db.findings.find_one({"_id": "f-ghost"}))["waived"] is True
        assert (await seeded_db.findings.find_one({"_id": "f-high"}))["waived"] is False

    @pytest.mark.asyncio
    async def test_a_rule_scope_waiver_reaches_the_same_rule_in_another_file(self, seeded_db):
        """Rule scope means "this rule everywhere"; keeping the waiver's own file in the query
        would silently degrade it to file scope."""
        rule = {"sast_findings": [{"id": "weak_rng"}]}
        await _insert_finding(
            seeded_db,
            {"_id": "f-rule-a", "type": "sast", "finding_id": "BEARER-weak_rng-src/a.js-10", "component": "src/a.js"}
            | {"details": rule},
        )
        await _insert_finding(
            seeded_db,
            {"_id": "f-rule-b", "type": "sast", "finding_id": "BEARER-weak_rng-src/b.js-42", "component": "src/b.js"}
            | {"details": rule},
        )
        await seeded_db.waivers.insert_one(
            {
                "_id": "w-rule",
                "project_id": PROJECT_ID,
                "scope": "rule",
                "rule_id": "weak_rng",
                "finding_type": "sast",
                "finding_id": "BEARER-weak_rng-src/a.js-10",
                "package_name": "src/a.js",
                "reason": "rule accepted project-wide",
                "created_by": "tester",
            }
        )

        await recalculate_project_stats(PROJECT_ID, seeded_db)

        assert (await seeded_db.findings.find_one({"_id": "f-rule-a"}))["waived"] is True
        assert (await seeded_db.findings.find_one({"_id": "f-rule-b"}))["waived"] is True

    @pytest.mark.asyncio
    async def test_a_file_scope_waiver_on_an_id_that_carries_no_line_number_still_matches_it(self, seeded_db):
        """Only a trailing line number is a line number: stripping the last segment of any
        hyphenated id turns the waiver into a regex that matches nothing."""
        await _insert_finding(
            seeded_db,
            {
                "_id": "f-license",
                "type": "license",
                "finding_id": "LIC-GPL-2.0-only",
                "component": "pkg-x",
                "severity": "MEDIUM",
            },
        )
        await seeded_db.waivers.insert_one(
            {
                "_id": "w-license-file",
                "project_id": PROJECT_ID,
                "scope": "file",
                "finding_type": "license",
                "finding_id": "LIC-GPL-2.0-only",
                "package_name": "pkg-x",
                "reason": "copyleft reviewed",
                "created_by": "tester",
            }
        )

        await recalculate_project_stats(PROJECT_ID, seeded_db)

        assert (await seeded_db.findings.find_one({"_id": "f-license"}))["waived"] is True
