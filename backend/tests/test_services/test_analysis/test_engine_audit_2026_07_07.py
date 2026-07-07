"""Audit 2026-07-07 remediation for backend/app/services/analysis/engine.py.

Covers four verified findings:
  1. Waived findings must be excluded from notifications/webhooks (_filter_out_waived_findings).
  2. Late / out-of-order scan completion must not clobber a newer project latest_scan_id/stats
     (_should_update_project_latest_scan / _finalize_scan_and_project).
  3. epss_kev/reachability + crypto post-processor rows must be cleaned up and never treated as
     external / carried-over results (_cleanup_analyzer_names, _aggregate_external_results,
     _carry_over_external_results).
  4. TOCTOU: a scanner result racing finalize must reschedule instead of being silently dropped
     (_finalize_scan_and_project with external_load_start).
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import (
    _aggregate_external_results,
    _carry_over_external_results,
    _cleanup_analyzer_names,
    _filter_out_waived_findings,
    _finalize_scan_and_project,
    _should_update_project_latest_scan,
)
from app.services.analysis.registry import CRYPTO_ANALYZERS


class _AsyncIter:
    """Minimal async cursor stand-in for motor's find()."""

    def __init__(self, docs):
        self._docs = list(docs)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._docs:
            raise StopAsyncIteration
        return self._docs.pop(0)


class _FakeFindings:
    def __init__(self, waived_docs):
        self._waived_docs = waived_docs
        self.last_query = None

    def with_options(self, read_preference=None):
        return self

    def find(self, query, projection=None):
        self.last_query = query
        return _AsyncIter(self._waived_docs)


# --------------------------------------------------------------------------- #
# Finding 1: waived findings excluded from notifications
# --------------------------------------------------------------------------- #
class TestFilterOutWaivedFindings:
    def test_waived_finding_is_excluded(self):
        findings = [SimpleNamespace(id="F1"), SimpleNamespace(id="F2"), SimpleNamespace(id="F3")]
        db = SimpleNamespace(findings=_FakeFindings([{"finding_id": "F2"}]))

        result = asyncio.run(_filter_out_waived_findings(findings, "scan-1", db))

        ids = [f.id for f in result]
        assert ids == ["F1", "F3"], f"waived F2 must be dropped, got {ids}"

    def test_no_waivers_returns_original(self):
        findings = [SimpleNamespace(id="F1")]
        db = SimpleNamespace(findings=_FakeFindings([]))

        result = asyncio.run(_filter_out_waived_findings(findings, "scan-1", db))

        assert result is findings  # same object, no filtering work done

    def test_query_filters_on_scan_and_waived(self):
        db = SimpleNamespace(findings=_FakeFindings([{"finding_id": "F1"}]))
        asyncio.run(_filter_out_waived_findings([SimpleNamespace(id="F1")], "scan-9", db))
        assert db.findings.last_query == {"scan_id": "scan-9", "waived": True}


# --------------------------------------------------------------------------- #
# Finding 2: out-of-order completion must not clobber a newer latest scan
# --------------------------------------------------------------------------- #
class TestShouldUpdateProjectLatestScan:
    def _run(self, this_created, current_latest_id, current_created):
        scan_doc = SimpleNamespace(created_at=this_created)
        project_repo = SimpleNamespace(
            get_by_id_strong=AsyncMock(return_value=SimpleNamespace(latest_scan_id=current_latest_id))
        )
        scan_repo = SimpleNamespace(
            get_by_id_strong=AsyncMock(return_value=SimpleNamespace(created_at=current_created))
        )
        return asyncio.run(
            _should_update_project_latest_scan("scan-new", scan_doc, "proj-1", scan_repo, project_repo)
        )

    def test_stale_scan_does_not_overwrite_newer_latest(self):
        now = datetime.now(timezone.utc)
        older = now - timedelta(days=7)
        # This scan (older) completing late must NOT overwrite the newer current latest.
        assert self._run(older, "scan-newer", now) is False

    def test_newer_scan_updates(self):
        now = datetime.now(timezone.utc)
        older = now - timedelta(days=7)
        assert self._run(now, "scan-older", older) is True

    def test_no_existing_latest_updates(self):
        now = datetime.now(timezone.utc)
        assert self._run(now, None, None) is True

    def test_naive_created_at_compared_as_utc(self):
        # Stored datetimes are often tz-naive UTC; comparison must not raise.
        naive_old = datetime(2020, 1, 1)
        aware_new = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert self._run(naive_old, "scan-newer", aware_new) is False


class TestFinalizeGuardsProjectUpdate:
    def _stats(self):
        return SimpleNamespace(model_dump=lambda: {"x": 1})

    def test_stale_completion_skips_project_update(self):
        now = datetime.now(timezone.utc)
        older = now - timedelta(days=7)
        project_update = AsyncMock()
        scan_repo = SimpleNamespace(
            update_raw=AsyncMock(),
            get_by_id_strong=AsyncMock(return_value=SimpleNamespace(created_at=now)),
        )
        project_repo = SimpleNamespace(
            update_raw=project_update,
            get_by_id_strong=AsyncMock(return_value=SimpleNamespace(latest_scan_id="scan-newer")),
        )
        scan_doc = SimpleNamespace(is_rescan=False, original_scan_id=None, created_at=older)

        finalized = asyncio.run(
            _finalize_scan_and_project(
                "scan-stale", scan_doc, "proj-1", 5, 0, self._stats(), {"status": "completed"},
                scan_repo, project_repo,
            )
        )

        assert finalized is True
        # scan row itself still updated, but project latest not clobbered by the stale scan.
        scan_repo.update_raw.assert_awaited()
        project_update.assert_not_awaited()


# --------------------------------------------------------------------------- #
# Finding 3: post-processor / crypto rows cleaned up & not treated as external
# --------------------------------------------------------------------------- #
class TestCleanupAnalyzerNames:
    def test_includes_post_processors_and_crypto(self):
        names = set(_cleanup_analyzer_names([]))
        assert "epss_kev" in names
        assert "reachability" in names
        assert CRYPTO_ANALYZERS.issubset(names)


class _FakeResult:
    def __init__(self, analyzer_name, result):
        self.analyzer_name = analyzer_name
        self.result = result


class TestAggregateExternalSkipsPostProcessors:
    def test_epss_kev_and_reachability_not_aggregated(self, monkeypatch):
        # analyzers empty -> only _POST_PROCESSOR_ANALYZERS membership can exclude these.
        monkeypatch.setattr("app.services.analysis.engine.analyzers", {})
        aggregator = ResultAggregator()

        calls = []
        orig = aggregator.aggregate

        def spy(analyzer_name, result, source=None):
            calls.append(analyzer_name)
            return orig(analyzer_name, result, source=source)

        aggregator.aggregate = spy

        results = [
            _FakeResult("epss_kev", {"summary": 1}),
            _FakeResult("reachability", {"summary": 1}),
        ]
        result_repo = SimpleNamespace(find_by_scan=AsyncMock(return_value=results))
        results_summary: list = []

        asyncio.run(_aggregate_external_results(aggregator, result_repo, "scan-1", results_summary))

        assert calls == [], f"post-processor rows must not be aggregated; got {calls}"
        assert results_summary == [], f"no spurious Success lines expected; got {results_summary}"


class TestCarryOverExcludesPostProcessors:
    def test_nin_includes_post_processors(self, monkeypatch):
        captured = {}

        class _FakeRepo:
            def __init__(self, _db):
                pass

            async def find_many(self, query, limit=0):
                captured["query"] = query
                return []

        monkeypatch.setattr("app.repositories.AnalysisResultRepository", _FakeRepo)

        scan_doc = SimpleNamespace(is_rescan=True, original_scan_id="orig-1")
        asyncio.run(_carry_over_external_results("scan-2", scan_doc, SimpleNamespace()))

        nin = captured["query"]["analyzer_name"]["$nin"]
        assert "epss_kev" in nin
        assert "reachability" in nin


# --------------------------------------------------------------------------- #
# Finding 4: TOCTOU — late result racing finalize reschedules, not drops
# --------------------------------------------------------------------------- #
class TestFinalizeTOCTOU:
    def _stats(self):
        return SimpleNamespace(model_dump=lambda: {"x": 1})

    def test_late_result_reschedules_instead_of_completing(self):
        # find_one_and_update returns None -> the last_result_at guard failed (a scanner
        # result arrived after external load began).
        collection = SimpleNamespace(find_one_and_update=AsyncMock(return_value=None))
        update_raw = AsyncMock()
        scan_repo = SimpleNamespace(collection=collection, update_raw=update_raw)
        project_update = AsyncMock()
        project_repo = SimpleNamespace(update_raw=project_update, get_by_id_strong=AsyncMock())
        scan_doc = SimpleNamespace(is_rescan=False, original_scan_id=None, created_at=None)

        finalized = asyncio.run(
            _finalize_scan_and_project(
                "scan-1", scan_doc, "proj-1", 5, 0, self._stats(), {"status": "completed"},
                scan_repo, project_repo,
                external_load_start=datetime.now(timezone.utc),
            )
        )

        assert finalized is False
        # Rescheduled to pending with a retry bump.
        reschedule = update_raw.await_args.args[1]
        assert reschedule["$set"]["status"] == "pending"
        assert reschedule["$inc"]["retry_count"] == 1
        # Must NOT have touched the project (would publish stale/incomplete stats).
        project_update.assert_not_awaited()

    def test_clean_completion_commits(self):
        collection = SimpleNamespace(find_one_and_update=AsyncMock(return_value={"_id": "scan-1"}))
        scan_repo = SimpleNamespace(
            collection=collection,
            update_raw=AsyncMock(),
            get_by_id_strong=AsyncMock(),
        )
        project_update = AsyncMock()
        project_repo = SimpleNamespace(
            update_raw=project_update,
            get_by_id_strong=AsyncMock(return_value=SimpleNamespace(latest_scan_id=None)),
        )
        scan_doc = SimpleNamespace(is_rescan=False, original_scan_id=None, created_at=None)

        finalized = asyncio.run(
            _finalize_scan_and_project(
                "scan-1", scan_doc, "proj-1", 5, 0, self._stats(), {"status": "completed"},
                scan_repo, project_repo,
                external_load_start=datetime.now(timezone.utc),
            )
        )

        assert finalized is True
        collection.find_one_and_update.assert_awaited_once()
        project_update.assert_awaited_once()
