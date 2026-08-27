"""Tests for the per-scan update-frequency rollup writer."""

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.core.metrics import update_frequency_delta_writes_total
from app.services.update_frequency_rollup import record_scan_update_delta
from tests.mocks.fake_mongo import FakeDatabase

PROJECT = "proj-1"
BRANCH = "main"
T0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _at(hours: int) -> datetime:
    return T0 + timedelta(hours=hours)


def _dep(scan_id: str, name: str, version: str, ecosystem: str = "pypi") -> dict[str, Any]:
    return {
        "_id": f"{scan_id}:{name}:{version}",
        "scan_id": scan_id,
        "project_id": PROJECT,
        "name": name,
        "version": version,
        # SBOM component type; the purl type is what the rollup must classify by.
        "type": "library",
        "purl": f"pkg:{ecosystem}/{name}@{version}",
        "license": "MIT",
        "locations": ["/app/requirements.txt"],
    }


async def _seed_scan(
    db: FakeDatabase,
    scan_id: str,
    created_at: datetime,
    deps: list[dict[str, Any]],
    outdated: tuple[str, ...] | None = None,
    status: str = "completed",
    is_rescan: bool = False,
    branch: str = BRANCH,
    project_id: str = PROJECT,
) -> None:
    """``outdated=None`` seeds no outdated analysis at all; ``()`` seeds one that found nothing."""
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "branch": branch,
            "created_at": created_at,
            "commit_hash": f"commit-{scan_id}",
            "status": status,
            "is_rescan": is_rescan,
            # Bulk the rollup must not pull into memory.
            "findings_summary": [{"id": f"CVE-{i}", "description": "x" * 200} for i in range(50)],
            "sbom_refs": [{"file_id": "gridfs-1", "filename": "sbom.json"}],
        }
    )
    for dep in deps:
        await db.dependencies.insert_one({**dep, "project_id": project_id})
    if outdated is not None:
        await db.analysis_results.insert_one(
            {
                "_id": f"{scan_id}:outdated",
                "scan_id": scan_id,
                "analyzer_name": "outdated_packages",
                "result": {
                    "outdated_dependencies": [
                        {
                            "component": name,
                            "current_version": "0.0.1",
                            "latest_version": "9.9.9",
                            "purl": f"pkg:pypi/{name}@0.0.1",
                            "severity": "info",
                            "message": "Update available: 9.9.9",
                        }
                        for name in outdated
                    ],
                    "ahead_of_default": [],
                    "yanked_versions": [],
                },
            }
        )


async def _delta(db: FakeDatabase, scan_id: str) -> dict[str, Any] | None:
    return await db.scan_update_deltas.find_one({"_id": scan_id})


def _counter(result: str) -> float:
    return update_frequency_delta_writes_total.labels(result=result)._value.get()


class TestBaseline:
    @pytest.mark.asyncio
    async def test_first_scan_is_baseline(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0"), _dep("s1", "flask", "3.0.0")], ("flask",))

        await record_scan_update_delta(db, "s1")

        doc = await _delta(db, "s1")
        assert doc is not None
        assert doc["is_baseline"] is True
        assert doc["prev_scan_id"] is None
        assert doc["prev_created_at"] is None
        assert doc["dep_count"] == 2
        assert doc["total_updates"] == 0
        assert doc["updates"] == {"patch": 0, "minor": 0, "major": 0, "unknown": 0, "downgrade": 0}
        assert doc["outdated_count"] == 1
        assert doc["outdated_added"] == []
        assert doc["outdated_resolved"] == []
        assert doc["eco"] == {"pypi": 2}
        assert doc["error"] is None
        assert doc["schema_version"] == 1
        assert doc["project_id"] == PROJECT
        assert doc["branch"] == BRANCH
        assert doc["commit_hash"] == "commit-s1"
        # Motor returns naive UTC; that is what the document carries after the round trip.
        assert doc["scan_created_at"] == _at(0).replace(tzinfo=None)

    @pytest.mark.asyncio
    async def test_outdated_set_is_written_separately(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], ("requests", "flask"))

        await record_scan_update_delta(db, "s1")

        outdated_set = await db.scan_outdated_sets.find_one({"_id": "s1"})
        assert outdated_set is not None
        assert outdated_set["names"] == ["flask", "requests"]
        assert outdated_set["n"] == 2
        assert outdated_set["scan_created_at"] == _at(0).replace(tzinfo=None)
        assert outdated_set["schema_version"] == 1

    @pytest.mark.asyncio
    async def test_scan_without_dependencies_is_recorded_with_zero_deps(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [])

        await record_scan_update_delta(db, "s1")

        doc = await _delta(db, "s1")
        assert doc is not None
        assert doc["dep_count"] == 0
        assert doc["is_baseline"] is True
        assert doc["eco"] == {}


class TestDiff:
    @pytest.mark.asyncio
    async def test_counts_and_sample_of_a_normal_diff(self):
        db = FakeDatabase()
        await _seed_scan(
            db,
            "s1",
            _at(0),
            [
                _dep("s1", "requests", "2.0.0"),
                _dep("s1", "flask", "3.0.0"),
                _dep("s1", "click", "8.1.0"),
                _dep("s1", "left", "1.0.0"),
            ],
            ("requests", "left"),
        )
        await _seed_scan(
            db,
            "s2",
            _at(1),
            [
                _dep("s2", "requests", "2.0.1"),  # patch
                _dep("s2", "flask", "3.1.0"),  # minor
                _dep("s2", "click", "9.0.0"),  # major
                _dep("s2", "added", "1.0.0"),  # new package, not an update
            ],
            ("click",),
        )

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["is_baseline"] is False
        assert doc["prev_scan_id"] == "s1"
        assert doc["prev_created_at"] == _at(0).replace(tzinfo=None)
        assert doc["updates"] == {"patch": 1, "minor": 1, "major": 1, "unknown": 0, "downgrade": 0}
        assert doc["total_updates"] == 3
        assert doc["dep_count"] == 4
        # "left" disappeared instead of being updated, so it is not resolved.
        assert doc["outdated_added"] == ["click"]
        assert doc["outdated_resolved"] == ["requests"]
        sample = {entry["n"]: entry for entry in doc["updates_sample"]}
        assert sample["click"]["k"] == "major"
        assert sample["click"]["ov"] == "8.1.0"
        assert sample["click"]["nv"] == "9.0.0"
        assert sample["click"]["p"] == "pkg:pypi/click@9.0.0"
        assert sample["click"]["t"] == "pypi"
        assert sample["requests"]["wo"] is True
        assert sample["flask"]["wo"] is False

    @pytest.mark.asyncio
    async def test_downgrade_is_recorded_but_not_counted_as_an_update(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.5.0"), _dep("s1", "flask", "3.0.0")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.4.0"), _dep("s2", "flask", "3.0.1")])

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["updates"]["downgrade"] == 1
        assert doc["updates"]["patch"] == 1
        assert doc["total_updates"] == 1
        kinds = {entry["n"]: entry["k"] for entry in doc["updates_sample"]}
        assert kinds == {"requests": "downgrade", "flask": "patch"}

    @pytest.mark.asyncio
    async def test_unchanged_versions_produce_no_updates(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "v2.0.0")])

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["total_updates"] == 0
        assert doc["updates_sample"] == []

    @pytest.mark.asyncio
    async def test_same_name_in_two_ecosystems_is_not_an_update(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "cache", "1.0.0", ecosystem="npm")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "cache", "2.0.0", ecosystem="pypi")])

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["total_updates"] == 0
        assert doc["eco"] == {"pypi": 1}

    @pytest.mark.asyncio
    async def test_duplicate_versions_in_one_scan_fold_to_the_highest(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")])
        await _seed_scan(
            db,
            "s2",
            _at(1),
            [_dep("s2", "requests", "2.1.0"), _dep("s2", "requests", "2.0.5")],
        )

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["dep_count"] == 1
        assert doc["updates"]["minor"] == 1

    @pytest.mark.asyncio
    async def test_sample_is_capped_at_twenty_deterministically(self):
        db = FakeDatabase()
        old = [_dep("s1", f"pkg{i:03d}", "1.0.0") for i in range(30)]
        new = [_dep("s2", f"pkg{i:03d}", "1.0.1") for i in range(30)]
        new[7]["version"] = "2.0.0"
        new[7]["purl"] = "pkg:pypi/pkg007@2.0.0"
        await _seed_scan(db, "s1", _at(0), old)
        await _seed_scan(db, "s2", _at(1), new)

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["total_updates"] == 30
        assert len(doc["updates_sample"]) == 20
        # Biggest jump first, then by name, so a recomputation keeps the same 20.
        assert doc["updates_sample"][0]["n"] == "pkg007"
        expected = [f"pkg{i:03d}" for i in range(20) if i != 7]
        assert [entry["n"] for entry in doc["updates_sample"][1:]] == expected


class TestOutdatedMeasurement:
    """A missing analysis must never read as "nothing is outdated"."""

    @pytest.mark.asyncio
    async def test_missing_analysis_resolves_nothing(self):
        db = FakeDatabase()
        deps = [("requests", "2.0.0"), ("flask", "3.0.0")]
        await _seed_scan(db, "s1", _at(0), [_dep("s1", *d) for d in deps], ("requests", "flask"))
        await _seed_scan(db, "s2", _at(1), [_dep("s2", *d) for d in deps], None)

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["outdated_count"] is None
        assert doc["outdated_resolved"] == []
        assert doc["outdated_added"] == []
        assert await db.scan_outdated_sets.find_one({"_id": "s2"}) is None

    @pytest.mark.asyncio
    async def test_analysis_that_found_nothing_resolves_the_backlog(self):
        db = FakeDatabase()
        deps = [("requests", "2.0.0"), ("flask", "3.0.0")]
        await _seed_scan(db, "s1", _at(0), [_dep("s1", *d) for d in deps], ("requests", "flask"))
        await _seed_scan(db, "s2", _at(1), [_dep("s2", *d) for d in deps], ())

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["outdated_count"] == 0
        assert doc["outdated_resolved"] == ["flask", "requests"]
        assert (await db.scan_outdated_sets.find_one({"_id": "s2"}))["names"] == []

    @pytest.mark.asyncio
    async def test_failed_analyzer_result_is_not_a_measurement(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], ("requests",))
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0")], None)
        # A CLI/HTTP analyzer failure is stored as a result without the outdated list.
        await db.analysis_results.insert_one(
            {
                "_id": "s2:outdated",
                "scan_id": "s2",
                "analyzer_name": "outdated_packages",
                "result": {"error": "deps.dev unreachable"},
            }
        )

        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["outdated_count"] is None
        assert doc["outdated_resolved"] == []

    @pytest.mark.asyncio
    async def test_unmeasured_predecessor_makes_the_whole_backlog_newly_observed(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0"), _dep("s1", "flask", "3.0.0")], None)
        await _seed_scan(
            db,
            "s2",
            _at(1),
            [_dep("s2", "requests", "2.1.0"), _dep("s2", "flask", "3.0.0")],
            ("requests", "flask"),
        )

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["outdated_count"] == 2
        # Without an earlier measurement there is nothing to subtract, so the
        # fold sees the whole set instead of losing it from the denominator.
        assert doc["outdated_added"] == ["flask", "requests"]
        # Whether the predecessor considered them outdated is unknown.
        assert doc["outdated_resolved"] == []
        assert doc["updates_sample"][0]["wo"] is False

    @pytest.mark.asyncio
    async def test_no_resolution_is_recorded_across_an_unmeasured_predecessor(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], None)
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.1.0")], ())

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["outdated_count"] == 0
        assert doc["outdated_added"] == []
        assert doc["outdated_resolved"] == []

    @pytest.mark.asyncio
    async def test_recomputation_without_an_analysis_drops_the_earlier_outdated_set(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], ("requests",))
        await record_scan_update_delta(db, "s1")
        assert await db.scan_outdated_sets.find_one({"_id": "s1"}) is not None

        # A re-ingest whose outdated analyzer never ran leaves no result behind.
        await db.analysis_results.delete_many({"scan_id": "s1"})
        await record_scan_update_delta(db, "s1")

        doc = await _delta(db, "s1")
        assert doc is not None
        assert doc["outdated_count"] is None
        assert await db.scan_outdated_sets.find_one({"_id": "s1"}) is None


class TestProjectSeparation:
    """Every project has a branch named ``main``; only the project filter keeps them apart."""

    @pytest.mark.asyncio
    async def test_other_project_is_not_a_predecessor(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _at(0), [_dep("a1", "requests", "1.0.0")], project_id="proj-A")
        await _seed_scan(db, "b1", _at(1), [_dep("b1", "requests", "9.0.0")], project_id="proj-B")

        await record_scan_update_delta(db, "a1")
        await record_scan_update_delta(db, "b1")

        doc = await _delta(db, "b1")
        assert doc is not None
        assert doc["is_baseline"] is True
        assert doc["prev_scan_id"] is None
        assert doc["total_updates"] == 0

    @pytest.mark.asyncio
    async def test_other_project_is_not_repaired_as_a_successor(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _at(0), [_dep("a1", "requests", "1.0.0")], project_id="proj-A")
        await _seed_scan(db, "a2", _at(2), [_dep("a2", "requests", "2.0.0")], project_id="proj-A")
        await _seed_scan(db, "b1", _at(1), [_dep("b1", "requests", "9.0.0")], project_id="proj-B")

        await record_scan_update_delta(db, "a1")
        await record_scan_update_delta(db, "a2")
        before = dict(await _delta(db, "a2"))  # type: ignore[arg-type]

        await record_scan_update_delta(db, "b1")

        assert await _delta(db, "a2") == before


class TestSameTimestamp:
    """BSON keeps milliseconds, so two pipelines can land on the same instant."""

    @pytest.mark.asyncio
    async def test_the_second_scan_of_one_millisecond_still_gets_a_predecessor(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")])
        await _seed_scan(db, "s2", _at(0), [_dep("s2", "requests", "2.0.0")])

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        first = await _delta(db, "s1")
        second = await _delta(db, "s2")
        assert first is not None
        assert second is not None
        assert first["is_baseline"] is True
        assert second["prev_scan_id"] == "s1"
        assert second["updates"]["major"] == 1

    @pytest.mark.asyncio
    async def test_the_pair_is_repaired_when_it_arrives_in_reverse(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")])
        await _seed_scan(db, "s2", _at(0), [_dep("s2", "requests", "2.0.0")])

        await record_scan_update_delta(db, "s2")
        await record_scan_update_delta(db, "s1")

        second = await _delta(db, "s2")
        assert second is not None
        assert second["prev_scan_id"] == "s1"
        assert second["updates"]["major"] == 1
        # A cycle would make both scans point at each other.
        assert (await _delta(db, "s1"))["prev_scan_id"] is None


class TestPredecessorSelection:
    @pytest.mark.asyncio
    async def test_sbom_less_scan_is_skipped_as_predecessor(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")])
        await _seed_scan(db, "s2", _at(1), [])
        await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "3.0.0")])

        for scan_id in ("s1", "s2", "s3"):
            await record_scan_update_delta(db, scan_id)

        empty = await _delta(db, "s2")
        assert empty is not None
        assert empty["dep_count"] == 0
        assert empty["prev_scan_id"] == "s1"

        doc = await _delta(db, "s3")
        assert doc is not None
        assert doc["prev_scan_id"] == "s1"
        assert doc["updates"]["major"] == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("surviving_deps", [0, 1], ids=["wiped", "partly_rewritten"])
    async def test_predecessor_whose_dependencies_changed_is_demoted(self, surviving_deps: int):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0"), _dep("s1", "flask", "1.0.0")], ())
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0"), _dep("s2", "flask", "2.0.0")], ())
        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        # A re-ingest of s2 died between deleting and rewriting its dependencies.
        await db.dependencies.delete_many({"scan_id": "s2"})
        for dep in [_dep("s2", "requests", "2.0.0")][:surviving_deps]:
            await db.dependencies.insert_one(dep)
        await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "3.0.0"), _dep("s3", "flask", "3.0.0")], ())

        await record_scan_update_delta(db, "s3")

        doc = await _delta(db, "s3")
        assert doc is not None
        assert doc["prev_scan_id"] == "s1"
        assert doc["updates"]["major"] == 2
        demoted = await _delta(db, "s2")
        assert demoted is not None
        assert "dependencies changed" in demoted["error"]
        assert demoted["dep_count"] == 0
        assert await db.scan_outdated_sets.find_one({"_id": "s2"}) is None

    @pytest.mark.asyncio
    async def test_other_branch_is_not_a_predecessor(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], branch="feature")
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "3.0.0")])

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["is_baseline"] is True
        assert doc["total_updates"] == 0

    @pytest.mark.asyncio
    async def test_error_document_is_not_a_predecessor(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.1.0")])
        await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "2.2.0")])

        await record_scan_update_delta(db, "s1")
        with _failing_dependency_reads(db):
            await record_scan_update_delta(db, "s2")
        await record_scan_update_delta(db, "s3")

        doc = await _delta(db, "s3")
        assert doc is not None
        assert doc["prev_scan_id"] == "s1"
        assert doc["updates"]["minor"] == 1


class TestOutOfOrderArrival:
    @pytest.mark.asyncio
    async def test_successor_is_recomputed_against_the_late_scan(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")], ("requests",))
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0")], ("requests",))
        await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "2.0.1")], ())

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s3")

        stale = await _delta(db, "s3")
        assert stale is not None
        assert stale["prev_scan_id"] == "s1"
        assert stale["updates"]["major"] == 1

        await record_scan_update_delta(db, "s2")

        repaired = await _delta(db, "s3")
        assert repaired is not None
        assert repaired["prev_scan_id"] == "s2"
        assert repaired["prev_created_at"] == _at(1).replace(tzinfo=None)
        assert repaired["updates"] == {"patch": 1, "minor": 0, "major": 0, "unknown": 0, "downgrade": 0}
        assert repaired["outdated_resolved"] == ["requests"]

    @pytest.mark.asyncio
    async def test_repair_walks_past_an_sbom_less_successor(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0")])
        await _seed_scan(db, "s3", _at(2), [])
        await _seed_scan(db, "s4", _at(3), [_dep("s4", "requests", "2.0.1")])

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s3")
        await record_scan_update_delta(db, "s4")
        await record_scan_update_delta(db, "s2")

        empty = await _delta(db, "s3")
        assert empty is not None
        assert empty["prev_scan_id"] == "s2"

        doc = await _delta(db, "s4")
        assert doc is not None
        assert doc["prev_scan_id"] == "s2"
        assert doc["updates"]["patch"] == 1

    @pytest.mark.asyncio
    async def test_repair_walk_is_bounded(self, caplog: pytest.LogCaptureFixture):
        db = FakeDatabase()
        await _seed_scan(db, "anchor", _at(0), [_dep("anchor", "requests", "1.0.0")])
        for i in range(1, 8):
            await _seed_scan(db, f"empty{i}", _at(i + 1), [])
        await record_scan_update_delta(db, "anchor")
        for i in range(1, 8):
            await record_scan_update_delta(db, f"empty{i}")

        await _seed_scan(db, "late", _at(1), [_dep("late", "requests", "1.5.0")])
        with caplog.at_level("WARNING"):
            await record_scan_update_delta(db, "late")

        repaired = [i for i in range(1, 8) if (await _delta(db, f"empty{i}"))["prev_scan_id"] == "late"]
        assert repaired == [1, 2, 3, 4, 5]
        # Silence here would hide deltas left on a stale predecessor.
        assert "repair stopped after 5 hops from scan late" in caplog.text

    @pytest.mark.asyncio
    async def test_repair_walks_past_a_successor_that_fails_to_recompute(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0")])
        await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "3.0.0")])
        await _seed_scan(db, "s4", _at(3), [_dep("s4", "requests", "4.0.0")])

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s3")
        await record_scan_update_delta(db, "s4")

        with _failing_dependency_reads(db, only_scan="s3"):
            await record_scan_update_delta(db, "s2")

        broken = await _delta(db, "s3")
        assert broken is not None
        assert broken["error"] == "RuntimeError: connection reset by peer"

        # s3 is an error document now, so s4 must fall back to the late scan.
        doc = await _delta(db, "s4")
        assert doc is not None
        assert doc["prev_scan_id"] == "s2"
        assert doc["updates"]["major"] == 1

    @pytest.mark.asyncio
    async def test_recording_an_unchanged_predecessor_again_reproduces_the_successor(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0")])

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")
        before = dict(await _delta(db, "s2"))  # type: ignore[arg-type]

        await record_scan_update_delta(db, "s1")

        after = dict(await _delta(db, "s2"))  # type: ignore[arg-type]
        before.pop("computed_at")
        after.pop("computed_at")
        assert after == before


class TestReIngest:
    """A re-ingest rewrites the dependencies of an existing scan, so the diff its
    successor recorded describes a comparison that no longer happened."""

    @pytest.mark.asyncio
    async def test_a_rewritten_predecessor_invalidates_the_successors_diff(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0")])
        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")
        assert (await _delta(db, "s2"))["updates"]["major"] == 1

        # Same package count, so the predecessor still passes the staleness check.
        await db.dependencies.delete_many({"scan_id": "s1"})
        await db.dependencies.insert_one(_dep("s1", "requests", "2.0.0"))
        await record_scan_update_delta(db, "s1")

        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["prev_scan_id"] == "s1"
        assert doc["total_updates"] == 0
        assert doc["updates"]["major"] == 0
        # 1.0.0 -> 2.0.0 is a transition that never took place.
        assert doc["updates_sample"] == []

    @pytest.mark.asyncio
    async def test_only_the_direct_successor_is_recomputed(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0")])
        await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "3.0.0")])
        for scan_id in ("s1", "s2", "s3"):
            await record_scan_update_delta(db, scan_id)
        before = dict(await _delta(db, "s3"))  # type: ignore[arg-type]

        await record_scan_update_delta(db, "s1")

        # s2 kept its dependencies, so nothing about the s2 -> s3 diff changed.
        assert await _delta(db, "s3") == before


class TestSkippedScans:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", ["failed", "processing", "pending"])
    async def test_unusable_status_writes_nothing(self, status: str):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], status=status)

        await record_scan_update_delta(db, "s1")

        assert await _delta(db, "s1") is None

    @pytest.mark.asyncio
    async def test_completed_with_errors_is_usable(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], status="completed_with_errors")

        await record_scan_update_delta(db, "s1")

        assert await _delta(db, "s1") is not None

    @pytest.mark.asyncio
    async def test_rescan_writes_nothing(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], is_rescan=True)

        await record_scan_update_delta(db, "s1")

        assert await _delta(db, "s1") is None

    @pytest.mark.asyncio
    async def test_missing_scan_writes_nothing(self):
        db = FakeDatabase()

        await record_scan_update_delta(db, "ghost")

        assert await _delta(db, "ghost") is None

    @pytest.mark.asyncio
    async def test_disabled_feature_flag_writes_nothing(self, monkeypatch: pytest.MonkeyPatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "UPDATE_FREQUENCY_ROLLUP_ENABLED", False)
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")])

        await record_scan_update_delta(db, "s1")

        assert await _delta(db, "s1") is None


class TestScanLostItsUsableStatus:
    """A re-ingest deletes the dependencies before rewriting them, so a scan that ends
    failed can be left with a delta counting dependencies that no longer exist."""

    @pytest.mark.asyncio
    async def test_failed_re_ingest_drops_the_delta_and_repoints_the_successor(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")], ("requests",))
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0")], ())
        await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "3.0.0")], ())
        for scan_id in ("s1", "s2", "s3"):
            await record_scan_update_delta(db, scan_id)
        assert (await _delta(db, "s3"))["prev_scan_id"] == "s2"

        await db.dependencies.delete_many({"scan_id": "s2"})
        await db.scans.update_one({"_id": "s2"}, {"$set": {"status": "failed"}})
        await record_scan_update_delta(db, "s2")

        assert await _delta(db, "s2") is None
        assert await db.scan_outdated_sets.find_one({"_id": "s2"}) is None
        repaired = await _delta(db, "s3")
        assert repaired["prev_scan_id"] == "s1"
        assert repaired["updates"]["major"] == 1
        assert repaired["outdated_resolved"] == ["requests"]

    @pytest.mark.asyncio
    async def test_a_scan_that_never_had_a_delta_stays_untouched(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "1.0.0")])
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.0.0")], status="failed")
        await record_scan_update_delta(db, "s1")
        before = dict(await _delta(db, "s1"))  # type: ignore[arg-type]

        await record_scan_update_delta(db, "s2")

        assert await _delta(db, "s2") is None
        assert await _delta(db, "s1") == before


class _failing_dependency_reads:
    """Make ``dependencies`` reads fail, the way a server error would.

    ``only_scan`` narrows the failure to one scan, which is how a single delta
    ends up as an error document while the rest of the branch stays computable.
    """

    def __init__(self, db: FakeDatabase, only_scan: str | None = None):
        self._collection = db.dependencies
        self._original = db.dependencies.find
        self._only_scan = only_scan

    def __enter__(self) -> None:
        def _raise(query: Any = None, *args: Any, **kwargs: Any) -> Any:
            if self._only_scan is None or (query or {}).get("scan_id") == self._only_scan:
                raise RuntimeError("connection reset by peer")
            return self._original(query, *args, **kwargs)

        self._collection.find = _raise  # type: ignore[method-assign]

    def __exit__(self, *_exc: object) -> None:
        self._collection.find = self._original  # type: ignore[method-assign]


class TestFailures:
    @pytest.mark.asyncio
    async def test_failed_computation_writes_an_error_document(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], ("requests",))
        errors_before = _counter("error")

        with _failing_dependency_reads(db):
            await record_scan_update_delta(db, "s1")

        doc = await _delta(db, "s1")
        assert doc is not None
        assert doc["error"] == "RuntimeError: connection reset by peer"
        assert doc["dep_count"] == 0
        assert doc["total_updates"] == 0
        assert doc["project_id"] == PROJECT
        assert doc["scan_created_at"] == _at(0).replace(tzinfo=None)
        # The outdated set belongs to a successful computation only.
        assert await db.scan_outdated_sets.find_one({"_id": "s1"}) is None
        assert _counter("error") == errors_before + 1

    @pytest.mark.asyncio
    async def test_a_failed_recomputation_drops_the_earlier_outdated_set(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], ("requests",))
        await record_scan_update_delta(db, "s1")
        assert await db.scan_outdated_sets.find_one({"_id": "s1"}) is not None

        with _failing_dependency_reads(db):
            await record_scan_update_delta(db, "s1")

        assert (await _delta(db, "s1"))["error"] is not None
        assert await db.scan_outdated_sets.find_one({"_id": "s1"}) is None

    @pytest.mark.asyncio
    async def test_recomputation_replaces_an_error_document(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")])

        with _failing_dependency_reads(db):
            await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s1")

        doc = await _delta(db, "s1")
        assert doc is not None
        assert doc["error"] is None
        assert doc["dep_count"] == 1

    @pytest.mark.asyncio
    async def test_unreadable_scan_does_not_reach_the_caller(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")])
        errors_before = _counter("error")

        async def _raise(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("no primary available")

        db.scans.find_one = _raise

        await record_scan_update_delta(db, "s1")

        assert _counter("error") == errors_before + 1

    @pytest.mark.asyncio
    async def test_unwritable_error_document_does_not_reach_the_caller(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")])

        async def _raise(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("not authorized on scan_update_deltas")

        db.scan_update_deltas.update_one = _raise

        with _failing_dependency_reads(db):
            await record_scan_update_delta(db, "s1")

        assert await _delta(db, "s1") is None

    @pytest.mark.asyncio
    async def test_successful_write_counts_as_ok(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")])
        ok_before = _counter("ok")

        await record_scan_update_delta(db, "s1")

        assert _counter("ok") == ok_before + 1


class TestReadShape:
    """The rollup runs on every ingest, so its reads stay narrow."""

    @pytest.mark.asyncio
    async def test_reads_are_projected(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], ("requests",))
        await _seed_scan(db, "s2", _at(1), [_dep("s2", "requests", "2.1.0")], ("requests",))
        await record_scan_update_delta(db, "s1")

        finds: dict[str, list[Any]] = {"dependencies": [], "analysis_results": [], "scans": []}
        _spy_on_find(db.dependencies, finds["dependencies"])
        _spy_on_find(db.analysis_results, finds["analysis_results"])
        _spy_on_find_one(db.scans, finds["scans"])

        await record_scan_update_delta(db, "s2")

        assert finds["scans"] == [{"project_id", "branch", "created_at", "commit_hash", "status", "is_rescan"}]

        assert len(finds["dependencies"]) == 2
        for projection in finds["dependencies"]:
            assert projection
            assert set(projection) <= {"name", "version", "type", "purl"}

        # An outdated_packages document averages 48 KB; only component names may be pulled.
        assert len(finds["analysis_results"]) == 2
        for projection in finds["analysis_results"]:
            assert projection
            assert all(key.startswith("result.outdated_dependencies.") for key in projection)


def _spy_on_find(collection: Any, log: list[Any]) -> None:
    original = collection.find

    def spy(query: Any = None, projection: Any = None, **kwargs: Any) -> Any:
        log.append(projection)
        return original(query, projection, **kwargs)

    collection.find = spy


def _spy_on_find_one(collection: Any, log: list[Any]) -> None:
    original = collection.find_one

    async def spy(query: Any, projection: Any = None, **kwargs: Any) -> Any:
        log.append(set(projection) if projection else None)
        return await original(query, projection, **kwargs)

    collection.find_one = spy


class TestIdempotency:
    @pytest.mark.asyncio
    async def test_recording_twice_keeps_one_document_with_the_same_content(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _at(0), [_dep("s1", "requests", "2.0.0")], ("requests",))
        await _seed_scan(
            db,
            "s2",
            _at(1),
            [_dep("s2", "requests", "2.1.0"), _dep("s2", "flask", "3.0.0")],
            ("flask",),
        )

        await record_scan_update_delta(db, "s1")
        await record_scan_update_delta(db, "s2")
        first = dict(await _delta(db, "s2"))  # type: ignore[arg-type]

        await record_scan_update_delta(db, "s2")
        second = dict(await _delta(db, "s2"))  # type: ignore[arg-type]

        assert await db.scan_update_deltas.count_documents({}) == 2
        assert await db.scan_outdated_sets.count_documents({}) == 2
        first.pop("computed_at")
        second.pop("computed_at")
        assert first == second
