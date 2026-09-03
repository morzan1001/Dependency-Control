"""One-off backfill of release records onto historical tag builds.

Scans whose ``branch`` equals their ``commit_tag`` came out of a tag pipeline whose ref name was
the tag. Each becomes a production release dated at its ``created_at``, and the tag name of every
tag build that ends the run released — this run's and any earlier one's — is dropped from
``Project.deleted_branches``, where several branch filters read them and hide the scan.

A release is a document in ``db.releases``; ``Scan.is_release`` is the denormalised boolean the
``scans_released_list`` partial index is keyed on. Both are written, in the order the mark endpoint
writes them, and a scan left holding only the row has its flag repaired on the next run.

The run plans first and writes second, and ``--execute`` only decides whether the plan is applied,
so the dry run's report is the plan the real run carries out.

Usage (in-pod): `python -m scripts.backfill_release_flags --help` from /app.

Exit codes:
    0 — completed (dry-run or execute)
    1 — connection or runtime error
"""

import argparse
import asyncio
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient

from app.core import ensure_utc
from app.core.config import settings
from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT, SCAN_USABLE_STATUSES
from app.models.release import Release
from app.repositories import ReleaseRepository

DEFAULT_BATCH_SIZE = 500
DEFAULT_SLEEP_MS = 50
NO_LIMIT = 0

_SCAN_PROJECTION = {
    "_id": 1,
    "project_id": 1,
    "branch": 1,
    "commit_tag": 1,
    "created_at": 1,
    "is_release": 1,
}
_PROJECT_PROJECTION = {"_id": 1, "deleted_branches": 1}


@dataclass(frozen=True)
class PlannedRelease:
    """One tag build to record as a production release."""

    scan_id: str
    project_id: str
    version: str
    released_at: datetime


@dataclass(frozen=True)
class PlannedPrune:
    """One project's ``deleted_branches`` after the marked tag names are dropped."""

    project_id: str
    removed: tuple[str, ...]
    remaining: tuple[str, ...]


@dataclass(frozen=True)
class BackfillPlan:
    """Everything a run would write, and why the rest was left alone."""

    releases: tuple[PlannedRelease, ...] = ()
    # Scans holding a release row but not the flag the partial index is keyed on.
    flag_repairs: tuple[str, ...] = ()
    prunes: tuple[PlannedPrune, ...] = ()
    inspected: int = 0
    skipped_already_released: int = 0
    skipped_undated: int = 0
    limit_reached: bool = False


def _is_tag_build(doc: dict[str, Any]) -> bool:
    tag = doc.get("commit_tag")
    return bool(tag) and doc.get("branch") == tag


def _tag_build_query(after_id: Any) -> dict[str, Any]:
    query: dict[str, Any] = {
        "status": {"$in": SCAN_USABLE_STATUSES},
        "commit_tag": {"$exists": True, "$ne": None},
        # A rescan copies its source's branch and tag, so it looks like a tag build; marking it
        # would open a second release for one deployment, which the mark endpoint also refuses.
        "is_rescan": {"$ne": True},
    }
    if after_id is not None:
        query["_id"] = {"$gt": after_id}
    return query


async def _already_released(db: Any, scan_ids: list[str]) -> set[str]:
    rows: list[str] = await db.releases.distinct("scan_id", {"scan_id": {"$in": scan_ids}})
    return set(rows)


async def _plan_prunes(db: Any, tag_names_by_project: dict[str, set[str]]) -> tuple[PlannedPrune, ...]:
    prunes: list[PlannedPrune] = []
    for project_id in sorted(tag_names_by_project):
        tags = tag_names_by_project[project_id]
        project = await db.projects.find_one({"_id": project_id}, _PROJECT_PROJECTION)
        if not project:
            continue
        current: list[str] = project.get("deleted_branches") or []
        remaining = [branch for branch in current if branch not in tags]
        if remaining == current:
            continue
        removed = [branch for branch in current if branch in tags]
        prunes.append(
            PlannedPrune(project_id=project_id, removed=tuple(removed), remaining=tuple(remaining))
        )
    return tuple(prunes)


async def _iter_tag_build_batches(db: Any, batch_size: int, sleep_ms: int) -> AsyncIterator[list[dict[str, Any]]]:
    """Usable original tag builds, paged on ``_id``."""
    after_id: Any = None
    while True:
        batch = (
            await db.scans.find(_tag_build_query(after_id), _SCAN_PROJECTION)
            .sort("_id", 1)
            .limit(batch_size)
            .to_list(batch_size)
        )
        if not batch:
            return
        after_id = batch[-1]["_id"]
        yield [doc for doc in batch if _is_tag_build(doc)]
        if len(batch) < batch_size:
            return
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000)


def _plan_release(doc: dict[str, Any], scan_id: str) -> PlannedRelease | None:
    """None for a scan with no creation time: a release has to be dated, and nothing here can date it."""
    released_at = ensure_utc(doc.get("created_at"))
    if released_at is None:
        return None
    return PlannedRelease(
        scan_id=scan_id,
        project_id=doc["project_id"],
        version=doc["commit_tag"],
        released_at=released_at,
    )


async def plan_backfill(db: Any, *, batch_size: int, sleep_ms: int, limit: int) -> BackfillPlan:
    """Read-only: everything the run would write, without writing any of it."""
    releases: list[PlannedRelease] = []
    flag_repairs: list[str] = []
    tag_names_by_project: dict[str, set[str]] = {}
    inspected = 0
    skipped_already_released = 0
    skipped_undated = 0
    limit_reached = False

    async for candidates in _iter_tag_build_batches(db, batch_size, sleep_ms):
        inspected += len(candidates)
        released = await _already_released(db, [str(doc["_id"]) for doc in candidates])

        for doc in candidates:
            scan_id = str(doc["_id"])
            # The row is the record, so it and not the flag decides: a scan already deployed
            # somewhere must not gain a second, invented production release.
            if scan_id in released:
                skipped_already_released += 1
                if not doc.get("is_release"):
                    flag_repairs.append(scan_id)
                # A run killed before its prunes leaves the tag hidden, and on the next pass the
                # scan reaches only this branch, so the prune has to be planned from here as well.
                tag_names_by_project.setdefault(doc["project_id"], set()).add(doc["commit_tag"])
                continue
            planned = _plan_release(doc, scan_id)
            if planned is None:
                skipped_undated += 1
                continue
            releases.append(planned)
            tag_names_by_project.setdefault(planned.project_id, set()).add(planned.version)
            if limit and len(releases) >= limit:
                limit_reached = True
                break

        print(f"inspected={inspected} planned={len(releases)} already_released={skipped_already_released}")
        if limit_reached:
            break

    return BackfillPlan(
        releases=tuple(releases),
        flag_repairs=tuple(flag_repairs),
        prunes=await _plan_prunes(db, tag_names_by_project),
        inspected=inspected,
        skipped_already_released=skipped_already_released,
        skipped_undated=skipped_undated,
        limit_reached=limit_reached,
    )


async def apply_plan(db: Any, plan: BackfillPlan, *, batch_size: int, sleep_ms: int) -> None:
    """Write the plan. Both writes per release are upserts of a value the plan already fixed, so a
    re-run of the same plan is a no-op rather than a second release."""
    release_repo = ReleaseRepository(db)
    for index, planned in enumerate(plan.releases, start=1):
        await release_repo.record(
            Release(
                project_id=planned.project_id,
                environment=DEFAULT_RELEASE_ENVIRONMENT,
                version=planned.version,
                scan_id=planned.scan_id,
                released_at=planned.released_at,
            )
        )
        await db.scans.update_one({"_id": planned.scan_id}, {"$set": {"is_release": True}})
        if sleep_ms > 0 and index % batch_size == 0:
            await asyncio.sleep(sleep_ms / 1000)

    for scan_id in plan.flag_repairs:
        await db.scans.update_one({"_id": scan_id}, {"$set": {"is_release": True}})

    for prune in plan.prunes:
        await db.projects.update_one(
            {"_id": prune.project_id}, {"$set": {"deleted_branches": list(prune.remaining)}}
        )


async def run_backfill(db: Any, *, batch_size: int, sleep_ms: int, limit: int, execute: bool) -> BackfillPlan:
    plan = await plan_backfill(db, batch_size=batch_size, sleep_ms=sleep_ms, limit=limit)
    if execute:
        await apply_plan(db, plan, batch_size=batch_size, sleep_ms=sleep_ms)
    return plan


def _report(plan: BackfillPlan, mode: str) -> None:
    pruned_names = sum(len(prune.removed) for prune in plan.prunes)
    print()
    print(f"[{mode}] tag builds inspected:        {plan.inspected}")
    print(f"[{mode}] releases to record:          {len(plan.releases)}")
    print(f"[{mode}] already released:            {plan.skipped_already_released}")
    print(f"[{mode}] of those, flags to repair:   {len(plan.flag_repairs)}")
    print(f"[{mode}] skipped, no created_at:      {plan.skipped_undated}")
    print(f"[{mode}] projects to prune:           {len(plan.prunes)}")
    print(f"[{mode}] deleted-branch names to drop: {pruned_names}")


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        mode = "EXECUTE" if args.execute else "DRY-RUN"
        print(f"[{mode}] Database: {db.name} — environment {DEFAULT_RELEASE_ENVIRONMENT}")

        plan = await run_backfill(
            db,
            batch_size=args.batch_size,
            sleep_ms=args.sleep_ms,
            limit=args.limit,
            execute=args.execute,
        )
        if plan.limit_reached:
            print(f"Reached --limit {args.limit}; the walk stopped early.")
        _report(plan, mode)
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"backfill_release_flags: ERROR — {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--execute",
        action="store_true",
        help="Actually record the releases (default: dry-run, report the plan only).",
    )
    mode.add_argument(
        "--dry-run",
        dest="execute",
        action="store_false",
        help="Report the plan without writing (the default).",
    )
    # store_true and store_false disagree on their implicit default for the shared dest.
    parser.set_defaults(execute=False)
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Scans fetched per batch, with a progress line after each (default: {DEFAULT_BATCH_SIZE}).",
    )
    parser.add_argument(
        "--sleep-ms",
        type=int,
        default=DEFAULT_SLEEP_MS,
        help=f"Milliseconds to sleep between batches (default: {DEFAULT_SLEEP_MS}).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=NO_LIMIT,
        help=f"Stop after planning N releases; {NO_LIMIT} = all (default). Useful for a smoke test.",
    )
    args = parser.parse_args()

    if args.batch_size < 1:
        parser.error("--batch-size must be >= 1")
    if args.sleep_ms < 0:
        parser.error("--sleep-ms must be >= 0")
    if args.limit < 0:
        parser.error("--limit must be >= 0")

    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
