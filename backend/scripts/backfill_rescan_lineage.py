"""One-off rewrite of every rescan's ``original_scan_id`` to its lineage root.

``Scan.original_scan_id`` names the scan a rescan lineage descends from. A pointer that instead
names another rescan makes the latest-scan guard compare a mid-chain link against a root, the
scan-history endpoint miss its siblings, and retention exempt an intermediate rescan nothing reads.
This walks each pointer up to the first scan that is not itself a rescan and stores that.

A rescan whose pointer runs past the hop bound — only reachable through a cycle — is reported and
left alone: no id on such a chain is defensibly its root.

The run plans first and writes second, and ``--execute`` only decides whether the plan is applied,
so the dry run's report is the plan the real run carries out.

Usage (in-pod): `python -m scripts.backfill_rescan_lineage --help` from /app.

Exit codes:
    0 — completed (dry-run or execute)
    1 — connection or runtime error
"""

import argparse
import asyncio
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings
from app.core.constants import MAX_RESCAN_HOPS

DEFAULT_BATCH_SIZE = 500
DEFAULT_SLEEP_MS = 50
NO_LIMIT = 0
_REPORT_LABEL_WIDTH = 30

_RESCAN_PROJECTION = {"_id": 1, "original_scan_id": 1}
_LINEAGE_PROJECTION = {"_id": 1, "is_rescan": 1, "original_scan_id": 1}


@dataclass(frozen=True)
class PlannedRepoint:
    """One rescan whose pointer moves from a mid-chain link to the lineage root."""

    scan_id: str
    parent_id: str
    root_id: str


@dataclass(frozen=True)
class LineagePlan:
    """Everything a run would write, and why the rest was left alone."""

    repoints: tuple[PlannedRepoint, ...] = ()
    inspected: int = 0
    already_rooted: int = 0
    unresolved: tuple[str, ...] = ()
    limit_reached: bool = False


def _rescan_query(after_id: Any) -> dict[str, Any]:
    query: dict[str, Any] = {
        "is_rescan": True,
        "original_scan_id": {"$exists": True, "$ne": None},
    }
    if after_id is not None:
        query["_id"] = {"$gt": after_id}
    return query


async def _iter_rescan_batches(db: Any, batch_size: int, sleep_ms: int) -> AsyncIterator[list[dict[str, Any]]]:
    """Rescans carrying a lineage pointer, paged on ``_id``."""
    after_id: Any = None
    while True:
        batch = (
            await db.scans.find(_rescan_query(after_id), _RESCAN_PROJECTION)
            .sort("_id", 1)
            .limit(batch_size)
            .to_list(batch_size)
        )
        if not batch:
            return
        after_id = batch[-1]["_id"]
        yield batch
        if len(batch) < batch_size:
            return
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000)


async def _roots_for(db: Any, parent_ids: set[str], cache: dict[str, str | None]) -> None:
    """Resolve each pointer to its lineage root into ``cache``; None where the bound was reached.

    One query per hop for the whole batch rather than one per pointer, and the cache is kept across
    batches because sibling rescans of one lineage share every id above them.
    """
    pending: dict[str, list[str]] = {}
    for parent_id in parent_ids:
        if parent_id not in cache:
            pending.setdefault(parent_id, []).append(parent_id)

    for _hop in range(MAX_RESCAN_HOPS):
        if not pending:
            return
        docs = {doc["_id"]: doc async for doc in db.scans.find({"_id": {"$in": list(pending)}}, _LINEAGE_PROJECTION)}
        advanced: dict[str, list[str]] = {}
        for cursor_id, origins in pending.items():
            doc = docs.get(cursor_id)
            # A missing scan and an original both end the walk: neither has a parent to climb to.
            next_id = doc.get("original_scan_id") if doc and doc.get("is_rescan") else None
            if not next_id or next_id == cursor_id:
                for origin in origins:
                    cache[origin] = cursor_id
            else:
                advanced.setdefault(next_id, []).extend(origins)
        pending = advanced

    for origins in pending.values():
        for origin in origins:
            cache[origin] = None


async def plan_lineage_backfill(db: Any, *, batch_size: int, sleep_ms: int, limit: int) -> LineagePlan:
    """Read-only: everything the run would write, without writing any of it."""
    repoints: list[PlannedRepoint] = []
    unresolved: list[str] = []
    roots: dict[str, str | None] = {}
    inspected = 0
    already_rooted = 0
    limit_reached = False

    async for batch in _iter_rescan_batches(db, batch_size, sleep_ms):
        inspected += len(batch)
        await _roots_for(db, {doc["original_scan_id"] for doc in batch}, roots)

        for doc in batch:
            scan_id = str(doc["_id"])
            parent_id = doc["original_scan_id"]
            root_id = roots[parent_id]
            if root_id is None:
                unresolved.append(scan_id)
                continue
            if root_id == parent_id:
                already_rooted += 1
                continue
            repoints.append(PlannedRepoint(scan_id=scan_id, parent_id=parent_id, root_id=root_id))
            if limit and len(repoints) >= limit:
                limit_reached = True
                break

        print(f"inspected={inspected} planned={len(repoints)} already_rooted={already_rooted}")
        if limit_reached:
            break

    return LineagePlan(
        repoints=tuple(repoints),
        inspected=inspected,
        already_rooted=already_rooted,
        unresolved=tuple(unresolved),
        limit_reached=limit_reached,
    )


async def apply_lineage_plan(db: Any, plan: LineagePlan, *, batch_size: int, sleep_ms: int) -> None:
    """Write the plan. Each write stores a value the plan already fixed, so a re-run of the same
    plan is a no-op."""
    for index, repoint in enumerate(plan.repoints, start=1):
        await db.scans.update_one({"_id": repoint.scan_id}, {"$set": {"original_scan_id": repoint.root_id}})
        if sleep_ms > 0 and index % batch_size == 0:
            await asyncio.sleep(sleep_ms / 1000)


async def run_lineage_backfill(db: Any, *, batch_size: int, sleep_ms: int, limit: int, execute: bool) -> LineagePlan:
    plan = await plan_lineage_backfill(db, batch_size=batch_size, sleep_ms=sleep_ms, limit=limit)
    if execute:
        await apply_lineage_plan(db, plan, batch_size=batch_size, sleep_ms=sleep_ms)
    return plan


def _report(plan: LineagePlan, mode: str) -> None:
    counts = (
        ("rescans inspected", plan.inspected),
        ("pointers to rewrite", len(plan.repoints)),
        ("already at the root", plan.already_rooted),
        ("unresolved, past the bound", len(plan.unresolved)),
    )
    print()
    for label, value in counts:
        print(f"[{mode}] {label + ':':<{_REPORT_LABEL_WIDTH}}{value}")
    for scan_id in plan.unresolved:
        print(f"[{mode}] unresolved: {scan_id}")


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        mode = "EXECUTE" if args.execute else "DRY-RUN"
        print(f"[{mode}] Database: {db.name}")

        plan = await run_lineage_backfill(
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
        print(f"backfill_rescan_lineage: ERROR — {exc}", file=sys.stderr)
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
        help="Actually rewrite the pointers (default: dry-run, report the plan only).",
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
        help=f"Rescans fetched per batch, with a progress line after each (default: {DEFAULT_BATCH_SIZE}).",
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
        help=f"Stop after planning N rewrites; {NO_LIMIT} = all (default). Useful for a smoke test.",
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
