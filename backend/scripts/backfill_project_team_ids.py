"""Expand the scalar project team fields into the multi-team ones.

Task 1 added ``Project.team_ids`` and ``Project.team_sources``, derived on read from the legacy
scalars ``team_id`` / ``team_source``. This migration writes those derived fields into MongoDB so
Mongo-side queries and the index can use them. It changes no application behaviour.

Of 742 production projects, 229 have a team and 513 do not; both must be written.

The planning half is pure so tests call it with plain dicts and no database. A document that
already carries ``team_ids`` is updated only if its stored list or sources differ from the value
derived from the scalar — the scalar stays authoritative in this phase.

Usage (in-pod): `python -m scripts.backfill_project_team_ids --help` from /app.

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

DEFAULT_BATCH_SIZE = 500
DEFAULT_SLEEP_MS = 50
_REPORT_LABEL_WIDTH = 30

_PROJECT_PROJECTION = {"_id": 1, "team_id": 1, "team_source": 1, "team_ids": 1, "team_sources": 1}


@dataclass(frozen=True)
class TeamIdsUpdate:
    """One project's expanded team fields."""

    project_id: str
    team_ids: list[str]
    team_sources: dict[str, str]


def plan_team_id_expansion(docs: list[dict[str, Any]]) -> list[TeamIdsUpdate]:
    """One update per project that lacks the multi-team fields or where they diverge from the scalar.

    The scalar stays authoritative in this phase. A document whose stored list or sources already
    equal the derived value is skipped — by the time Phase 3 writers own the list, re-running the
    migration must never clobber their work.
    """
    plan: list[TeamIdsUpdate] = []
    for doc in docs:
        team_id = doc.get("team_id")
        source = doc.get("team_source")
        derived_ids = [team_id] if team_id else []
        derived_sources = {team_id: source} if team_id and source else {}

        stored_ids = doc.get("team_ids")
        stored_sources = doc.get("team_sources")

        if stored_ids == derived_ids and stored_sources == derived_sources:
            continue

        plan.append(TeamIdsUpdate(project_id=str(doc["_id"]), team_ids=derived_ids, team_sources=derived_sources))
    return plan


async def _iter_project_batches(db: Any, batch_size: int, sleep_ms: int) -> AsyncIterator[list[dict[str, Any]]]:
    """All projects, paged on ``_id``."""
    after_id: Any = None
    while True:
        batch = (
            await db.projects.find({} if after_id is None else {"_id": {"$gt": after_id}}, _PROJECT_PROJECTION)
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


async def apply_plan(db: Any, updates: list[TeamIdsUpdate], *, batch_size: int, sleep_ms: int) -> int:
    """Write the plan. Returns the number of matched documents."""
    matched = 0
    for index, update in enumerate(updates, start=1):
        result = await db.projects.update_one(
            {"_id": update.project_id},
            {"$set": {"team_ids": update.team_ids, "team_sources": update.team_sources}},
        )
        matched += result.matched_count
        if sleep_ms > 0 and index % batch_size == 0:
            await asyncio.sleep(sleep_ms / 1000)
    return matched


async def run_expand(db: Any, *, batch_size: int, sleep_ms: int, execute: bool) -> tuple[int, int]:
    """Plan and optionally apply the expansion. Returns (planned, matched)."""
    planned = 0
    matched = 0

    async for batch in _iter_project_batches(db, batch_size, sleep_ms):
        plan = plan_team_id_expansion(batch)
        planned += len(plan)
        if execute and plan:
            matched += await apply_plan(db, plan, batch_size=batch_size, sleep_ms=sleep_ms)
        print(f"batched={len(batch)} planned={planned} matched={matched if execute else 'N/A'}")

    return planned, matched


def _report(planned: int, matched: int, mode: str) -> None:
    counts = [("projects planned", planned)]
    if matched is not None:
        counts.append(("projects matched", matched))
    print()
    for label, value in counts:
        print(f"[{mode}] {label + ':':<{_REPORT_LABEL_WIDTH}}{value}")


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        mode = "EXECUTE" if args.execute else "DRY-RUN"
        print(f"[{mode}] Database: {db.name}")

        planned, matched = await run_expand(
            db,
            batch_size=args.batch_size,
            sleep_ms=args.sleep_ms,
            execute=args.execute,
        )
        _report(planned, matched if args.execute else None, mode)
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"backfill_project_team_ids: ERROR — {exc}", file=sys.stderr)
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
        help="Actually write the team_ids and team_sources (default: dry-run, report the plan only).",
    )
    mode.add_argument(
        "--dry-run",
        dest="execute",
        action="store_false",
        help="Report the plan without writing (the default).",
    )
    parser.set_defaults(execute=False)
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Projects fetched per batch, with a progress line after each (default: {DEFAULT_BATCH_SIZE}).",
    )
    parser.add_argument(
        "--sleep-ms",
        type=int,
        default=DEFAULT_SLEEP_MS,
        help=f"Milliseconds to sleep between batches (default: {DEFAULT_SLEEP_MS}).",
    )
    args = parser.parse_args()

    if args.batch_size < 1:
        parser.error("--batch-size must be >= 1")
    if args.sleep_ms < 0:
        parser.error("--sleep-ms must be >= 0")

    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
