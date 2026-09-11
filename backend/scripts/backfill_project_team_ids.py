"""Expand the scalar project team fields into the multi-team ones.

This migration writes ``team_ids`` / ``team_sources`` from the legacy scalars ``team_id`` /
``team_source`` so Mongo-side queries and the index can use them.

A project with no team is written too, as ``[]`` and ``{}``: absent and null answer no ownership
filter and no ``$size`` test, so leaving one unwritten hides it from every team view at once.

The planning half is pure so tests call it with plain dicts and no database. A document that
already carries ``team_ids`` is updated only if its stored list or sources differ from the value
derived from the scalar — the scalar stays authoritative in this phase.

``--verify`` counts the documents that still disagree with their scalar, and separately the ones
holding an owner no provenance entry names. It is the release gate for the deploy that stops
deriving the fields on read: from that image on, whatever is stored is what readers act on, and
every team transfer made since the last ``--execute`` run wrote the scalar only.
See ``README-deploy-multi-team-phase-1.md`` §6.

Usage (in-pod): `python -m scripts.backfill_project_team_ids --help` from /app.

Exit codes:
    0 — completed (dry-run, execute, or a --verify that found nothing)
    1 — connection or runtime error
    2 — --verify found documents disagreeing with the scalar or holding an un-provenanced owner
"""

import argparse
import asyncio
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings
from app.core.constants import TEAM_SOURCE_MANUAL

DEFAULT_BATCH_SIZE = 500
DEFAULT_SLEEP_MS = 50
_REPORT_LABEL_WIDTH = 30
EXIT_DRIFT_FOUND = 2

_PROJECT_PROJECTION = {"_id": 1, "team_id": 1, "team_source": 1, "team_ids": 1, "team_sources": 1}

# Both spellings of "this project has no team": Pydantic reads "" as absent, so the query must too.
_NO_TEAM = [None, ""]
_SCALAR_ID = {"$ifNull": ["$team_id", None]}
_SCALAR_SOURCE = {"$ifNull": ["$team_source", None]}
# A legacy scalar with no source names a provider nothing can identify, so the entry is written as
# a hand assignment. Guessing a provider would have that provider's next sync retire the owner.
_DERIVED_SOURCE = {"$cond": [{"$in": [_SCALAR_SOURCE, _NO_TEAM]}, TEAM_SOURCE_MANUAL, "$team_source"]}


def drift_filter() -> dict[str, Any]:
    """Selects every project whose stored team fields differ from what the scalar says.

    Equivalent to ``plan_team_id_expansion`` expressed server-side, so a count of 0 means a re-run
    of this migration would plan nothing. Both stored fields are compared raw rather than through
    ``$ifNull``: an absent or null ``team_ids`` is itself a disagreement, and the second is the one
    shape that no longer loads into the model at all.

    ``team_sources`` is compared as ``$objectToArray`` output because an absent map yields null
    there, which no document expression can be written to equal by accident.

    A scalar owner whose ``team_source`` is absent derives a ``manual`` entry, so a document left
    with no provenance for it disagrees here rather than reading as finished.
    """
    return {
        "$expr": {
            "$or": [
                {
                    "$ne": [
                        "$team_ids",
                        {"$cond": [{"$in": [_SCALAR_ID, _NO_TEAM]}, [], ["$team_id"]]},
                    ]
                },
                {
                    "$ne": [
                        {"$objectToArray": "$team_sources"},
                        {
                            "$cond": [
                                {"$in": [_SCALAR_ID, _NO_TEAM]},
                                [],
                                [{"k": "$team_id", "v": _DERIVED_SOURCE}],
                            ]
                        },
                    ]
                },
            ]
        }
    }


def provenance_gap_filter() -> dict[str, Any]:
    """Selects every project holding an owner that no ``team_sources`` entry names.

    Such an entry belongs to no provider, so no sync can ever retire it: the repository moves
    between groups and the owner it left keeps its access forever. Unlike the scalar comparison
    this stays meaningful after the cutover — no writer may produce the shape, so a count above
    zero is a document an older one left behind.
    """
    return {
        "$expr": {
            "$ne": [
                {
                    "$setDifference": [
                        {"$ifNull": ["$team_ids", []]},
                        {
                            "$map": {
                                "input": {"$objectToArray": {"$ifNull": ["$team_sources", {}]}},
                                "as": "entry",
                                "in": "$$entry.k",
                            }
                        },
                    ]
                },
                [],
            ]
        }
    }


async def count_drift(db: Any) -> int:
    """How many projects disagree with their scalar. Zero is the gate for dropping the derivation."""
    return await db.projects.count_documents(drift_filter())


async def count_provenance_gaps(db: Any) -> int:
    """How many projects hold an owner no provenance entry names."""
    return await db.projects.count_documents(provenance_gap_filter())


@dataclass(frozen=True)
class TeamIdsUpdate:
    """One project's expanded team fields."""

    project_id: str
    team_ids: list[str]
    team_sources: dict[str, str]


def plan_team_id_expansion(docs: list[dict[str, Any]]) -> list[TeamIdsUpdate]:
    """One update per project that lacks the multi-team fields or where they diverge from the scalar.

    The scalar stays authoritative in this phase. A document whose stored list and sources already
    equal the derived value is skipped. Once writers own the list, this migration must not be re-run,
    as any subsequent scalar change would overwrite writer-added teams.

    An owner whose ``team_source`` is absent is written as a hand assignment rather than left
    without one: an entry no provenance names belongs to no provider, so no sync could retire it,
    and no evidence exists for naming one of them instead.
    """
    plan: list[TeamIdsUpdate] = []
    for doc in docs:
        team_id = doc.get("team_id")
        source = doc.get("team_source")
        derived_ids = [team_id] if team_id else []
        derived_sources = {team_id: source or TEAM_SOURCE_MANUAL} if team_id else {}

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


async def apply_plan(db: Any, updates: list[TeamIdsUpdate]) -> int:
    """Write the plan. Returns the number of matched documents."""
    matched = 0
    for update in updates:
        result = await db.projects.update_one(
            {"_id": update.project_id},
            {"$set": {"team_ids": update.team_ids, "team_sources": update.team_sources}},
        )
        matched += result.matched_count
    return matched


async def run_expand(db: Any, *, batch_size: int, sleep_ms: int, execute: bool) -> tuple[int, int]:
    """Plan and optionally apply the expansion. Returns (planned, matched)."""
    planned = 0
    matched = 0

    async for batch in _iter_project_batches(db, batch_size, sleep_ms):
        plan = plan_team_id_expansion(batch)
        planned += len(plan)
        if execute and plan:
            matched += await apply_plan(db, plan)
        print(f"batched={len(batch)} planned={planned} matched={matched if execute else 'N/A'}")

    return planned, matched


def _report(planned: int, matched: int | None, mode: str) -> None:
    counts = [("projects planned", planned)]
    if matched is not None:
        counts.append(("projects matched", matched))
    print()
    for label, value in counts:
        print(f"[{mode}] {label + ':':<{_REPORT_LABEL_WIDTH}}{value}")


async def run_verify(db: Any) -> int:
    """Report both counts and return the process exit code."""
    drifted = await count_drift(db)
    gaps = await count_provenance_gaps(db)
    print(f"[VERIFY] {'projects disagreeing:':<{_REPORT_LABEL_WIDTH}}{drifted}")
    print(f"[VERIFY] {'owners with no provenance:':<{_REPORT_LABEL_WIDTH}}{gaps}")
    if drifted or gaps:
        print("GATE FAILED — run --execute before rolling the image that stops deriving the fields.")
        return EXIT_DRIFT_FOUND
    print("Gate passed — every stored owner matches the scalar and names the source that set it.")
    return 0


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        mode = "VERIFY" if args.verify else "EXECUTE" if args.execute else "DRY-RUN"
        print(f"[{mode}] Database: {db.name}")

        if args.verify:
            return await run_verify(db)

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
    mode.add_argument(
        "--verify",
        action="store_true",
        help=(
            "Count projects whose stored team fields disagree with the scalar and projects holding "
            f"an owner no provenance entry names; exit {EXIT_DRIFT_FOUND} if either is above zero."
        ),
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
