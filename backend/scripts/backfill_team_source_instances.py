"""Name the instance in every ownership provenance value a project carries.

``team_sources`` used to record a provider alone. With two instances of one provider configured,
each instance's sync reads the other's owners as its own and retires them, so the two delete each
other's teams on alternating CI runs. This migration rewrites every bare ``gitlab`` / ``github``
value to ``<provider>:<instance id>``, and the legacy ``team_source`` scalar with it. ``manual`` is
never touched.

The instance is resolved from the database, not passed in: exactly one instance per provider has
team sync enabled, and that is the only one that can have written a provenance entry. A provider
whose bare values are present while its instance count is anything other than one aborts the run
rather than guessing — a value naming the wrong instance hands the owner to that instance's next
ingest to delete.

The planning half is pure so tests call it with plain dicts and no database.

``--verify`` is the gate on this migration, which runs *after* the image that reads the new format:
it counts the documents still carrying a bare provider value and exits non-zero while any remain.
See ``README-deploy-team-bindings-and-provenance.md``.

Usage (in-pod): `python -m scripts.backfill_team_source_instances --help` from /app.

Exit codes:
    0 — completed (dry-run, execute, or a --verify that found nothing)
    1 — connection or runtime error, including a provider whose instance cannot be resolved
    2 — --verify found a document still carrying a bare provider value
"""

import argparse
import asyncio
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings
from app.core.constants import TEAM_SOURCE_PROVIDERS, team_source

DEFAULT_BATCH_SIZE = 500
DEFAULT_SLEEP_MS = 50
_REPORT_LABEL_WIDTH = 30
EXIT_BARE_SOURCES_FOUND = 2

_PROJECT_PROJECTION = {"_id": 1, "team_sources": 1, "team_source": 1}

# The instances collection per provider, and the flag that marks the one that syncs teams.
_INSTANCE_COLLECTION = {provider: f"{provider}_instances" for provider in TEAM_SOURCE_PROVIDERS}


class InstanceNotResolvable(Exception):
    """A provider's bare values cannot be attributed to exactly one instance."""


def _bare_entries(providers: tuple[str, ...]) -> dict[str, Any]:
    """The ``team_sources`` entries whose value is a provider and no instance."""
    return {
        "$filter": {
            "input": {"$objectToArray": {"$ifNull": ["$team_sources", {}]}},
            "as": "entry",
            "cond": {"$in": ["$$entry.v", {"$literal": list(providers)}]},
        }
    }


def bare_source_filter(providers: tuple[str, ...] = TEAM_SOURCE_PROVIDERS) -> dict[str, Any]:
    """Selects every project carrying a provenance value that names a provider and no instance.

    Equivalent to ``plan_instance_stamping`` expressed server-side, so a count of 0 means a re-run
    of this migration would plan nothing. The scalar is included because it mirrors one of the map's
    entries: left bare it contradicts the map it mirrors.

    ``manual``, and any value already carrying an instance, match neither clause.
    """
    return {
        "$or": [
            {"$expr": {"$gt": [{"$size": _bare_entries(providers)}, 0]}},
            {"team_source": {"$in": list(providers)}},
        ]
    }


async def count_bare_sources(db: Any, providers: tuple[str, ...] = TEAM_SOURCE_PROVIDERS) -> int:
    """How many projects still carry a provenance value that names no instance."""
    return await db.projects.count_documents(bare_source_filter(providers))


async def resolve_sync_instance(db: Any, provider: str) -> str:
    """The id of the one instance of ``provider`` whose syncs could have written its entries."""
    docs = await db[_INSTANCE_COLLECTION[provider]].find({"sync_teams": True}, {"_id": 1}).to_list(None)
    ids = sorted(str(doc["_id"]) for doc in docs)
    if len(ids) != 1:
        raise InstanceNotResolvable(
            f"{provider}: {len(ids)} instance(s) have team sync enabled ({ids or 'none'}); "
            "exactly one is required to attribute the bare values. Resolve them by hand."
        )
    return ids[0]


async def resolve_instances(db: Any) -> dict[str, str]:
    """The instance id per provider that still has bare values to attribute.

    Only the providers that appear are resolved: a single-provider installation must not be blocked
    by the other provider having no instance at all.
    """
    instances: dict[str, str] = {}
    for provider in TEAM_SOURCE_PROVIDERS:
        if await count_bare_sources(db, (provider,)):
            instances[provider] = await resolve_sync_instance(db, provider)
    return instances


@dataclass(frozen=True)
class SourceInstanceUpdate:
    """One project's rewritten provenance, as the fields to set."""

    project_id: str
    fields: dict[str, Any]


def _stamped(value: Any, instances: dict[str, str]) -> Any:
    return team_source(value, instances[value]) if value in instances else value


def plan_instance_stamping(docs: list[dict[str, Any]], instances: dict[str, str]) -> list[SourceInstanceUpdate]:
    """One update per project carrying a bare provider value, rewriting only those values.

    A value already naming an instance is left exactly as stored: this migration attributes the
    values that predate instance ids, and re-attributing one would move an owner between instances.
    """
    plan: list[SourceInstanceUpdate] = []
    for doc in docs:
        fields: dict[str, Any] = {}

        stored_sources = doc.get("team_sources") or {}
        stamped_sources = {team_id: _stamped(value, instances) for team_id, value in stored_sources.items()}
        if stamped_sources != stored_sources:
            fields["team_sources"] = stamped_sources

        stored_scalar = doc.get("team_source")
        stamped_scalar = _stamped(stored_scalar, instances)
        if stamped_scalar != stored_scalar:
            fields["team_source"] = stamped_scalar

        if fields:
            plan.append(SourceInstanceUpdate(project_id=str(doc["_id"]), fields=fields))
    return plan


async def _iter_project_batches(db: Any, batch_size: int, sleep_ms: int) -> AsyncIterator[list[dict[str, Any]]]:
    """The projects carrying a bare value, paged on ``_id``.

    ``--execute`` takes each batch out of the selector as it writes it, which the forward ``_id``
    paging is already indifferent to: a stamped document sits behind the cursor either way.
    """
    after_id: Any = None
    while True:
        selector: dict[str, Any] = dict(bare_source_filter())
        if after_id is not None:
            selector["_id"] = {"$gt": after_id}
        cursor = db.projects.find(selector, _PROJECT_PROJECTION).sort("_id", 1).limit(batch_size)
        batch = await cursor.to_list(batch_size)
        if not batch:
            return
        after_id = batch[-1]["_id"]
        yield batch
        if len(batch) < batch_size:
            return
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000)


async def apply_plan(db: Any, updates: list[SourceInstanceUpdate]) -> int:
    """Write the plan. Returns the number of matched documents."""
    matched = 0
    for update in updates:
        result = await db.projects.update_one({"_id": update.project_id}, {"$set": update.fields})
        matched += result.matched_count
    return matched


async def run_stamp(db: Any, *, batch_size: int, sleep_ms: int, execute: bool) -> tuple[int, int]:
    """Plan and optionally apply the stamping. Returns (planned, matched)."""
    instances = await resolve_instances(db)
    for provider, instance_id in sorted(instances.items()):
        print(f"[{provider}] bare values attributed to instance {instance_id}")

    planned = 0
    matched = 0
    async for batch in _iter_project_batches(db, batch_size, sleep_ms):
        plan = plan_instance_stamping(batch, instances)
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
    """Report the count and return the process exit code."""
    bare = await count_bare_sources(db)
    print(f"[VERIFY] {'projects with a bare source:':<{_REPORT_LABEL_WIDTH}}{bare}")
    if bare:
        # The image is already rolled by the time this gate runs; rolling it back is the one
        # response that turns these projects into 500s.
        print("GATE FAILED — run --execute. Do not roll the image back: it is what reads these values.")
        return EXIT_BARE_SOURCES_FOUND
    print("Gate passed — every provenance value names the instance that established the owner.")
    return 0


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        mode = "VERIFY" if args.verify else "EXECUTE" if args.execute else "DRY-RUN"
        print(f"[{mode}] Database: {db.name}")

        if args.verify:
            return await run_verify(db)

        planned, matched = await run_stamp(
            db,
            batch_size=args.batch_size,
            sleep_ms=args.sleep_ms,
            execute=args.execute,
        )
        _report(planned, matched if args.execute else None, mode)
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"backfill_team_source_instances: ERROR — {exc}", file=sys.stderr)
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
        help="Actually rewrite the provenance values (default: dry-run, report the plan only).",
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
            "Count projects still carrying a provenance value that names a provider and no "
            f"instance; exit {EXIT_BARE_SOURCES_FOUND} if any remain."
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
