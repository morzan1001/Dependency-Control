"""Name the instance in every member provenance value a team carries.

``teams.members[].source`` used to record a provider alone. With two instances of one provider
bound to a team, both syncs claim the same member subset and the list follows whichever ingested
last; with both providers bound, each sync used to relabel the other's members as hand-added, after
which no sync ever refreshed them again. This migration rewrites every bare ``gitlab`` / ``github``
value to ``<provider>:<instance id>``. ``manual`` is never touched, and neither is a member
carrying no ``source`` at all: the model reads an absent value as ``manual`` already, and writing
one would claim a human added a member whose origin nothing records.

The instance is resolved from the database, not passed in: exactly one instance per provider has
team sync enabled, and that is the only one that can have written a member provenance value. A
provider whose bare values are present while its instance count is anything other than one aborts
the run rather than guessing — a value naming the wrong instance hands that member to that
instance's next sync to drop.

The planning half is pure so tests call it with plain dicts and no database.

``--verify`` is the gate on this migration, which runs *after* the image that reads the new format:
it counts the teams still carrying a bare provider value and exits non-zero while any remain.
See ``README-deploy-member-provenance.md``.

Usage (in-pod): `python -m scripts.backfill_team_member_sources --help` from /app.

Exit codes:
    0 — completed (dry-run, execute, or a --verify that found nothing)
    1 — connection or runtime error, including a provider whose instance cannot be resolved
    2 — --verify found a member still carrying a bare provider value
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

# The same rule as the ownership provenance migration, and deliberately the one definition of it:
# two spellings of "which instance may be attributed" is two chances to attribute differently.
from scripts.backfill_team_source_instances import resolve_sync_instance

DEFAULT_BATCH_SIZE = 500
DEFAULT_SLEEP_MS = 50
_REPORT_LABEL_WIDTH = 30
EXIT_BARE_MEMBERS_FOUND = 2

_MEMBER_SOURCE = "members.source"
_TEAM_PROJECTION = {"_id": 1, _MEMBER_SOURCE: 1}


def bare_member_filter(providers: tuple[str, ...] = TEAM_SOURCE_PROVIDERS) -> dict[str, Any]:
    """Selects every team holding a member whose provenance names a provider and no instance.

    Equivalent to ``plan_member_stamping`` expressed server-side, so a count of 0 means a re-run of
    this migration would plan nothing.

    ``manual``, an absent value, and any value already carrying an instance match none of it.
    """
    return {_MEMBER_SOURCE: {"$in": list(providers)}}


async def count_bare_members(db: Any, providers: tuple[str, ...] = TEAM_SOURCE_PROVIDERS) -> int:
    """How many teams still hold a member whose provenance names no instance."""
    return await db.teams.count_documents(bare_member_filter(providers))


async def resolve_instances(db: Any) -> dict[str, str]:
    """The instance id per provider that still has bare member values to attribute.

    Only the providers that appear are resolved: a single-provider installation must not be blocked
    by the other provider having no instance at all.
    """
    instances: dict[str, str] = {}
    for provider in TEAM_SOURCE_PROVIDERS:
        if await count_bare_members(db, (provider,)):
            instances[provider] = await resolve_sync_instance(db, provider)
    return instances


@dataclass(frozen=True)
class MemberSourceUpdate:
    """One team's rewritten member provenance, as the bare value each stamped one replaces."""

    team_id: str
    stamped: dict[str, str]
    members: int


@dataclass(frozen=True)
class StampCounts:
    teams_planned: int
    teams_matched: int
    members_planned: int


def plan_member_stamping(teams: list[dict[str, Any]], instances: dict[str, str]) -> list[MemberSourceUpdate]:
    """One update per team holding a bare provider value, rewriting only those values.

    A value already naming an instance is left exactly as stored: this migration attributes the
    values that predate instance ids, and re-attributing one would move a member between instances.
    """
    plan: list[MemberSourceUpdate] = []
    for team in teams:
        bare = [member.get("source") for member in team.get("members") or [] if member.get("source") in instances]
        if not bare:
            continue
        plan.append(
            MemberSourceUpdate(
                team_id=str(team["_id"]),
                stamped={provider: team_source(provider, instances[provider]) for provider in sorted(set(bare))},
                members=len(bare),
            )
        )
    return plan


async def _iter_team_batches(db: Any, batch_size: int, sleep_ms: int) -> AsyncIterator[list[dict[str, Any]]]:
    """The teams holding a bare value, paged on ``_id``.

    ``--execute`` takes each batch out of the selector as it writes it, which the forward ``_id``
    paging is already indifferent to: a stamped document sits behind the cursor either way.
    """
    after_id: Any = None
    while True:
        selector: dict[str, Any] = dict(bare_member_filter())
        if after_id is not None:
            selector["_id"] = {"$gt": after_id}
        cursor = db.teams.find(selector, _TEAM_PROJECTION).sort("_id", 1).limit(batch_size)
        batch = await cursor.to_list(batch_size)
        if not batch:
            return
        after_id = batch[-1]["_id"]
        yield batch
        if len(batch) < batch_size:
            return
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000)


async def apply_plan(db: Any, updates: list[MemberSourceUpdate]) -> int:
    """Write the plan. Returns the number of matched documents.

    Addressed member by member rather than by replacing the array, so a member added or removed
    between the read and this write survives it. The array-filter identifier is the provider name
    and so is the value it selects on, because a bare value *is* the bare provider name.
    """
    matched = 0
    for update in updates:
        result = await db.teams.update_one(
            {"_id": update.team_id},
            {"$set": {f"members.$[{provider}].source": stamped for provider, stamped in update.stamped.items()}},
            array_filters=[{f"{provider}.source": provider} for provider in update.stamped],
        )
        matched += result.matched_count
    return matched


async def run_stamp(db: Any, *, batch_size: int, sleep_ms: int, execute: bool) -> StampCounts:
    """Plan and optionally apply the stamping."""
    instances = await resolve_instances(db)
    for provider, instance_id in sorted(instances.items()):
        print(f"[{provider}] bare member values attributed to instance {instance_id}")

    teams_planned = 0
    teams_matched = 0
    members_planned = 0
    async for batch in _iter_team_batches(db, batch_size, sleep_ms):
        plan = plan_member_stamping(batch, instances)
        teams_planned += len(plan)
        members_planned += sum(update.members for update in plan)
        if execute and plan:
            teams_matched += await apply_plan(db, plan)
        print(
            f"batched={len(batch)} planned={teams_planned} "
            f"members={members_planned} matched={teams_matched if execute else 'N/A'}"
        )

    return StampCounts(teams_planned, teams_matched, members_planned)


def _report(counts: StampCounts, mode: str, execute: bool) -> None:
    lines = [("teams planned", counts.teams_planned), ("members planned", counts.members_planned)]
    if execute:
        lines.append(("teams matched", counts.teams_matched))
    print()
    for label, value in lines:
        print(f"[{mode}] {label + ':':<{_REPORT_LABEL_WIDTH}}{value}")


async def run_verify(db: Any) -> int:
    """Report the count and return the process exit code."""
    bare = await count_bare_members(db)
    print(f"[VERIFY] {'teams with a bare member source:':<{_REPORT_LABEL_WIDTH}}{bare}")
    if bare:
        # The image is already rolled by the time this gate runs, and it is the one that reads a
        # bare value as nobody's. Rolling it back leaves those members unrefreshable either way.
        print("GATE FAILED — run --execute. Do not roll the image back: it is what reads these values.")
        return EXIT_BARE_MEMBERS_FOUND
    print("Gate passed — every member provenance value names the instance that added the member.")
    return 0


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        mode = "VERIFY" if args.verify else "EXECUTE" if args.execute else "DRY-RUN"
        print(f"[{mode}] Database: {db.name}")

        if args.verify:
            return await run_verify(db)

        counts = await run_stamp(
            db,
            batch_size=args.batch_size,
            sleep_ms=args.sleep_ms,
            execute=args.execute,
        )
        _report(counts, mode, args.execute)
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"backfill_team_member_sources: ERROR — {exc}", file=sys.stderr)
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
        help="Actually rewrite the member provenance values (default: dry-run, report the plan only).",
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
            "Count teams still holding a member whose provenance names a provider and no "
            f"instance; exit {EXIT_BARE_MEMBERS_FOUND} if any remain."
        ),
    )
    parser.set_defaults(execute=False)
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Teams fetched per batch, with a progress line after each (default: {DEFAULT_BATCH_SIZE}).",
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
