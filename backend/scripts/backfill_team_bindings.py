"""Move every team's provider binding from the four scalars into the bindings array.

A team used to carry ``gitlab_instance_id``/``gitlab_group_id``/``gitlab_group_path`` and
``github_instance_id``/``github_org``/``github_team_id``/``github_team_slug`` — one binding per
provider, whatever the number of instances. ``bindings`` holds one entry per instance instead, each
carrying the composite key the unique index is on.

The run has two passes, and they are two deploy steps:

* ``--execute`` derives the entries and **keeps** the scalars. Both images read correctly from a
  team in that state, which is what makes the rolling update safe.
* ``--execute --drop-scalars`` derives them again — picking up whatever a not-yet-replaced pod
  wrote during the rollout — and unsets the scalars in the same update.

An entry is never overwritten: a team that already holds a binding for an instance keeps the one it
holds, because the array is what the new image writes and the scalars are what the old one wrote.

The planning half is pure so tests call it with plain dicts and no database.

``--verify`` is the gate on the contract pass: it counts the teams still carrying a scalar and
exits non-zero while any remain. See ``README-deploy-team-bindings.md``.

Usage (in-pod): `python -m scripts.backfill_team_bindings --help` from /app.

Exit codes:
    0 — completed (dry-run, execute, or a --verify that found nothing)
    1 — connection or runtime error
    2 — --verify found a team still carrying a scalar binding field
"""

import argparse
import asyncio
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings
from app.models.team import GitHubTeamBinding, GitLabGroupBinding

DEFAULT_BATCH_SIZE = 500
DEFAULT_SLEEP_MS = 50
_REPORT_LABEL_WIDTH = 30
EXIT_SCALAR_BINDINGS_FOUND = 2

# Every field the array replaces. The display fields are in it too: left behind they would go on
# naming a group the binding no longer points at.
SCALAR_FIELDS: tuple[str, ...] = (
    "gitlab_instance_id",
    "gitlab_group_id",
    "gitlab_group_path",
    "github_instance_id",
    "github_org",
    "github_team_id",
    "github_team_slug",
)

_TEAM_PROJECTION = {field_name: 1 for field_name in (*SCALAR_FIELDS, "bindings", "name")}


def scalar_binding_filter() -> dict[str, Any]:
    """Selects every team still carrying one of the scalar binding fields.

    Equivalent to the contract pass of ``plan_bindings`` expressed server-side, so a count of 0
    means a re-run would plan nothing. Presence, not truth: every team document carries all seven
    as an explicit null, and a null left behind is a field the model no longer declares.
    """
    return {"$or": [{field_name: {"$exists": True}} for field_name in SCALAR_FIELDS]}


async def count_scalar_bindings(db: Any) -> int:
    """How many teams still carry a scalar binding field."""
    return await db.teams.count_documents(scalar_binding_filter())


@dataclass(frozen=True)
class BindingUpdate:
    """One team's move into the array, as the update to apply."""

    team_id: str
    bindings: list[dict[str, Any]] | None = None
    unset: tuple[str, ...] = field(default_factory=tuple)

    def to_update(self) -> dict[str, Any]:
        update: dict[str, Any] = {}
        if self.bindings is not None:
            update["$set"] = {"bindings": self.bindings}
        if self.unset:
            update["$unset"] = dict.fromkeys(self.unset, "")
        return update


def _is_id(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def derive_bindings(team: dict[str, Any]) -> list[dict[str, Any]]:
    """The entries the team's scalars describe, in provider order.

    A half-filled pair is dropped: an instance without a group number addresses no group, so the
    binding it describes would resolve nothing while occupying the team's one entry per instance.
    """
    derived = []
    if team.get("gitlab_instance_id") and _is_id(team.get("gitlab_group_id")):
        derived.append(
            GitLabGroupBinding(
                instance_id=str(team["gitlab_instance_id"]),
                external_id=int(team["gitlab_group_id"]),
                path=team.get("gitlab_group_path"),
            ).model_dump()
        )
    if team.get("github_instance_id") and team.get("github_org") and _is_id(team.get("github_team_id")):
        derived.append(
            GitHubTeamBinding(
                instance_id=str(team["github_instance_id"]),
                org=str(team["github_org"]),
                external_id=int(team["github_team_id"]),
                slug=team.get("github_team_slug"),
            ).model_dump()
        )
    return derived


def plan_bindings(teams: list[dict[str, Any]], *, drop_scalars: bool) -> list[BindingUpdate]:
    """One update per team that has something to move, or a scalar to shed once ``drop_scalars``."""
    plan: list[BindingUpdate] = []
    for team in teams:
        stored = list(team.get("bindings") or [])
        held = {binding.get("instance_id") for binding in stored}
        added = [binding for binding in derive_bindings(team) if binding["instance_id"] not in held]
        unset = tuple(name for name in SCALAR_FIELDS if name in team) if drop_scalars else ()
        if added or unset:
            plan.append(BindingUpdate(str(team["_id"]), [*stored, *added] if added else None, unset))
    return plan


async def _iter_team_batches(db: Any, batch_size: int) -> AsyncIterator[list[dict[str, Any]]]:
    """The teams still carrying a scalar, paged on ``_id``.

    One selector for both passes — only the update differs. The contract pass takes each batch out
    of it as it writes, which the forward ``_id`` paging is already indifferent to.
    """
    after_id: Any = None
    while True:
        selector: dict[str, Any] = dict(scalar_binding_filter())
        if after_id is not None:
            selector = {"$and": [selector, {"_id": {"$gt": after_id}}]}
        cursor = db.teams.find(selector, _TEAM_PROJECTION).sort("_id", 1).limit(batch_size)
        batch = await cursor.to_list(batch_size)
        if not batch:
            return
        after_id = batch[-1]["_id"]
        yield batch
        if len(batch) < batch_size:
            return


async def apply_plan(db: Any, updates: list[BindingUpdate]) -> int:
    """Write the plan. Returns the number of matched documents."""
    matched = 0
    for update in updates:
        result = await db.teams.update_one({"_id": update.team_id}, update.to_update())
        matched += result.matched_count
    return matched


async def run_move(db: Any, *, batch_size: int, sleep_ms: int, execute: bool, drop_scalars: bool) -> tuple[int, int]:
    """Plan and optionally apply the move. Returns (planned, matched)."""
    planned = 0
    matched = 0
    async for batch in _iter_team_batches(db, batch_size):
        plan = plan_bindings(batch, drop_scalars=drop_scalars)
        planned += len(plan)
        if execute and plan:
            matched += await apply_plan(db, plan)
        print(f"batched={len(batch)} planned={planned} matched={matched if execute else 'N/A'}")
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000)

    return planned, matched


def _report(planned: int, matched: int | None, mode: str) -> None:
    counts = [("teams planned", planned)]
    if matched is not None:
        counts.append(("teams matched", matched))
    print()
    for label, value in counts:
        print(f"[{mode}] {label + ':':<{_REPORT_LABEL_WIDTH}}{value}")


async def run_verify(db: Any) -> int:
    """Report the count and return the process exit code."""
    remaining = await count_scalar_bindings(db)
    print(f"[VERIFY] {'teams with a scalar binding:':<{_REPORT_LABEL_WIDTH}}{remaining}")
    if remaining:
        print("GATE FAILED — run --execute --drop-scalars before claiming the cutover is complete.")
        return EXIT_SCALAR_BINDINGS_FOUND
    print("Gate passed — every binding lives in the array and no team carries a scalar.")
    return 0


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        pass_name = "CONTRACT" if args.drop_scalars else "EXPAND"
        mode = "VERIFY" if args.verify else f"{'EXECUTE' if args.execute else 'DRY-RUN'} {pass_name}"
        print(f"[{mode}] Database: {db.name}")

        if args.verify:
            return await run_verify(db)

        planned, matched = await run_move(
            db,
            batch_size=args.batch_size,
            sleep_ms=args.sleep_ms,
            execute=args.execute,
            drop_scalars=args.drop_scalars,
        )
        _report(planned, matched if args.execute else None, mode)
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"backfill_team_bindings: ERROR — {exc}", file=sys.stderr)
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
        help="Actually write the bindings (default: dry-run, report the plan only).",
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
            "Count teams still carrying a scalar binding field; "
            f"exit {EXIT_SCALAR_BINDINGS_FOUND} if any remain."
        ),
    )
    parser.set_defaults(execute=False)
    parser.add_argument(
        "--drop-scalars",
        action="store_true",
        help=(
            "The contract pass: derive the entries and unset the scalars in the same update. "
            "Only after every pod runs the image that reads the array."
        ),
    )
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

    if args.verify and args.drop_scalars:
        parser.error("--verify reports on the contract pass; it does not run one")
    if args.batch_size < 1:
        parser.error("--batch-size must be >= 1")
    if args.sleep_ms < 0:
        parser.error("--sleep-ms must be >= 0")

    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
