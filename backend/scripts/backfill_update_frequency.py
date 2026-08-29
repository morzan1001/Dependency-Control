"""Backfill the per-scan update-frequency delta ledger for scans ingested before the writer existed.

Feeds every usable non-rescan scan to `record_scan_update_delta` (the runtime writer — no
duplicated diff formula), one (project, branch) chain at a time and oldest scan first. That
order matters twice: the predecessor lookup reads `scan_update_deltas`, so a newer scan
processed first finds nothing and is stored as a baseline, and the writer's self-repair then
rewrites it once the older scan arrives — doubling the most expensive part of the run.
Chains are independent, so `--concurrency` parallelises across them but never inside one.

Resuming after an abort needs no checkpoint file: the ledger is the checkpoint. A scan is
skipped when it already has a delta at the current schema version that records no failure.
A schema bump therefore recomputes everything (the read path ignores older documents anyway),
and a scan whose delta holds an `error` is retried rather than counted as done.

Operational cost, and where the defaults come from
--------------------------------------------------
The full history is 50,422 scans. For each one the writer reads two dependency sets — the
scan's own and its predecessor's, ~371 documents each — out of a 16.0 M document / 34 GB
collection sitting behind a ~1.5 GB WiredTiger cache. That is ~740 documents (~1.6 MB) per
scan, or ~79 GB over the whole run against a cache 23x too small to hold the collection:
essentially every read is a miss and evicts whatever the API and the ingest were using.
There is no rate that avoids this, only rates that leave gaps for the rest of the system.

The live comparison walks 30,159 scans in 206 s at concurrency 3, i.e. ~20 ms of serial work
per scan with one dependency set; two sets plus the predecessor lookup and two upserts put
this writer at ~40 ms. With the defaults (concurrency 2, 100 ms sleep) one worker manages
~7 scans/s, so ~14/s in total — about 10,000 dependency documents/s, ~22 MB/s of cache churn:

    full history   50,422 / 14  ~= 60 min
    --since-days 90  30,159 / 14  ~= 36 min   (all the comparison window ever reads)

Concurrency 2 keeps the job inside one of mongod's two cores. `--sleep-ms 0 --concurrency 4`
finishes the full history in ~8 min at ~74 MB/s of churn; that belongs in a maintenance
window, not next to live traffic.

Backfilling only part of the history is safe for the metrics: the fold treats the oldest
scan of its window as an anchor and discards its update counts either way. Backfill at least
as far back as the widest window that will be served.

Usage (in-pod): `python -m scripts.backfill_update_frequency --help` from /app.

Exit codes:
    0 — completed (dry-run or execute)
    1 — connection or runtime error
    2 — refused: UPDATE_FREQUENCY_ROLLUP_ENABLED is off, so the writer would record nothing
"""

import argparse
import asyncio
import sys
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings
from app.core.constants import SCAN_USABLE_STATUSES
from app.models.update_frequency import UPDATE_DELTA_SCHEMA_VERSION
from app.services.update_frequency_rollup import record_scan_update_delta

DEFAULT_CONCURRENCY = 2
DEFAULT_SLEEP_MS = 100
DEFAULT_BATCH_SIZE = 500

# Serial cost of one scan for the writer, from the measurement in the module docstring.
_SECONDS_PER_SCAN = 0.04

# BSON type bracketing: a date floor also excludes scans whose created_at is missing or a
# string, which have no place on a timeline and which the writer skips anyway.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

_PROGRESS_EVERY = 500

Chain = tuple[str, str]


def scan_filter(since: datetime | None, project_id: str | None) -> dict[str, Any]:
    """Scans the writer would accept: usable status, not a rescan, dated."""
    query: dict[str, Any] = {
        "status": {"$in": SCAN_USABLE_STATUSES},
        "is_rescan": {"$ne": True},
        "created_at": {"$gte": since or _EPOCH},
    }
    if project_id:
        query["project_id"] = project_id
    return query


async def find_chains(db: Any, since: datetime | None, project_id: str | None) -> list[tuple[Chain, int]]:
    """Every (project, branch) chain in scope with its scan count, in a stable order."""
    rows = await db.scans.aggregate(
        [
            {"$match": scan_filter(since, project_id)},
            {"$group": {"_id": {"p": "$project_id", "b": "$branch"}, "scans": {"$sum": 1}}},
        ]
    ).to_list(None)
    chains = []
    for row in rows:
        # A grouping key drops the field entirely when a document lacks it. A scan that
        # names no branch has nothing to be diffed against, and both read paths skip it.
        project, branch = row["_id"].get("p"), row["_id"].get("b")
        if isinstance(project, str) and isinstance(branch, str) and branch:
            chains.append(((project, branch), row["scans"]))
    return sorted(chains, key=lambda entry: entry[0])


async def iter_chain_scans(
    db: Any, chain: Chain, since: datetime | None, batch_size: int
) -> AsyncIterator[dict[str, Any]]:
    """Scans of one chain, oldest first, paged on ``(created_at, _id)``."""
    project_id, branch = chain
    cursor_at: datetime | None = None
    cursor_id: str | None = None
    while True:
        query = scan_filter(since, None) | {"project_id": project_id, "branch": branch}
        if cursor_at is not None:
            query["$or"] = [
                {"created_at": {"$gt": cursor_at}},
                {"created_at": cursor_at, "_id": {"$gt": cursor_id}},
            ]
        batch = (
            await db.scans.find(query, {"_id": 1, "created_at": 1})
            .sort([("created_at", 1), ("_id", 1)])
            .limit(batch_size)
            .to_list(batch_size)
        )
        if not batch:
            return
        for doc in batch:
            yield doc
        cursor_at, cursor_id = batch[-1]["created_at"], batch[-1]["_id"]
        if len(batch) < batch_size:
            return


async def recorded_scan_ids(db: Any, chain: Chain, since: datetime | None) -> set[str]:
    """Scans of the chain whose delta is current: this schema version and no recorded failure."""
    project_id, branch = chain
    query: dict[str, Any] = {
        "project_id": project_id,
        "branch": branch,
        "schema_version": UPDATE_DELTA_SCHEMA_VERSION,
        "error": None,
    }
    if since is not None:
        query["scan_created_at"] = {"$gte": since}
    docs = await db.scan_update_deltas.find(query, {"_id": 1}).to_list(None)
    return {doc["_id"] for doc in docs}


async def backfill_chain(
    db: Any,
    chain: Chain,
    since: datetime | None,
    counters: dict[str, int],
    *,
    batch_size: int,
    sleep_ms: int,
    execute: bool,
) -> None:
    recorded = await recorded_scan_ids(db, chain, since)
    async for scan in iter_chain_scans(db, chain, since, batch_size):
        if scan["_id"] in recorded:
            counters["skipped_recorded"] += 1
            continue
        counters["to_record"] += 1
        if not execute:
            continue
        await record_scan_update_delta(db, scan["_id"])
        counters["recorded"] += 1
        if counters["recorded"] % _PROGRESS_EVERY == 0:
            print(f"recorded={counters['recorded']} skipped_recorded={counters['skipped_recorded']}")
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000)


async def backfill(
    db: Any,
    chains: list[tuple[Chain, int]],
    since: datetime | None,
    *,
    concurrency: int,
    batch_size: int,
    sleep_ms: int,
    execute: bool,
) -> dict[str, int]:
    counters = {"chains": len(chains), "to_record": 0, "recorded": 0, "skipped_recorded": 0}
    semaphore = asyncio.Semaphore(concurrency)

    async def _run(chain: Chain) -> None:
        async with semaphore:
            await backfill_chain(
                db,
                chain,
                since,
                counters,
                batch_size=batch_size,
                sleep_ms=sleep_ms,
                execute=execute,
            )

    await asyncio.gather(*(_run(chain) for chain, _count in chains))
    return counters


def estimated_seconds(scans: int, *, concurrency: int, sleep_ms: int) -> float:
    return scans * (_SECONDS_PER_SCAN + sleep_ms / 1000) / concurrency


async def count_failed_deltas(db: Any, since: datetime | None, project_id: str | None) -> int:
    query: dict[str, Any] = {"error": {"$ne": None}}
    if since is not None:
        query["scan_created_at"] = {"$gte": since}
    if project_id:
        query["project_id"] = project_id
    return int(await db.scan_update_deltas.count_documents(query))


async def run(args: argparse.Namespace) -> int:
    if not settings.UPDATE_FREQUENCY_ROLLUP_ENABLED:
        print(
            "backfill_update_frequency: REFUSED — UPDATE_FREQUENCY_ROLLUP_ENABLED is off, "
            "so record_scan_update_delta returns without writing anything.",
            file=sys.stderr,
        )
        return 2

    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        since = datetime.now(tz=timezone.utc) - timedelta(days=args.since_days) if args.since_days else None
        mode = "EXECUTE" if args.execute else "DRY-RUN"

        chains = await find_chains(db, since, args.project_id)
        total_scans = sum(count for _chain, count in chains)
        window = f"last {args.since_days} day(s)" if since else "all time"
        scope = args.project_id or "every project"
        print(f"[{mode}] Database: {db.name} — {scope}, {window}")
        print(f"[{mode}] {total_scans} scan(s) across {len(chains)} (project, branch) chain(s)")
        estimate = estimated_seconds(total_scans, concurrency=args.concurrency, sleep_ms=args.sleep_ms)
        print(f"[{mode}] estimated {estimate / 60:.0f} min at concurrency {args.concurrency}, {args.sleep_ms} ms sleep")

        counters = await backfill(
            db,
            chains,
            since,
            concurrency=args.concurrency,
            batch_size=args.batch_size,
            sleep_ms=args.sleep_ms,
            execute=args.execute,
        )
        failed = await count_failed_deltas(db, since, args.project_id)

        print()
        print(f"[{mode}] chains:                    {counters['chains']}")
        print(f"[{mode}] scans already recorded:    {counters['skipped_recorded']}")
        print(f"[{mode}] scans needing a delta:     {counters['to_record']}")
        print(f"[{mode}] deltas written:            {counters['recorded']}")
        print(f"[{mode}] deltas in scope holding an error: {failed}")
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"backfill_update_frequency: ERROR — {exc}", file=sys.stderr)
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
        help="Actually write the deltas (default: dry-run, report the plan only).",
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
        "--since-days",
        type=int,
        default=0,
        help="Only backfill scans from the last N days; 0 = the whole history (default).",
    )
    parser.add_argument(
        "--project-id",
        help="Restrict the run to one project.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"(project, branch) chains backfilled in parallel (default: {DEFAULT_CONCURRENCY}).",
    )
    parser.add_argument(
        "--sleep-ms",
        type=int,
        default=DEFAULT_SLEEP_MS,
        help=f"Milliseconds each worker sleeps after every recorded scan (default: {DEFAULT_SLEEP_MS}).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Scans fetched per page while walking a chain (default: {DEFAULT_BATCH_SIZE}).",
    )
    args = parser.parse_args()

    if args.since_days < 0:
        parser.error("--since-days must be >= 0")
    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")
    if args.sleep_ms < 0:
        parser.error("--sleep-ms must be >= 0")
    if args.batch_size < 1:
        parser.error("--batch-size must be >= 1")

    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
