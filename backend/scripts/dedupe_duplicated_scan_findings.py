"""One-off removal of finding documents a retried scan persisted more than once.

Before deterministic finding ids, delete-then-insert was neither atomic nor
idempotent, so a scan that raced its own retry could store its whole finding set
twice. Analytics over historical findings double-count those scans until the
surplus is removed.

A scan is only touched when its stored count is an exact integer multiple `k`
(>= 2) of the scan's own `findings_count`, and every identity group
(type, component, version, finding_id) within it divides by `k`. A finding set
may legitimately hold several documents of one identity — the engine keeps them
apart by an occurrence suffix — so collapsing each group to a single document
would delete real data. Scans that do not divide cleanly are reported and left
alone rather than guessed at.

Re-runnable: a repaired scan no longer matches the multiple test.

Usage (in-pod): `python -m scripts.dedupe_duplicated_scan_findings --help` from /app.

Exit codes:
    0 — completed (dry-run or execute)
    1 — connection or runtime error
"""

import argparse
import asyncio
import sys
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings

DEFAULT_BATCH_SIZE = 20
DEFAULT_SLEEP_MS = 100


def _surplus_ids(docs: list[dict[str, Any]], factor: int) -> tuple[list[Any], bool]:
    """Ids to delete so every identity group shrinks by `factor`; False when a group does not divide."""
    groups: dict[tuple[Any, Any, Any, Any], list[Any]] = {}
    for doc in docs:
        key = (doc.get("type"), doc.get("component"), doc.get("version"), doc.get("finding_id"))
        groups.setdefault(key, []).append(doc["_id"])

    surplus: list[Any] = []
    for ids in groups.values():
        if len(ids) % factor:
            return [], False
        keep = len(ids) // factor
        surplus.extend(sorted(ids, key=str)[keep:])
    return surplus, True


async def dedupe(db: Any, min_retry_count: int, batch_size: int, sleep_ms: int, execute: bool) -> dict[str, int]:
    counters = {"scans": 0, "deleted": 0, "skipped_uneven": 0}

    # Only a retried scan can have persisted its set twice; the default keeps the
    # per-scan count query off all 45k scans. Pass 0 to sweep everything.
    scan_filter: dict[str, Any] = {"findings_count": {"$gt": 0}}
    if min_retry_count > 0:
        scan_filter["retry_count"] = {"$gte": min_retry_count}
    cursor = db.scans.find(scan_filter, {"_id": 1, "findings_count": 1})
    candidates: list[tuple[str, int]] = []
    async for scan in cursor:
        scan_id = scan.get("_id")
        declared = scan.get("findings_count") or 0
        if not scan_id or declared <= 0:
            continue
        stored = await db.findings.count_documents({"scan_id": scan_id})
        if stored > declared and stored % declared == 0:
            candidates.append((scan_id, stored // declared))

    print(f"{len(candidates)} scan(s) store an exact multiple of their declared findings_count")

    processed_in_batch = 0
    for scan_id, factor in candidates:
        docs = await db.findings.find(
            {"scan_id": scan_id},
            {"type": 1, "component": 1, "version": 1, "finding_id": 1},
        ).to_list(None)
        surplus, even = _surplus_ids(docs, factor)
        if not even:
            counters["skipped_uneven"] += 1
            print(f"  SKIP {scan_id}: x{factor} overall but an identity group does not divide — inspect manually")
            continue

        counters["scans"] += 1
        counters["deleted"] += len(surplus)
        if execute and surplus:
            await db.findings.delete_many({"_id": {"$in": surplus}})

        processed_in_batch += 1
        if processed_in_batch >= batch_size:
            print(f"scans={counters['scans']} deleted={counters['deleted']}")
            processed_in_batch = 0
            if sleep_ms > 0:
                await asyncio.sleep(sleep_ms / 1000)

    return counters


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        mode = "EXECUTE" if args.execute else "DRY-RUN"
        total = await db.findings.estimated_document_count()
        print(f"[{mode}] Database: {db.name} — ~{total} finding(s)")

        counters = await dedupe(db, args.min_retry_count, args.batch_size, args.sleep_ms, args.execute)

        print()
        print(f"[{mode}] scans repaired:            {counters['scans']}")
        print(f"[{mode}] surplus findings deleted:  {counters['deleted']}")
        print(f"[{mode}] skipped (uneven groups):   {counters['skipped_uneven']}")
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"dedupe_duplicated_scan_findings: ERROR — {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually delete the surplus findings (default: dry-run, report only).",
    )
    parser.add_argument(
        "--min-retry-count",
        type=int,
        default=1,
        help="Only consider scans with at least this retry_count; 0 sweeps every scan (default: 1).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Scans processed between progress lines/sleeps (default: {DEFAULT_BATCH_SIZE}).",
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
    if args.min_retry_count < 0:
        parser.error("--min-retry-count must be >= 0")

    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
