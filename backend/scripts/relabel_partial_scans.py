"""One-off relabel of historical partial scans to `completed_with_errors`.

A scan that carries a `SCAN-ERROR-*` finding had an analyzer crash, time out or
return partial coverage. Before this release such scans stayed `completed`, so
they were indistinguishable from a clean run. New scans get the honest status
from the engine; this backfills the ~1,831 historical ones and fills
`failed_analyzers` from the finding ids.

A scan is skipped when it has zero dependencies AND zero non-system findings:
that is the all-SBOMs-failed shape, which maps to `failed`, not to a partial
success. Production has none; any hit is reported for manual handling rather
than guessed at.

Re-runnable: already-relabelled scans no longer match the `completed` filter.

Usage (in-pod): `python -m scripts.relabel_partial_scans --help` from /app.

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
from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS

DEFAULT_BATCH_SIZE = 200
DEFAULT_SLEEP_MS = 50

_SCAN_ERROR_PREFIX = "SCAN-ERROR-"
_SYSTEM_WARNING = "system_warning"


async def _collect_error_analyzers(db: Any) -> dict[str, list[str]]:
    """scan_id -> sorted analyzer names taken from that scan's SCAN-ERROR finding ids."""
    by_scan: dict[str, set[str]] = {}
    cursor = db.findings.find(
        {"finding_id": {"$regex": f"^{_SCAN_ERROR_PREFIX}"}},
        {"scan_id": 1, "finding_id": 1},
    )
    async for doc in cursor:
        scan_id = doc.get("scan_id")
        finding_id = doc.get("finding_id") or ""
        if not scan_id:
            continue
        analyzer = finding_id[len(_SCAN_ERROR_PREFIX) :]
        if analyzer:
            by_scan.setdefault(scan_id, set()).add(analyzer)
    return {scan_id: sorted(names) for scan_id, names in by_scan.items()}


async def _is_all_failed_shape(db: Any, scan_id: str) -> bool:
    """True when nothing survived the run: no dependencies and no finding other than the errors."""
    if await db.dependencies.count_documents({"scan_id": scan_id}, limit=1):
        return False
    return not await db.findings.count_documents(
        {"scan_id": scan_id, "type": {"$ne": _SYSTEM_WARNING}},
        limit=1,
    )


async def relabel(db: Any, batch_size: int, sleep_ms: int, execute: bool) -> dict[str, int]:
    counters = {"candidates": 0, "relabelled": 0, "analyzers_filled": 0, "skipped_all_failed": 0, "latest_run": 0}

    by_scan = await _collect_error_analyzers(db)
    print(f"{len(by_scan)} scan(s) carry a {_SCAN_ERROR_PREFIX}* finding")

    relabelled_ids: list[str] = []
    processed_in_batch = 0
    for scan_id, analyzers in sorted(by_scan.items()):
        scan = await db.scans.find_one({"_id": scan_id}, {"status": 1, "failed_analyzers": 1, "latest_run": 1})
        if not scan or scan.get("status") != SCAN_STATUS_COMPLETED:
            continue
        counters["candidates"] += 1

        if await _is_all_failed_shape(db, scan_id):
            counters["skipped_all_failed"] += 1
            print(
                f"  SKIP {scan_id}: no dependencies and no non-system findings — belongs in `failed`, decide manually"
            )
            continue

        update: dict[str, Any] = {"status": SCAN_STATUS_COMPLETED_WITH_ERRORS}
        if not scan.get("failed_analyzers"):
            update["failed_analyzers"] = analyzers
            counters["analyzers_filled"] += 1
        latest_run = scan.get("latest_run") or {}
        if latest_run.get("scan_id") == scan_id and latest_run.get("status") == SCAN_STATUS_COMPLETED:
            update["latest_run.status"] = SCAN_STATUS_COMPLETED_WITH_ERRORS
            counters["latest_run"] += 1

        counters["relabelled"] += 1
        relabelled_ids.append(scan_id)
        if execute:
            await db.scans.update_one({"_id": scan_id}, {"$set": update})

        processed_in_batch += 1
        if processed_in_batch >= batch_size:
            print(f"candidates={counters['candidates']} relabelled={counters['relabelled']}")
            processed_in_batch = 0
            if sleep_ms > 0:
                await asyncio.sleep(sleep_ms / 1000)

    # The Pipelines table renders `latest_run` in preference to the scan's own fields, so an
    # original scan superseded by a relabelled rescan would keep showing "completed".
    if relabelled_ids:
        mirror_filter = {
            "latest_run.scan_id": {"$in": relabelled_ids},
            "latest_run.status": SCAN_STATUS_COMPLETED,
        }
        mirrored = await db.scans.count_documents(mirror_filter)
        counters["latest_run"] += mirrored
        if execute and mirrored:
            await db.scans.update_many(
                mirror_filter,
                {"$set": {"latest_run.status": SCAN_STATUS_COMPLETED_WITH_ERRORS}},
            )

    return counters


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        mode = "EXECUTE" if args.execute else "DRY-RUN"
        total = await db.scans.estimated_document_count()
        print(f"[{mode}] Database: {db.name} — ~{total} scan(s)")

        counters = await relabel(db, args.batch_size, args.sleep_ms, args.execute)

        print()
        print(f"[{mode}] completed scans with scanner errors: {counters['candidates']}")
        print(f"[{mode}] relabelled completed_with_errors:    {counters['relabelled']}")
        print(f"[{mode}] failed_analyzers backfilled:         {counters['analyzers_filled']}")
        print(f"[{mode}] latest_run.status corrected:         {counters['latest_run']}")
        print(f"[{mode}] skipped (all-failed shape):          {counters['skipped_all_failed']}")
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"relabel_partial_scans: ERROR — {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually relabel the scans (default: dry-run, report only).",
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

    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
