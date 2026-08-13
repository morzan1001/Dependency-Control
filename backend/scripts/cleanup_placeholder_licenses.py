"""One-off removal of placeholder license sentinels from `dependency_enrichments`.

Enrichment no longer writes the deps.dev sentinels ("non-standard", "unknown",
"NOASSERTION"), but $set semantics never remove already-written values, so stale
docs keep them indefinitely. This unsets `license` where it holds a sentinel and
pulls sentinel entries from `licenses_detailed`.

Usage (in-pod): `python -m scripts.cleanup_placeholder_licenses --help` from /app.

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

DEFAULT_BATCH_SIZE = 500
DEFAULT_SLEEP_MS = 50

SENTINEL_MATCH = {"$regex": "^(non-standard|unknown|noassertion)$", "$options": "i"}


async def cleanup_pass(
    db: Any,
    label: str,
    query: dict[str, Any],
    update: dict[str, Any],
    batch_size: int,
    sleep_ms: int,
    execute: bool,
) -> dict[str, int]:
    counters = {"matched": 0, "updated": 0}
    last_id: Any = None

    while True:
        page: dict[str, Any] = dict(query)
        if last_id is not None:
            page["_id"] = {"$gt": last_id}
        batch = (
            await db.dependency_enrichments.find(page, {"_id": 1}).sort("_id", 1).limit(batch_size).to_list(batch_size)
        )
        if not batch:
            break

        ids = [doc["_id"] for doc in batch]
        counters["matched"] += len(ids)
        if execute:
            result = await db.dependency_enrichments.update_many({"_id": {"$in": ids}}, update)
            counters["updated"] += result.modified_count

        last_id = ids[-1]
        print(f"[{label}] matched={counters['matched']} updated={counters['updated']}")
        if len(batch) < batch_size:
            break
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000)

    return counters


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        mode = "EXECUTE" if args.execute else "DRY-RUN"
        total = await db.dependency_enrichments.estimated_document_count()
        print(f"[{mode}] Database: {db.name} — ~{total} dependency_enrichments doc(s)")

        license_counters = await cleanup_pass(
            db,
            "license",
            {"license": SENTINEL_MATCH},
            {"$unset": {"license": ""}},
            args.batch_size,
            args.sleep_ms,
            args.execute,
        )
        detailed_counters = await cleanup_pass(
            db,
            "licenses_detailed",
            {"licenses_detailed.spdx_id": SENTINEL_MATCH},
            {"$pull": {"licenses_detailed": {"spdx_id": SENTINEL_MATCH}}},
            args.batch_size,
            args.sleep_ms,
            args.execute,
        )

        print()
        print(f"[{mode}] docs with sentinel `license`:            {license_counters['matched']}")
        print(f"[{mode}] docs with `license` unset:               {license_counters['updated']}")
        print(f"[{mode}] docs with sentinel `licenses_detailed`:  {detailed_counters['matched']}")
        print(f"[{mode}] docs with entries pulled:                {detailed_counters['updated']}")
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"cleanup_placeholder_licenses: ERROR — {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually remove sentinel values (default: dry-run, report only).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Docs fetched per batch, with a progress line after each (default: {DEFAULT_BATCH_SIZE}).",
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
