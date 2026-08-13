"""One-off backfill of scan/project risk scores onto the saturating severity-weighted scale.

Recomputes stats.risk_score and stats.adjusted_risk_score for every scan that has a
stats block by re-running calculate_comprehensive_stats (the runtime path — no
duplicated formula), then mirrors the scores onto each project's stats for its
latest_scan_id. Scans whose stored stats count findings that no longer exist in the
findings collection are skipped, not zeroed.

Usage (in-pod): `python -m scripts.backfill_risk_scores --help` from /app.

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
from app.models.stats import Stats
from app.services.analysis.stats import calculate_comprehensive_stats

DEFAULT_BATCH_SIZE = 500
DEFAULT_SLEEP_MS = 50

_BUCKET_FIELDS = ("critical", "high", "medium", "low", "negligible", "info", "unknown")


def _bucket_total(stats: dict[str, Any]) -> int:
    return sum(int(stats.get(field) or 0) for field in _BUCKET_FIELDS)


def _scores_differ(stored: dict[str, Any], computed: Stats) -> bool:
    stored_risk = stored.get("risk_score")
    stored_adjusted = stored.get("adjusted_risk_score")
    return (
        stored_risk is None
        or round(float(stored_risk), 1) != computed.risk_score
        or stored_adjusted is None
        or round(float(stored_adjusted), 1) != computed.adjusted_risk_score
    )


async def backfill_scans(db: Any, batch_size: int, sleep_ms: int, limit: int, execute: bool) -> dict[str, Any]:
    counters = {"processed": 0, "would_update": 0, "updated": 0, "unchanged": 0, "skipped_no_findings": 0}
    new_scores: dict[str, tuple[float, float]] = {}
    last_id: Any = None

    while True:
        query: dict[str, Any] = {"stats": {"$exists": True}}
        if last_id is not None:
            query["_id"] = {"$gt": last_id}
        batch = await db.scans.find(query, {"_id": 1, "stats": 1}).sort("_id", 1).limit(batch_size).to_list(batch_size)
        if not batch:
            break

        for doc in batch:
            scan_id = doc["_id"]
            stored = doc.get("stats") or {}
            computed = await calculate_comprehensive_stats(db, scan_id)

            counters["processed"] += 1
            if _bucket_total(computed.model_dump()) == 0 and _bucket_total(stored) > 0:
                # Findings for this scan are gone (pruned/never persisted); zeroing the
                # stored score would fabricate a clean bill of health.
                counters["skipped_no_findings"] += 1
            elif _scores_differ(stored, computed):
                counters["would_update"] += 1
                new_scores[scan_id] = (computed.risk_score, computed.adjusted_risk_score)
                if execute:
                    await db.scans.update_one(
                        {"_id": scan_id},
                        {
                            "$set": {
                                "stats.risk_score": computed.risk_score,
                                "stats.adjusted_risk_score": computed.adjusted_risk_score,
                            }
                        },
                    )
                    counters["updated"] += 1
            else:
                counters["unchanged"] += 1

            if limit and counters["processed"] >= limit:
                print(f"Reached --limit {limit}.")
                counters["new_scores"] = new_scores
                return counters

        last_id = batch[-1]["_id"]
        print(
            f"processed={counters['processed']} would_update={counters['would_update']} "
            f"updated={counters['updated']} unchanged={counters['unchanged']} "
            f"skipped_no_findings={counters['skipped_no_findings']}"
        )
        if len(batch) < batch_size:
            break
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000)

    counters["new_scores"] = new_scores
    return counters


async def mirror_projects(db: Any, new_scores: dict[str, tuple[float, float]], execute: bool) -> dict[str, int]:
    counters = {"projects_would_update": 0, "projects_updated": 0}
    cursor = db.projects.find(
        {"latest_scan_id": {"$in": list(new_scores.keys())}},
        {"_id": 1, "latest_scan_id": 1, "stats.risk_score": 1, "stats.adjusted_risk_score": 1},
    )
    async for project in cursor:
        risk, adjusted = new_scores[project["latest_scan_id"]]
        stored = project.get("stats") or {}
        if stored.get("risk_score") == risk and stored.get("adjusted_risk_score") == adjusted:
            continue
        counters["projects_would_update"] += 1
        if execute:
            await db.projects.update_one(
                {"_id": project["_id"]},
                {"$set": {"stats.risk_score": risk, "stats.adjusted_risk_score": adjusted}},
            )
            counters["projects_updated"] += 1
    return counters


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        total = await db.scans.count_documents({"stats": {"$exists": True}}, maxTimeMS=120_000)
        mode = "EXECUTE" if args.execute else "DRY-RUN"
        print(f"[{mode}] Database: {db.name} — {total} scan(s) with a stats block")

        counters = await backfill_scans(db, args.batch_size, args.sleep_ms, args.limit, args.execute)
        new_scores = counters.pop("new_scores")
        project_counters = await mirror_projects(db, new_scores, args.execute)

        print()
        print(f"[{mode}] scans processed:           {counters['processed']}")
        print(f"[{mode}] scans needing new scores:  {counters['would_update']}")
        print(f"[{mode}] scans updated:             {counters['updated']}")
        print(f"[{mode}] scans unchanged:           {counters['unchanged']}")
        print(f"[{mode}] scans skipped (no findings for non-zero stats): {counters['skipped_no_findings']}")
        print(f"[{mode}] projects needing mirror:   {project_counters['projects_would_update']}")
        print(f"[{mode}] projects updated:          {project_counters['projects_updated']}")
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"backfill_risk_scores: ERROR — {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually write recomputed scores (default: dry-run, report only).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Scans fetched per batch, with a progress line after each (default: {DEFAULT_BATCH_SIZE}).",
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
        default=0,
        help="Stop after N scans; 0 = all (default). Useful for a smoke test.",
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
