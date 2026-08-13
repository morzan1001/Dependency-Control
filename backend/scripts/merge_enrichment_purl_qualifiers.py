"""One-off merge of `dependency_enrichments` docs onto the canonical purl key.

Enrichment reads/writes now key on the canonical purl (qualifiers/subpath
stripped), so docs stored under qualifier variants like `?type=jar` are
unreachable and duplicate sets (`?classifier=...` siblings) must collapse to
one doc. For every canonical base this re-keys the surviving doc to the
canonical purl, fills its missing fields from sibling variants, and deletes
the siblings.

Usage (in-pod): `python -m scripts.merge_enrichment_purl_qualifiers --help` from /app.

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
from app.services.analyzers.purl_utils import canonical_purl

DEFAULT_BATCH_SIZE = 200
DEFAULT_SLEEP_MS = 50

_IMMUTABLE_KEYS = {"_id", "purl"}


def _pick_survivor(docs: list[dict[str, Any]], canonical: str) -> dict[str, Any]:
    """Prefer the doc already keyed canonically, else the richest one; break ties by _id for determinism."""
    already_canonical = [d for d in docs if d["purl"] == canonical]
    if already_canonical:
        return already_canonical[0]
    return max(docs, key=lambda d: (len(d), str(d["_id"])))


def _merged_fields(survivor: dict[str, Any], siblings: list[dict[str, Any]]) -> dict[str, Any]:
    """Fields to $set on the survivor: missing/empty keys filled from sibling variants."""
    merged: dict[str, Any] = {}
    for sibling in sorted(siblings, key=lambda d: (-len(d), str(d["_id"]))):
        for key, value in sibling.items():
            if key in _IMMUTABLE_KEYS or key in merged:
                continue
            if survivor.get(key) in (None, "", [], {}) and value not in (None, "", [], {}):
                merged[key] = value
    return merged


async def merge_groups(db: Any, batch_size: int, sleep_ms: int, execute: bool) -> dict[str, int]:
    counters = {"groups": 0, "rekeyed": 0, "deleted": 0, "filled_fields": 0}

    groups: dict[str, list[str]] = {}
    async for doc in db.dependency_enrichments.find({}, {"purl": 1}):
        purl = doc.get("purl")
        if purl:
            groups.setdefault(canonical_purl(purl), []).append(purl)

    pending = {c: p for c, p in groups.items() if len(p) > 1 or p[0] != c}
    print(f"{len(groups)} canonical base(s), {len(pending)} needing migration")

    processed_in_batch = 0
    for canonical, purls in sorted(pending.items()):
        docs = await db.dependency_enrichments.find({"purl": {"$in": purls}}).to_list(len(purls))
        if not docs:
            continue
        counters["groups"] += 1
        survivor = _pick_survivor(docs, canonical)
        siblings = [d for d in docs if d["_id"] != survivor["_id"]]
        update: dict[str, Any] = _merged_fields(survivor, siblings)
        counters["filled_fields"] += len(update)
        if survivor["purl"] != canonical:
            update["purl"] = canonical
            counters["rekeyed"] += 1
        counters["deleted"] += len(siblings)

        if execute:
            # Siblings go first so the unique purl index is free before the re-key.
            if siblings:
                await db.dependency_enrichments.delete_many({"_id": {"$in": [d["_id"] for d in siblings]}})
            if update:
                await db.dependency_enrichments.update_one({"_id": survivor["_id"]}, {"$set": update})

        processed_in_batch += 1
        if processed_in_batch >= batch_size:
            print(
                f"groups={counters['groups']} rekeyed={counters['rekeyed']} "
                f"deleted={counters['deleted']} filled_fields={counters['filled_fields']}"
            )
            processed_in_batch = 0
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

        counters = await merge_groups(db, args.batch_size, args.sleep_ms, args.execute)

        print()
        print(f"[{mode}] groups migrated:            {counters['groups']}")
        print(f"[{mode}] docs re-keyed to canonical: {counters['rekeyed']}")
        print(f"[{mode}] duplicate docs deleted:     {counters['deleted']}")
        print(f"[{mode}] fields filled on survivors: {counters['filled_fields']}")
        if not args.execute:
            print("Dry-run (pass --execute to write).")
    except Exception as exc:
        print(f"merge_enrichment_purl_qualifiers: ERROR — {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually merge and re-key docs (default: dry-run, report only).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Groups processed between progress lines/sleeps (default: {DEFAULT_BATCH_SIZE}).",
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
