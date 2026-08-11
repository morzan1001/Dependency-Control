"""One-off cleanup for `dependencies` docs with `type: "file"` from CycloneDX file-catalog ingestion.

Filter matches ~56% of the collection on a Percona PSMDB replica set, so deletes run in
bounded batches — a single delete_many would flood the oplog and stall replication.
"""

import argparse
import sys
import time
from typing import Any

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

from app.core.config import settings

FILTER = {"type": "file"}
COUNT_MAX_TIME_MS = 120_000
DEFAULT_BATCH_SIZE = 5000
DEFAULT_SLEEP_MS = 100


def print_dry_run_summary(collection: Collection[dict[str, Any]]) -> None:
    total = collection.estimated_document_count()
    print(f"Collection estimated_document_count: {total}")
    try:
        matched = collection.count_documents(FILTER, maxTimeMS=COUNT_MAX_TIME_MS)
        print(f"Documents matching {FILTER}: {matched}")
    except PyMongoError as exc:
        print(f"count timed out; filter is {FILTER} ({exc})")


def run_delete(collection: Collection[dict[str, Any]], batch_size: int, sleep_ms: int) -> None:
    deleted_total = 0
    last_id: Any = None
    while True:
        # Walk by _id > last_id instead of re-running find(FILTER) from the start each round:
        # `type` is unindexed, so a plain limit()-loop would full-scan the collection per batch.
        # This also makes the run crash-safe — restarting just resumes, since deleted docs no
        # longer match FILTER.
        query: dict[str, Any] = dict(FILTER)
        if last_id is not None:
            query["_id"] = {"$gt": last_id}
        batch_ids = [doc["_id"] for doc in collection.find(query, {"_id": 1}).sort("_id", 1).limit(batch_size)]
        if not batch_ids:
            break
        collection.delete_many({"_id": {"$in": batch_ids}})
        deleted_total += len(batch_ids)
        last_id = batch_ids[-1]
        print(f"Deleted so far: {deleted_total}")
        if len(batch_ids) < batch_size:
            break
        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000)
    print(f"Done. Total deleted: {deleted_total}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually delete matching documents (default: dry-run, count only).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Documents deleted per batch (default: {DEFAULT_BATCH_SIZE}).",
    )
    parser.add_argument(
        "--sleep-ms",
        type=int,
        default=DEFAULT_SLEEP_MS,
        help=f"Milliseconds to sleep between batches, to let replication breathe (default: {DEFAULT_SLEEP_MS}).",
    )
    args = parser.parse_args()

    if args.batch_size < 1:
        parser.error("--batch-size must be >= 1")
    if args.sleep_ms < 0:
        parser.error("--sleep-ms must be >= 0")

    client: MongoClient = MongoClient(settings.MONGODB_URL)
    try:
        # Select the database explicitly rather than via the connection string's default-db
        # segment, matching every other DB access in this codebase.
        db = client[settings.DATABASE_NAME]
        collection = db.dependencies
        print(f"Database: {db.name}, Collection: {collection.name}")
        print_dry_run_summary(collection)

        if args.execute:
            run_delete(collection, args.batch_size, args.sleep_ms)
        else:
            print("Dry-run (pass --execute to delete).")
    except Exception as exc:
        print(f"cleanup_file_dependencies: ERROR — {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
