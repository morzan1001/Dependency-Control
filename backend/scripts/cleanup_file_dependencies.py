"""One-off cleanup: remove `dependencies` docs with `type: "file"` left over from CycloneDX file-catalog ingestion.

Run via `kubectl exec` into the backend pod, e.g.:
    python -m scripts.cleanup_file_dependencies          # dry-run: count only
    python -m scripts.cleanup_file_dependencies --execute

The filter matches ~17.9M docs (56% of the collection) on a Percona PSMDB
replica set, so deletes run in bounded batches instead of one delete_many —
a single giant delete would flood the oplog and stall replication.
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


def run_dry_run(collection: Collection[dict[str, Any]]) -> None:
    total = collection.estimated_document_count()
    print(f"Collection estimated_document_count: {total}")
    try:
        matched = collection.count_documents(FILTER, maxTimeMS=COUNT_MAX_TIME_MS)
        print(f"Documents matching {FILTER}: {matched}")
    except PyMongoError as exc:
        print(f"count timed out; filter is {FILTER} ({exc})")


def run_delete(collection: Collection[dict[str, Any]], batch_size: int, sleep_ms: int) -> None:
    deleted_total = 0
    while True:
        batch_ids = [doc["_id"] for doc in collection.find(FILTER, {"_id": 1}).limit(batch_size)]
        if not batch_ids:
            break
        result = collection.delete_many({"_id": {"$in": batch_ids}})
        deleted_total += result.deleted_count
        print(f"Deleted so far: {deleted_total}")
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

    client: MongoClient = MongoClient(settings.MONGODB_URL)
    try:
        collection = client.get_default_database().dependencies

        if args.execute:
            run_delete(collection, args.batch_size, args.sleep_ms)
        else:
            print(f"Dry-run (pass --execute to delete). Filter: {FILTER}")
            run_dry_run(collection)
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
