"""Pre-deploy guard: refuse to deploy unless archive_metadata is empty.

The archive bundle format was bumped from v1 (the prototype) to v2 (NDJSON
frames + chunked AES-GCM). No backward-compat path exists. Any pre-existing
documents in archive_metadata would point at v1 bundles that the new code
cannot read.

Exit codes:
    0 — collection empty, safe to deploy
    1 — collection has documents; deploy aborted (operator must drop the
        collection manually if the v1 prototype data is disposable)
    2 — connection or runtime error
"""

import asyncio
import os
import sys

from motor.motor_asyncio import AsyncIOMotorClient


async def main() -> int:
    url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    db_name = os.getenv("DATABASE_NAME", "dependency_control")
    client = None
    try:
        client = AsyncIOMotorClient(url)
        db = client[db_name]
        count = await db.archive_metadata.count_documents({})
    except Exception as e:
        print(
            f"check_archive_empty: ERROR — could not query archive_metadata: {e}",
            file=sys.stderr,
        )
        return 2
    finally:
        if client is not None:
            client.close()

    if count == 0:
        print("check_archive_empty: OK (collection empty)")
        return 0

    print(
        f"check_archive_empty: FAIL — archive_metadata has {count} document(s). "
        "The new code (bundle v2) cannot read v1 bundles. Drop the collection manually "
        "before deploying.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
