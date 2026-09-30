"""Repository for analysis results."""

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.models.project import AnalysisResult
from app.repositories.base import BaseRepository
from app.services.gridfs_maintenance import load_gridfs_json, upload_gridfs_json

RESULT_PROJECTION = {"analyzer_name": 1, "source": 1, "result": 1, "result_gridfs_id": 1}


class AnalysisResultRepository(BaseRepository[AnalysisResult]):
    collection_name = "analysis_results"
    model_class = AnalysisResult

    async def find_by_scan(self, scan_id: str, limit: int) -> list[AnalysisResult]:
        rows = await self.find_many_raw(
            {"scan_id": scan_id}, limit=limit, projection={"result": 0, "result_gridfs_id": 0}
        )
        return self._to_model_list(rows)

    async def save_result(
        self, scan_id: str, analyzer_name: str, result: Mapping[str, Any], source: str | None = None
    ) -> None:
        """Replace the row of this scan, analyzer and source; ``None`` also replaces legacy rows stored without one."""
        key = {"scan_id": scan_id, "analyzer_name": analyzer_name, "source": source}
        # Upserting on a key-derived _id lets the unique _id index merge concurrent first writes into one row.
        row_id = ":".join(filter(None, (scan_id, analyzer_name, source)))
        file_id = await upload_gridfs_json(self.db, f"result-{row_id}.json", result)
        await self.collection.update_one(
            {"_id": row_id},
            {
                "$set": {**key, "result_gridfs_id": file_id, "created_at": datetime.now(timezone.utc)},
                "$unset": {"result": ""},
            },
            upsert=True,
        )
        await self.collection.delete_many({**key, "_id": {"$ne": row_id}})

    async def load_result(self, row: Mapping[str, Any]) -> Any:
        """The stored result of a row read with ``RESULT_PROJECTION``; legacy rows carry it inline."""
        if file_id := row.get("result_gridfs_id"):
            return await load_gridfs_json(AsyncIOMotorGridFSBucket(self.db), file_id)
        return row["result"]

    async def carry_over(self, from_scan_id: str, to_scan_id: str, exclude_names: list[str]) -> None:
        """Copy a scan's rows onto a rescan server-side; the derived ``_id`` makes a repeated copy a no-op."""
        await self.aggregate(
            [
                {"$match": {"scan_id": from_scan_id, "analyzer_name": {"$nin": exclude_names}}},
                {
                    "$set": {
                        "_id": {"$concat": [to_scan_id, ":", {"$toString": "$_id"}]},
                        "scan_id": to_scan_id,
                        "created_at": datetime.now(timezone.utc),
                    }
                },
                {"$merge": {"into": self.collection_name, "on": "_id", "whenMatched": "keepExisting"}},
            ]
        )
