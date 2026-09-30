"""Repository for analysis results."""

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from app.models.project import AnalysisResult
from app.repositories.base import BaseRepository


class AnalysisResultRepository(BaseRepository[AnalysisResult]):
    collection_name = "analysis_results"
    model_class = AnalysisResult

    async def find_by_scan(self, scan_id: str, limit: int) -> list[AnalysisResult]:
        return await self.find_many({"scan_id": scan_id}, limit=limit)

    async def delete_by_scan(self, scan_id: str) -> int:
        return await self.delete_many({"scan_id": scan_id})

    async def save_result(
        self, scan_id: str, analyzer_name: str, result: Mapping[str, Any], source: str | None = None
    ) -> None:
        """Replace the row of this scan, analyzer and source; ``None`` also replaces legacy rows stored without one."""
        key = {"scan_id": scan_id, "analyzer_name": analyzer_name, "source": source}
        # Upserting on a key-derived _id lets the unique _id index merge concurrent first writes into one row.
        row_id = ":".join(filter(None, (scan_id, analyzer_name, source)))
        await self.collection.update_one(
            {"_id": row_id}, {"$set": {**key, "result": result, "created_at": datetime.now(timezone.utc)}}, upsert=True
        )
        await self.collection.delete_many({**key, "_id": {"$ne": row_id}})

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
