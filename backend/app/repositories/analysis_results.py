"""Repository for analysis results."""

import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from pymongo import UpdateOne

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
        """Replace the row of this scan, analyzer and source; ``None`` also matches legacy rows stored without one."""
        await self.collection.update_one(
            {"scan_id": scan_id, "analyzer_name": analyzer_name, "source": source},
            {
                "$set": {"result": result, "created_at": datetime.now(timezone.utc)},
                "$setOnInsert": {"_id": str(uuid.uuid4())},
            },
            upsert=True,
        )

    async def carry_over(self, from_scan_id: str, to_scan_id: str, exclude_names: list[str]) -> int:
        """Copy a scan's rows onto a rescan, keyed on the whole result so a re-run copies nothing twice."""
        old_results = await self.find_many(
            {"scan_id": from_scan_id, "analyzer_name": {"$nin": exclude_names}}, limit=10000
        )
        if not old_results:
            return 0
        now = datetime.now(timezone.utc)
        await self.collection.bulk_write(
            [
                UpdateOne(
                    {"scan_id": to_scan_id, "analyzer_name": old.analyzer_name, "result": old.result},
                    {
                        "$setOnInsert": {
                            **old.model_dump(by_alias=True),
                            "_id": str(uuid.uuid4()),
                            "scan_id": to_scan_id,
                            "created_at": now,
                        }
                    },
                    upsert=True,
                )
                for old in old_results
            ],
            ordered=False,
        )
        return len(old_results)
