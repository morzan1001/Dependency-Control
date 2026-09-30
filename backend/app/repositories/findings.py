"""Repository for finding database operations."""

from collections.abc import AsyncGenerator, Mapping, Sequence
from datetime import datetime
from typing import Any

from pymongo import UpdateOne

from app.models.finding import LOCATION_FINDING_TYPES
from app.models.finding_record import FindingRecord
from app.repositories.base import BaseRepository, find_window

# What names a CVE, plus the fields a recurrence row reports back.
_VULNERABILITY_IDENTITY_PROJECTION = {
    "scan_id": 1,
    "severity": 1,
    "component": 1,
    "description": 1,
    "finding_id": 1,
    "aliases": 1,
    "details.vulnerabilities.id": 1,
    "details.vulnerabilities.resolved_cve": 1,
    "details.vulnerabilities.aliases": 1,
}

FindingIdentity = tuple[Any, Any, Any, Any]

# What names an advisory, and its per-advisory waiver state.
_ADVISORY_WAIVER_FIELDS = ("id", "aliases", "resolved_cve", "severity", "waived", "waiver_reason")


def finding_identity(doc: Mapping[str, Any]) -> FindingIdentity:
    """What makes the findings of two scans of one project the same finding."""
    return doc.get("type"), doc.get("component"), doc.get("version"), doc.get("finding_id")


class FindingRepository(BaseRepository[FindingRecord]):
    collection_name = "findings"
    model_class = FindingRecord

    async def find_waiver_state(self, scan_id: str) -> list[dict[str, Any]]:
        """The scan's findings that carry a waived or lapsed flag."""
        query = {"scan_id": scan_id, "$or": [{"waived": True}, {"waiver_lapsed": True}]}
        projection = {"waived": 1, "waiver_reason": 1, "waiver_lapsed": 1, "lapsed_waiver_id": 1}
        return await self.collection.find(query, projection).to_list(None)

    async def find_ids(self, scan_id: str, query: dict[str, Any]) -> list[str]:
        return [doc["_id"] async for doc in self.collection.find({"scan_id": scan_id, **query}, {"_id": 1})]

    async def find_advisory_state(self, scan_id: str, clause: dict[str, Any]) -> list[dict[str, Any]]:
        """Vulnerability documents matching ``clause``: waiver scope fields and advisories, in stored order."""
        projection = {
            "finding_id": 1,
            "component": 1,
            "version": 1,
            "severity": 1,
            **{f"details.vulnerabilities.{f}": 1 for f in _ADVISORY_WAIVER_FIELDS},
        }
        return await self.collection.find({"scan_id": scan_id, "type": "vulnerability", **clause}, projection).to_list(
            None
        )

    async def set_fields(self, scan_id: str, fields_by_id: Mapping[str, dict[str, Any]]) -> None:
        if fields_by_id:
            await self.collection.bulk_write(
                [UpdateOne({"_id": fid, "scan_id": scan_id}, {"$set": fields}) for fid, fields in fields_by_id.items()],
                ordered=False,
            )

    async def any_in_scans(self, scan_ids: list[str], query: dict[str, Any]) -> bool:
        return await self.collection.find_one({"scan_id": {"$in": scan_ids}, **query}, {"_id": 1}) is not None

    async def find_by_scan(self, scan_id: str, limit: int) -> tuple[list[FindingRecord], int]:
        """The scan's unwaived findings up to ``limit``, and how many it holds. ``limit`` is required: a default
        here is a cap the caller never chose and cannot see."""
        rows, total = await find_window(self.collection, {"scan_id": scan_id, "waived": {"$ne": True}}, limit)
        return self._to_model_list(rows), total

    async def iter_vulnerability_identities(self, scan_ids: Sequence[str]) -> AsyncGenerator[dict[str, Any], None]:
        """Every vulnerability finding of these scans, projected to what names a CVE.

        Streamed and unbounded: a recurrence count taken over a cut of this set reports a CVE
        present in every scan as absent from most of them.
        """
        if not scan_ids:
            return
        query = {"scan_id": {"$in": list(scan_ids)}, "type": "vulnerability"}
        async for doc in self.collection.find(query, _VULNERABILITY_IDENTITY_PROJECTION):
            yield doc

    async def earliest_detections(
        self, project_id: str, records: Sequence[Mapping[str, Any]]
    ) -> dict[FindingIdentity, datetime]:
        """Earliest detection per identity among the project's stored copies; a copy predating first_seen_at
        counts from its scan. Runs on every persist, so it reads only fields the covering index in init_db holds."""
        if not records:
            return {}
        pipeline: list[dict[str, Any]] = [
            {
                "$match": {
                    "project_id": project_id,
                    "component": {"$in": list({r["component"] for r in records})},
                    "type": {"$in": list({r["type"] for r in records})},
                    "finding_id": {"$in": list({r["finding_id"] for r in records})},
                }
            },
            {
                "$group": {
                    "_id": {
                        "type": "$type",
                        "component": "$component",
                        "version": "$version",
                        "finding_id": "$finding_id",
                    },
                    "first_seen_at": {"$min": {"$ifNull": ["$first_seen_at", "$scan_created_at"]}},
                }
            },
        ]
        rows = await self.aggregate(pipeline, allow_disk_use=True)
        return {
            finding_identity(row["_id"]): first_seen for row in rows if (first_seen := row["first_seen_at"]) is not None
        }

    async def delete_by_scan(self, scan_id: str) -> int:
        return await self.delete_many({"scan_id": scan_id})

    async def count_by_scan(self, scan_id: str) -> int:
        return await self.count({"scan_id": scan_id})

    async def find_location_findings(self, scan_id: str) -> list[dict[str, Any]]:
        """A scan's location findings, with details only where the match signature must be recomputed from them."""
        docs = await self.collection.find(
            {"scan_id": scan_id, "type": {"$in": sorted(LOCATION_FINDING_TYPES)}},
            {"_id": 1, "finding_id": 1, "component": 1, "match": 1},
        ).to_list(None)
        unsigned = {d["_id"]: d for d in docs if not d.get("match")}
        if unsigned:
            async for doc in self.collection.find({"scan_id": scan_id, "_id": {"$in": list(unsigned)}}, {"details": 1}):
                unsigned[doc["_id"]]["details"] = doc.get("details")
        return docs

    async def get_severity_distribution(
        self,
        scan_ids: list[str],
        finding_type: str | None = "vulnerability",
    ) -> dict[str, int]:
        """Returns {severity: count} of non-waived findings aggregated across `scan_ids`; None counts every type."""
        match: dict[str, Any] = {"scan_id": {"$in": scan_ids}, "waived": {"$ne": True}}
        if finding_type is not None:
            match["type"] = finding_type
        pipeline: list[dict[str, Any]] = [
            {"$match": match},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
        results = await self.aggregate(pipeline)
        return {r["_id"]: r["count"] for r in results if r["_id"]}
