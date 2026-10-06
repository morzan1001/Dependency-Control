"""Repository for finding database operations."""

from collections import defaultdict
from collections.abc import AsyncGenerator, Mapping, Sequence
from datetime import datetime
from typing import Any

from pymongo import ASCENDING, DESCENDING, UpdateOne

from app.core.cve import advisory_ids
from app.models.finding import LOCATION_FINDING_TYPES, FindingType
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

# Every field earliest_detections reads, so it never fetches a document.
FIRST_DETECTION_INDEX = [
    ("project_id", ASCENDING),
    ("component", ASCENDING),
    ("type", ASCENDING),
    ("finding_id", ASCENDING),
    ("version", ASCENDING),
    ("first_seen_at", ASCENDING),
    ("scan_created_at", ASCENDING),
]

# A vulnerability's finding_id names its component@version, so each version's newest copy is one seek.
NEWEST_VULNERABILITY_INDEX = [("project_id", ASCENDING), ("finding_id", ASCENDING), ("created_at", DESCENDING)]
VULNERABILITIES_ONLY = {"type": FindingType.VULNERABILITY.value}

_DETECTION_CHUNK = 10_000

# What advisory_detections reads of a copy: its component, and each advisory's names and date.
_COPY_DATES: dict[str, Any] = {
    "component": "$component",
    "advisories": {
        "$map": {
            "input": "$details.vulnerabilities",
            "in": {field: f"$$this.{field}" for field in ("id", "aliases", "resolved_cve", "first_seen_at")},
        }
    },
}

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
        """Unwaived findings up to ``limit`` and their total; no default ``limit``, so no caller gets a hidden cap."""
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
        counts from its scan. Runs on every persist, so it reads only FIRST_DETECTION_INDEX keys."""
        earliest: dict[FindingIdentity, datetime] = {}
        # One $match naming every finding outgrows the 16 MiB command limit on large scans.
        for start in range(0, len(records), _DETECTION_CHUNK):
            asked = records[start : start + _DETECTION_CHUNK]
            pipeline: list[dict[str, Any]] = [
                {
                    "$match": {
                        "project_id": project_id,
                        "component": {"$in": list({r["component"] for r in asked})},
                        "type": {"$in": list({r["type"] for r in asked})},
                        "finding_id": {"$in": list({r["finding_id"] for r in asked})},
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
            # Unhinted, the planner races candidate plans on every persist, which took most of the lookup's time in prod.
            cursor = self.collection.aggregate(pipeline, hint=dict(FIRST_DETECTION_INDEX), allowDiskUse=True)
            earliest.update(
                {
                    finding_identity(row["_id"]): first
                    async for row in cursor
                    if (first := row["first_seen_at"]) is not None
                }
            )
        return earliest

    async def advisory_detections(
        self, project_id: str, records: Sequence[Mapping[str, Any]]
    ) -> dict[tuple[str, str], datetime]:
        """Earliest detection per (component, advisory id) of the records' advisories over every stored version.
        Every persist dates each advisory of its copy with its earliest detection, so each version's newest copy
        answers for the advisories it dates, and every copy of the component dates the rest."""
        asked: dict[str, set[str]] = defaultdict(set)
        for record in records:
            for entry in record["details"]["vulnerabilities"]:
                asked[record["component"]].update(advisory_ids(entry))
        components = list(asked)
        earliest: dict[tuple[str, str], datetime] = {}
        for start in range(0, len(components), _DETECTION_CHUNK):
            chunk = components[start : start + _DETECTION_CHUNK]
            versions = await self.collection.distinct(
                "finding_id", {"project_id": project_id, "component": {"$in": chunk}, **VULNERABILITIES_ONLY}
            )
            newest: list[dict[str, Any]] = [
                {"$match": {"project_id": project_id, "finding_id": {"$in": versions}, **VULNERABILITIES_ONLY}},
                {"$sort": dict(NEWEST_VULNERABILITY_INDEX)},
                {"$group": {"_id": "$finding_id", **{key: {"$first": value} for key, value in _COPY_DATES.items()}}},
            ]
            await self._fold_advisory_dates(earliest, newest, NEWEST_VULNERABILITY_INDEX)
            # A scan whose analyzer failed or came back partial stores a newest copy that misses advisories.
            if missed := [c for c in chunk if any((c, advisory_id) not in earliest for advisory_id in asked[c])]:
                every = [
                    {"$match": {"project_id": project_id, "component": {"$in": missed}, **VULNERABILITIES_ONLY}},
                    # A copy's date spans at most its own version, so only the minimum over every copy may use it.
                    {"$project": {**_COPY_DATES, "first_seen_at": {"$ifNull": ["$first_seen_at", "$scan_created_at"]}}},
                ]
                await self._fold_advisory_dates(earliest, every, FIRST_DETECTION_INDEX)
        return earliest

    async def _fold_advisory_dates(
        self, earliest: dict[tuple[str, str], datetime], pipeline: list[dict[str, Any]], index: list[tuple[str, int]]
    ) -> None:
        async for copy in self.collection.aggregate(pipeline, hint=dict(index)):
            for advisory in copy["advisories"] or []:
                # A copy written before its advisories carried their own date has its finding's.
                if first := advisory.get("first_seen_at") or copy.get("first_seen_at"):
                    for advisory_id in advisory_ids(advisory):
                        key = (copy["component"], advisory_id)
                        earliest[key] = min(earliest.get(key, first), first)

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
