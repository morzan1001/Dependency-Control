"""Repository for finding database operations."""

from typing import Any

from pymongo import UpdateOne

from app.core.constants import get_severity_value
from app.models.finding_record import FindingRecord
from app.repositories.base import BaseRepository
from app.services.aggregation.components import add_artifact_name_aliases


class FindingRepository(BaseRepository[FindingRecord]):
    collection_name = "findings"
    model_class = FindingRecord

    async def apply_vulnerability_waiver(
        self,
        scan_id: str,
        vulnerability_id: str,
        waived: bool,
        waiver_reason: str | None = None,
        scope: dict[str, Any] | None = None,
    ) -> int:
        """Waive the nested entry known under vulnerability_id, its aliases, or its resolved CVE.

        ``scope`` narrows the documents (component/version/finding_id) the waiver applies to.
        """
        update_data: dict[str, Any] = {"details.vulnerabilities.$[vuln].waived": waived}
        if waiver_reason:
            update_data["details.vulnerabilities.$[vuln].waiver_reason"] = waiver_reason

        query: dict[str, Any] = {
            "scan_id": scan_id,
            **{k: v for k, v in (scope or {}).items() if k != "type"},
            "type": "vulnerability",
            "$or": [
                {"details.vulnerabilities.id": vulnerability_id},
                {"details.vulnerabilities.aliases": vulnerability_id},
                {"details.vulnerabilities.resolved_cve": vulnerability_id},
            ],
        }
        result = await self.collection.update_many(
            query,
            {"$set": update_data},
            array_filters=[
                {
                    "$or": [
                        {"vuln.id": vulnerability_id},
                        {"vuln.aliases": vulnerability_id},
                        {"vuln.resolved_cve": vulnerability_id},
                    ]
                }
            ],
        )
        await self._rollup_vulnerability_waivers(query, waiver_reason)
        return result.modified_count

    async def reset_nested_vulnerability_waivers(self, scan_id: str) -> int:
        """Clear per-entry waiver flags so a deleted or expired waiver stops suppressing."""
        result = await self.collection.update_many(
            {"scan_id": scan_id, "type": "vulnerability", "details.vulnerabilities.waived": True},
            {
                "$set": {
                    "details.vulnerabilities.$[].waived": False,
                    "details.vulnerabilities.$[].waiver_reason": None,
                }
            },
        )
        # The rollup demotes severity to the highest live entry; without this the demotion
        # outlives the waiver and the buckets under-report until the next rescan.
        await self._rollup_vulnerability_waivers({"scan_id": scan_id, "type": "vulnerability"}, None)
        return result.modified_count

    async def _rollup_vulnerability_waivers(self, query: dict[str, Any], waiver_reason: str | None) -> None:
        """Sync the document-level waived flag and severity with the nested entries.

        Every waiver consumer (severity buckets, ignored_count) reads the document level, so a
        document counts as waived only once all its entries are, and its severity must reflect
        what is still live.
        """
        cursor = self.collection.find(query, {"_id": 1, "severity": 1, "waived": 1, "details.vulnerabilities": 1})
        updates: list[UpdateOne] = []
        for doc in await cursor.to_list(None):
            entries = (doc.get("details") or {}).get("vulnerabilities") or []
            if not entries:
                continue
            live = [e for e in entries if not e.get("waived")] or entries
            changes: dict[str, Any] = {}
            all_waived = all(e.get("waived") for e in entries)
            if bool(doc.get("waived")) != all_waived:
                changes["waived"] = all_waived
                changes["waiver_reason"] = waiver_reason if all_waived else None
            # A fully waived document keeps the severity of its entries, so dropping the
            # waiver restores it without a rescan.
            severity = max((e.get("severity") for e in live), key=get_severity_value)
            if severity and severity != doc.get("severity"):
                changes["severity"] = severity
            if changes:
                updates.append(UpdateOne({"_id": doc["_id"]}, {"$set": changes}))
        if updates:
            await self.collection.bulk_write(updates)

    async def apply_finding_waiver(
        self,
        scan_id: str,
        query: dict,
        waived: bool,
        waiver_reason: str | None = None,
    ) -> int:
        """Apply waiver to findings matching `query` (finding-level, not nested-vulnerability)."""
        full_query = {"scan_id": scan_id, **query}
        update_data: dict[str, Any] = {"waived": waived}
        if waiver_reason:
            update_data["waiver_reason"] = waiver_reason

        result = await self.collection.update_many(full_query, {"$set": update_data})
        return result.modified_count

    async def find_by_scan(
        self,
        scan_id: str,
        skip: int = 0,
        limit: int = 1000,
        query_filter: dict[str, Any] | None = None,
    ) -> list[FindingRecord]:
        query: dict[str, Any] = {"scan_id": scan_id}
        if query_filter:
            query.update(query_filter)
        return await self.find_many(query, skip=skip, limit=limit)

    async def delete_by_scan(self, scan_id: str) -> int:
        return await self.delete_many({"scan_id": scan_id})

    async def count_by_scan(self, scan_id: str) -> int:
        return await self.count({"scan_id": scan_id})

    async def bulk_upsert(self, operations: list[UpdateOne]) -> int:
        if not operations:
            return 0
        result = await self.collection.bulk_write(operations)
        return result.upserted_count + result.modified_count

    _LOCATION_TYPES = ("sast", "iac", "secret", "crypto_key_management")

    async def find_location_findings(self, scan_id: str) -> list[dict[str, Any]]:
        """Raw docs for location-based findings of a scan (waiver-matchable)."""
        cursor = self.collection.find(
            {"scan_id": scan_id, "type": {"$in": list(self._LOCATION_TYPES)}},
            # "details" is needed to recompute a missing match signature.
            {"_id": 1, "finding_id": 1, "type": 1, "component": 1, "match": 1, "details": 1},
        )
        return await cursor.to_list(None)

    async def set_waived(self, scan_id: str, finding_ids: list[str], reason: str | None) -> int:
        if not finding_ids:
            return 0
        result = await self.collection.update_many(
            {"scan_id": scan_id, "_id": {"$in": finding_ids}},
            {"$set": {"waived": True, "waiver_reason": reason}},
        )
        return result.modified_count

    async def set_lapsed(self, scan_id: str, mapping: dict[str, str]) -> int:
        ops = [
            UpdateOne({"scan_id": scan_id, "_id": fid}, {"$set": {"waiver_lapsed": True, "lapsed_waiver_id": wid}})
            for fid, wid in mapping.items()
        ]
        if not ops:
            return 0
        result = await self.collection.bulk_write(ops)
        return result.modified_count

    async def get_severity_distribution(
        self,
        scan_ids: list[str],
        finding_type: str = "vulnerability",
    ) -> dict[str, int]:
        """Returns {severity: count} of non-waived findings aggregated across `scan_ids`."""
        pipeline: list[dict[str, Any]] = [
            {
                "$match": {
                    "scan_id": {"$in": scan_ids},
                    "type": finding_type,
                    "waived": {"$ne": True},
                }
            },
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
        results = await self.aggregate(pipeline)
        return {r["_id"]: r["count"] for r in results if r["_id"]}

    async def get_vuln_counts_by_components(
        self,
        scan_ids: list[str],
        project_ids: list[str],
    ) -> dict[str, int]:
        """{component_name: non_waived_vulnerability_count}; scan_ids+project_ids exclude prior-scan findings.

        Also keyed by the bare artifact name where unambiguous, so a bare dependency name
        resolves a group-qualified finding component.
        """
        pipeline: list[dict[str, Any]] = [
            {
                "$match": {
                    "scan_id": {"$in": scan_ids},
                    "project_id": {"$in": project_ids},
                    "type": "vulnerability",
                    "waived": {"$ne": True},
                }
            },
            {"$group": {"_id": "$component", "count": {"$sum": 1}}},
        ]
        results = await self.aggregate(pipeline)
        return add_artifact_name_aliases({r["_id"]: r["count"] for r in results if r["_id"]})
