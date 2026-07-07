"""ScanManager - scan lifecycle: find/create scans, apply waivers, store results, compute stats, trigger aggregation."""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.worker import worker_manager
from app.models.finding import Finding
from app.models.project import Project
from app.models.stats import Stats
from app.models.waiver import Waiver
from app.schemas.ingest import BaseIngest, ScanContext

logger = logging.getLogger(__name__)


class ScanManager:
    """Manages the lifecycle of scans."""

    def __init__(self, db: AsyncIOMotorDatabase, project: Project):
        self.db = db
        self.project = project
        # Memoized for this request-scoped instance; no cross-request cache/TTL.
        self._waivers: Optional[List[Waiver]] = None

    def build_pipeline_url(self, data: BaseIngest) -> Optional[str]:
        """Construct pipeline URL if not provided."""
        if data.pipeline_url:
            return data.pipeline_url
        if data.project_url and data.pipeline_id:
            if self.project.github_instance_id:
                return f"{data.project_url}/actions/runs/{data.pipeline_id}"
            return f"{data.project_url}/-/pipelines/{data.pipeline_id}"
        return None

    async def find_or_create_scan(self, data: BaseIngest) -> ScanContext:
        """Find or create the scan for this pipeline, returning a ScanContext.

        Uses deterministic UUID5 scan_ids so all scanners for the same commit+pipeline
        share one scan across pods.
        """
        pipeline_url = self.build_pipeline_url(data)

        if data.pipeline_id and data.commit_hash:
            scan_id_seed = f"{self.project.id}-{data.pipeline_id}-{data.commit_hash}"
            scan_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))
        elif data.pipeline_id:
            # No commit_hash: pipeline_id only (less precise).
            scan_id_seed = f"{self.project.id}-{data.pipeline_id}"
            scan_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))
        else:
            # Manual upload: random UUID.
            scan_id = str(uuid.uuid4())

        # Atomic upsert to avoid races between concurrent scanners.
        now = datetime.now(timezone.utc)

        scan_update = {
            "$set": {
                "branch": data.branch or "unknown",
                "commit_hash": data.commit_hash,
                "project_url": data.project_url,
                "pipeline_url": pipeline_url,
                "job_id": data.job_id,
                "job_started_at": data.job_started_at,
                "project_name": data.project_name,
                "commit_message": data.commit_message,
                "commit_tag": data.commit_tag,
                "pipeline_user": data.pipeline_user,
                "updated_at": now,
            },
            "$setOnInsert": {
                "_id": scan_id,
                "project_id": str(self.project.id),
                "pipeline_id": data.pipeline_id,
                "pipeline_iid": data.pipeline_iid,
                "status": "pending",
                "created_at": now,
                "sbom_refs": [],
            },
        }

        # Capture the raw result so is_new reflects insert (upserted_id set) vs update.
        from app.core.metrics import track_db_operation
        from app.repositories import ScanRepository

        scan_repo = ScanRepository(self.db)
        with track_db_operation("scans", "update_one"):
            upsert_result = await scan_repo.collection.update_one({"_id": scan_id}, scan_update, upsert=True)

        is_new = upsert_result.upserted_id is not None

        return ScanContext(scan_id=scan_id, is_new=is_new, pipeline_url=pipeline_url)

    async def _get_waivers(self) -> List[Waiver]:
        """Fetch active waivers for this project, memoized for this request-scoped instance."""
        if self._waivers is None:
            from app.repositories import WaiverRepository

            waiver_repo = WaiverRepository(self.db)
            self._waivers = await waiver_repo.find_active_for_project(str(self.project.id), include_global=True)

        return self._waivers

    def _finding_matches_waiver(self, finding: Finding, waiver: Waiver) -> bool:
        """Best-effort exact match at ingest. Location-based findings use the strong-anchor
        signature (no re-anchoring here — the recalc is authoritative for that)."""
        if finding.match is not None and waiver.match is not None:
            from app.services.waivers.matching import waiver_strong_match
            return waiver_strong_match(finding.match, waiver.match, waiver.status or "false_positive")
        # Legacy path for non-location findings (license/eol/vuln-by-type/component).
        # Mirror _build_waiver_query's AND semantics (services/stats.py): every field the
        # waiver sets must match the finding; an unset (or "Unknown") field is a wildcard.
        # Using OR here over-waives, e.g. a secret waiver scoped to one file would suppress
        # every secret in the whole upload.
        field_pairs = (
            (waiver.finding_id, finding.id),
            (waiver.package_name, finding.component),
            (waiver.package_version, finding.version),
            (waiver.finding_type, finding.type),
        )
        matched_any = False
        for waiver_value, finding_value in field_pairs:
            if not waiver_value or waiver_value == "Unknown":
                continue
            if waiver_value != finding_value:
                return False
            matched_any = True
        return matched_any

    async def apply_waivers(self, findings: List[Finding]) -> Tuple[List[Finding], int]:
        """
        Apply waivers to findings.

        Returns (non_waived_findings, waived_count).
        """
        waivers = await self._get_waivers()

        final_findings = []
        waived_count = 0

        for finding in findings:
            is_waived = any(self._finding_matches_waiver(finding, waiver) for waiver in waivers)

            if is_waived:
                waived_count += 1
                finding.waived = True
            else:
                final_findings.append(finding)

        return final_findings, waived_count

    async def store_results(self, analyzer_name: str, result: Dict[str, Any], scan_id: str) -> str:
        """Store analysis results in the database using AnalysisResultRepository."""
        from app.repositories import AnalysisResultRepository

        result_id = str(uuid.uuid4())
        result_repo = AnalysisResultRepository(self.db)

        await result_repo.create_raw(
            {
                "_id": result_id,
                "scan_id": scan_id,
                "analyzer_name": analyzer_name,
                "result": result,
                "created_at": datetime.now(timezone.utc),
            }
        )
        return result_id

    async def trigger_aggregation(self, scan_id: str) -> None:
        """Add scan to worker queue for aggregation."""
        await worker_manager.add_job(scan_id)

    async def register_result(self, scan_id: str, analyzer_name: str, trigger_analysis: bool = False) -> None:
        """Record a scanner's submission; if the scan was completed, reset to pending and re-aggregate.

        Triggers aggregation when ``trigger_analysis`` is set or a late result reopened the scan.
        """
        now = datetime.now(timezone.utc)

        # Atomic update to avoid races across pods.
        update_ops: Dict[str, Any] = {
            "$set": {
                "last_result_at": now,
                "updated_at": now,
            },
            "$addToSet": {"received_results": analyzer_name},
        }

        from app.repositories import ScanRepository

        scan_repo = ScanRepository(self.db)

        scan = await self.db.scans.find_one_and_update(
            {"_id": scan_id},
            update_ops,
            return_document=True,
        )

        if not scan:
            logger.warning(f"Scan {scan_id} not found during register_result")
            return

        current_status = scan.get("status", "pending")
        should_reaggregate = False

        if current_status == "completed":
            logger.info(
                f"Late result from {analyzer_name} for completed scan {scan_id}. "
                f"Resetting to pending for re-aggregation."
            )
            await scan_repo.update_raw(
                scan_id,
                {"$set": {"status": "pending", "retry_count": 0}},
            )
            should_reaggregate = True

        if trigger_analysis or should_reaggregate:
            await self.trigger_aggregation(scan_id)

    async def update_project_last_scan(self) -> None:
        """Update the project's last_scan_at timestamp via repository."""
        from app.repositories import ProjectRepository

        project_repo = ProjectRepository(self.db)
        await project_repo.update_raw(str(self.project.id), {"$set": {"last_scan_at": datetime.now(timezone.utc)}})

    @staticmethod
    def compute_stats(findings: List[Finding]) -> Stats:
        """Compute severity statistics from findings."""
        stats = Stats()
        for f in findings:
            sev = f.severity.lower() if f.severity else "unknown"
            if sev == "critical":
                stats.critical += 1
            elif sev == "high":
                stats.high += 1
            elif sev == "medium":
                stats.medium += 1
            elif sev == "low":
                stats.low += 1
            elif sev == "info":
                stats.info += 1
            else:
                stats.unknown += 1
        return stats
