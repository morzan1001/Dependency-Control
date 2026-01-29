"""
ScanManager - Centralized service for scan lifecycle management.

This service handles:
- Finding or creating scans based on pipeline data
- Applying waivers to findings
- Storing analysis results
- Computing statistics
- Triggering aggregation jobs
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.worker import worker_manager
from app.models.finding import Finding
from app.models.project import Project, Scan
from app.models.stats import Stats
from app.schemas.ingest import BaseIngest, ScanContext

logger = logging.getLogger(__name__)


class ScanManager:
    """
    Manages the lifecycle of scans.

    Usage:
        manager = ScanManager(db, project)
        ctx = await manager.find_or_create_scan(data)

        # Process findings...

        await manager.store_results("trufflehog", result_dict, ctx.scan_id)
        findings = await manager.apply_waivers(findings)
        await manager.trigger_aggregation(ctx.scan_id)
    """

    def __init__(self, db: AsyncIOMotorDatabase, project: Project):
        self.db = db
        self.project = project
        self._waivers_cache: Optional[List[Dict]] = None
        self._waivers_cache_time: Optional[datetime] = None
        self._cache_ttl_minutes = 5  # Cache TTL in minutes

    def build_pipeline_url(self, data: BaseIngest) -> Optional[str]:
        """Construct pipeline URL if not provided."""
        if data.pipeline_url:
            return data.pipeline_url
        if data.project_url and data.pipeline_id:
            return f"{data.project_url}/-/pipelines/{data.pipeline_id}"
        return None

    async def find_or_create_scan(self, data: BaseIngest) -> ScanContext:
        """
        Find an existing scan for this pipeline or create a new one.

        Uses DETERMINISTIC scan_id generation (UUID5) to ensure consistency
        across all ingest endpoints in multi-pod environments.

        Returns a ScanContext with the scan_id and whether it's new.
        """
        import uuid

        pipeline_url = self.build_pipeline_url(data)

        # Generate DETERMINISTIC scan_id (same logic as SBOM endpoint)
        # This ensures all scanners (TruffleHog, OpenGrep, SBOM, etc.) use the SAME scan
        # for the same commit in the same pipeline
        if data.pipeline_id and data.commit_hash:
            # Deterministic: Same commit + pipeline = same scan
            scan_id_seed = f"{self.project.id}-{data.pipeline_id}-{data.commit_hash}"
            scan_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))
        elif data.pipeline_id:
            # No commit_hash: Use pipeline_id only (less precise)
            scan_id_seed = f"{self.project.id}-{data.pipeline_id}"
            scan_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))
        else:
            # No pipeline_id: Use random UUID (manual upload)
            scan_id = str(uuid.uuid4())

        # Atomic upsert: Create scan if doesn't exist, update if it does
        # This prevents race conditions when multiple scanners run concurrently
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

        # Atomic upsert via ScanRepository
        from app.repositories import ScanRepository

        scan_repo = ScanRepository(self.db)
        result = await scan_repo.upsert({"_id": scan_id}, scan_update)

        # Check if new scan was created
        is_new = True  # This is a simplification - could be improved

        return ScanContext(scan_id=scan_id, is_new=is_new, pipeline_url=pipeline_url)

    async def _get_waivers(self) -> List[Dict]:
        """
        Fetch and cache active waivers for this project.
        Cache is invalidated after TTL expires.

        Uses WaiverRepository for consistent data access.
        """
        from app.repositories import WaiverRepository

        now = datetime.now(timezone.utc)

        # Check if cache is valid
        if self._waivers_cache is not None and self._waivers_cache_time is not None:
            cache_age = (now - self._waivers_cache_time).total_seconds() / 60
            if cache_age < self._cache_ttl_minutes:
                return self._waivers_cache
            else:
                logger.debug(
                    f"Waiver cache expired (age: {cache_age:.1f} min, TTL: {self._cache_ttl_minutes} min)"
                )

        # Fetch fresh waivers from database via repository
        waiver_repo = WaiverRepository(self.db)
        self._waivers_cache = await waiver_repo.find_active_for_project(
            str(self.project.id), include_global=True
        )
        self._waivers_cache_time = now

        return self._waivers_cache

    def _finding_matches_waiver(self, finding: Finding, waiver: Dict[str, Any]) -> bool:
        """Check if a finding matches a waiver."""
        # Match by finding ID
        if waiver.get("finding_id") and waiver["finding_id"] == finding.id:
            return True

        # Match by finding type
        if waiver.get("finding_type") and waiver["finding_type"] == finding.type:
            return True

        # Match by component/package name
        if waiver.get("package_name") and waiver["package_name"] == finding.component:
            return True

        return False

    async def apply_waivers(self, findings: List[Finding]) -> Tuple[List[Finding], int]:
        """
        Apply waivers to findings.

        Returns (non_waived_findings, waived_count).
        """
        waivers = await self._get_waivers()

        final_findings = []
        waived_count = 0

        for finding in findings:
            is_waived = any(
                self._finding_matches_waiver(finding, waiver) for waiver in waivers
            )

            if is_waived:
                waived_count += 1
                finding.waived = True
            else:
                final_findings.append(finding)

        return final_findings, waived_count

    async def store_results(
        self, analyzer_name: str, result: Dict[str, Any], scan_id: str
    ) -> str:
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

    async def register_result(
        self, scan_id: str, analyzer_name: str, trigger_analysis: bool = False
    ) -> None:
        """
        Register that a scanner has submitted results.

        This method:
        1. Updates last_result_at timestamp
        2. Adds analyzer_name to received_results list
        3. If scan was 'completed', resets status to 'pending' and triggers re-aggregation
        4. Optionally triggers the aggregation (for SBOM scanner)

        Args:
            scan_id: The scan ID
            analyzer_name: Name of the analyzer that submitted results
            trigger_analysis: If True, trigger the aggregation worker
        """
        now = datetime.now(timezone.utc)

        # Atomic update: Update scan and retrieve new state in one operation
        # This prevents race conditions in multi-pod environments
        update_ops: Dict[str, Any] = {
            "$set": {
                "last_result_at": now,
                "updated_at": now,
            },
            "$addToSet": {"received_results": analyzer_name},
        }

        # Use find_one_and_update for atomic operation via repository
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

        # If scan is completed, reset to pending and trigger re-aggregation
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

        # Trigger aggregation if:
        # 1. Explicitly requested (SBOM scanner), OR
        # 2. Late result arrived after completion
        if trigger_analysis or should_reaggregate:
            await self.trigger_aggregation(scan_id)

    async def update_project_last_scan(self) -> None:
        """Update the project's last_scan_at timestamp via repository."""
        from app.repositories import ProjectRepository

        project_repo = ProjectRepository(self.db)
        await project_repo.update_raw(
            str(self.project.id), {"$set": {"last_scan_at": datetime.now(timezone.utc)}}
        )

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
