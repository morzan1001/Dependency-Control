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
from typing import Any, Dict, List, Optional

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

    def _build_pipeline_url(self, data: BaseIngest) -> Optional[str]:
        """Construct pipeline URL if not provided."""
        if data.pipeline_url:
            return data.pipeline_url
        if data.project_url and data.pipeline_id:
            return f"{data.project_url}/-/pipelines/{data.pipeline_id}"
        return None

    async def find_or_create_scan(self, data: BaseIngest) -> ScanContext:
        """
        Find an existing scan for this pipeline or create a new one.

        Returns a ScanContext with the scan_id and whether it's new.
        """
        pipeline_url = self._build_pipeline_url(data)

        # Try to find existing scan for this pipeline
        existing_scan = None
        if data.pipeline_id:
            existing_scan = await self.db.scans.find_one(
                {"project_id": str(self.project.id), "pipeline_id": data.pipeline_id}
            )

        # Fallback: If ingest provides NO pipeline_id, try to match by commit_hash
        # This allows scanners running outside of CI (or without pipeline context) 
        # to attach results to the CI scan of the same commit.
        if not existing_scan and not data.pipeline_id and data.commit_hash:
             existing_scan = await self.db.scans.find_one(
                {
                    "project_id": str(self.project.id), 
                    "commit_hash": data.commit_hash,
                },
                sort=[("created_at", -1)]
             )

        if existing_scan:
            scan_id = existing_scan["_id"]
            # Update metadata
            await self.db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "updated_at": datetime.now(timezone.utc),
                        "branch": data.branch or existing_scan.get("branch"),
                        "commit_hash": data.commit_hash
                        or existing_scan.get("commit_hash"),
                        "project_url": data.project_url,
                        "pipeline_url": pipeline_url,
                        "job_id": data.job_id,
                        "job_started_at": data.job_started_at,
                        "project_name": data.project_name,
                        "commit_message": data.commit_message,
                        "commit_tag": data.commit_tag,
                        "pipeline_user": data.pipeline_user,
                        "status": "pending",
                    }
                },
            )
            return ScanContext(scan_id=scan_id, is_new=False, pipeline_url=pipeline_url)

        # Create new scan
        scan = Scan(
            project_id=str(self.project.id),
            branch=data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=data.pipeline_id,
            pipeline_iid=data.pipeline_iid,
            project_url=data.project_url,
            pipeline_url=pipeline_url,
            job_id=data.job_id,
            job_started_at=data.job_started_at,
            project_name=data.project_name,
            commit_message=data.commit_message,
            commit_tag=data.commit_tag,
            pipeline_user=data.pipeline_user,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        await self.db.scans.insert_one(scan.model_dump(by_alias=True))
        return ScanContext(scan_id=scan.id, is_new=True, pipeline_url=pipeline_url)

    async def _get_waivers(self) -> List[Dict]:
        """Fetch and cache active waivers for this project."""
        if self._waivers_cache is not None:
            return self._waivers_cache

        cursor = self.db.waivers.find(
            {
                "$or": [
                    {"project_id": str(self.project.id)},
                    {"project_id": None},  # Global waivers
                ],
                "expiration_date": {"$gt": datetime.now(timezone.utc)},
            }
        )
        self._waivers_cache = await cursor.to_list(length=1000)
        return self._waivers_cache

    def _finding_matches_waiver(self, finding: Finding, waiver: Dict) -> bool:
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

    async def apply_waivers(self, findings: List[Finding]) -> tuple[List[Finding], int]:
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
        """Store analysis results in the database."""
        result_id = str(uuid.uuid4())
        await self.db.analysis_results.insert_one(
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
        
        # Get current scan status
        scan = await self.db.scans.find_one({"_id": scan_id})
        if not scan:
            return
        
        current_status = scan.get("status", "pending")
        
        # Determine new status and whether to trigger re-aggregation
        new_status = current_status
        should_reaggregate = False
        
        if current_status == "completed":
            # Late result arrived after completion - need to re-aggregate
            new_status = "pending"
            should_reaggregate = True
            logger.info(
                f"Late result from {analyzer_name} for completed scan {scan_id}. "
                f"Resetting to pending for re-aggregation."
            )
        
        update_ops: Dict[str, Any] = {
            "$set": {
                "last_result_at": now,
                "updated_at": now,
            },
            "$addToSet": {"received_results": analyzer_name},
        }
        
        if new_status != current_status:
            update_ops["$set"]["status"] = new_status
        
        await self.db.scans.update_one({"_id": scan_id}, update_ops)
        
        # Trigger aggregation if:
        # 1. Explicitly requested (SBOM scanner), OR
        # 2. Late result arrived after completion
        if trigger_analysis or should_reaggregate:
            await self.trigger_aggregation(scan_id)

    async def update_project_last_scan(self) -> None:
        """Update the project's last_scan_at timestamp."""
        await self.db.projects.update_one(
            {"_id": str(self.project.id)},
            {"$set": {"last_scan_at": datetime.now(timezone.utc)}},
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
