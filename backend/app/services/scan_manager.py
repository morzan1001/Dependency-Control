"""ScanManager - scan lifecycle: find/create scans, apply waivers, store results, compute stats, trigger aggregation."""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import SCAN_STATUS_PENDING, SCAN_USABLE_STATUSES
from app.core.worker import AnalysisWorkerManager, worker_manager
from app.models.finding import Finding
from app.models.project import Project, Scan
from app.models.release import Release
from app.models.waiver import Waiver
from app.repositories import ReleaseRepository, ScanRepository
from app.schemas.ingest import BaseIngest
from app.services.waivers.matching import record_matches, route_waiver, waiver_criteria, waiver_strong_match

logger = logging.getLogger(__name__)


def derive_pipeline_scan_id(project_id: str, pipeline_id: int | None, commit_hash: str | None) -> str | None:
    """The scan every job of one CI run writes to, so SBOM, scanner results and callgraph meet; None without a run."""
    if not pipeline_id:
        return None
    seed = f"{project_id}-{pipeline_id}-{commit_hash}" if commit_hash else f"{project_id}-{pipeline_id}"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


def _lineage_root(scan: dict[str, Any]) -> str:
    return scan.get("original_scan_id") or str(scan["_id"])


def build_rescan(source_scan: dict[str, Any], project_id: str) -> Scan:
    """A pending re-analysis of the source's SBOMs, rooted at the original scan of its lineage."""
    return Scan(
        project_id=project_id,
        branch=source_scan.get("branch", "unknown"),
        commit_hash=source_scan.get("commit_hash"),
        pipeline_id=None,  # Don't collide with ingest
        pipeline_iid=source_scan.get("pipeline_iid"),
        project_url=source_scan.get("project_url"),
        pipeline_url=source_scan.get("pipeline_url"),
        job_id=source_scan.get("job_id"),
        job_started_at=source_scan.get("job_started_at"),
        project_name=source_scan.get("project_name"),
        commit_message=source_scan.get("commit_message"),
        commit_tag=source_scan.get("commit_tag"),
        sbom_refs=source_scan.get("sbom_refs", []),
        # Drives the analysis engine's analyzer selection, so the rescan must run under it too.
        scan_type=source_scan.get("scan_type"),
        status=SCAN_STATUS_PENDING,
        created_at=datetime.now(timezone.utc),
        is_rescan=True,
        original_scan_id=_lineage_root(source_scan),
    )


async def queue_rescan(
    db: AsyncIOMotorDatabase, source_scan: dict[str, Any], project_id: str, queue: AnalysisWorkerManager
) -> Scan:
    """Queue a rescan of the lineage (the root shows it pending and restarts its clock), or return the active one."""
    scan_repo = ScanRepository(db)
    root = _lineage_root(source_scan)
    active = await scan_repo.find_active_rescan(project_id, root)
    if active:
        return Scan(**active)

    rescan = build_rescan(source_scan, project_id)
    await scan_repo.create(rescan)
    now = datetime.now(timezone.utc)
    await scan_repo.update_raw(
        root,
        {
            "$set": {
                "latest_rescan_id": rescan.id,
                "latest_run": {"scan_id": rescan.id, "status": SCAN_STATUS_PENDING, "created_at": now},
                "last_rescanned_at": now,
            }
        },
    )
    await queue.add_job(rescan.id)
    return rescan


class ScanManager:
    """Manages the lifecycle of scans."""

    def __init__(self, db: AsyncIOMotorDatabase, project: Project):
        self.db = db
        self.project = project
        # Memoized for this request-scoped instance; no cross-request cache/TTL.
        self._waivers: list[Waiver] | None = None

    def build_pipeline_url(self, data: BaseIngest) -> str | None:
        """Construct pipeline URL if not provided."""
        if data.pipeline_url:
            return data.pipeline_url
        if data.project_url and data.pipeline_id:
            if self.project.github_instance_id:
                return f"{data.project_url}/actions/runs/{data.pipeline_id}"
            return f"{data.project_url}/-/pipelines/{data.pipeline_id}"
        return None

    async def scan_upsert(self, data: BaseIngest, scan_id: str, now: datetime) -> dict[str, Any]:
        """The scan document every ingest of the run writes, sbom_refs aside; records the release the payload marks."""
        update: dict[str, Any] = {
            "$set": {
                "branch": data.branch or "unknown",
                "commit_hash": data.commit_hash,
                "project_url": data.project_url,
                "pipeline_url": self.build_pipeline_url(data),
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
            },
        }
        release = data.release_fields(now)
        if release:
            # The row before the flag: the backfill sweeps the release rows and repairs a missing
            # flag, while a flag whose row is missing shows a release that is not there.
            await ReleaseRepository(self.db).record(
                Release(project_id=str(self.project.id), scan_id=scan_id, **release)
            )
            update["$set"]["is_release"] = True
        return update

    def run_scan_id(self, data: BaseIngest) -> str:
        # pipeline_id 0 derives nothing and still needs a scan of its own.
        return derive_pipeline_scan_id(str(self.project.id), data.pipeline_id, data.commit_hash) or str(uuid.uuid4())

    async def find_or_create_scan(self, data: BaseIngest) -> str:
        """The run's scan id; the upsert lets concurrent scanners of one run share it across pods."""
        scan_id = self.run_scan_id(data)
        update = await self.scan_upsert(data, scan_id, datetime.now(timezone.utc))
        update["$setOnInsert"]["sbom_refs"] = []
        await ScanRepository(self.db).upsert({"_id": scan_id}, update)
        return scan_id

    async def _get_waivers(self) -> list[Waiver]:
        """Fetch active waivers for this project, memoized for this request-scoped instance."""
        if self._waivers is None:
            from app.repositories import WaiverRepository

            waiver_repo = WaiverRepository(self.db)
            self._waivers = await waiver_repo.find_active_for_project(str(self.project.id), include_global=True)

        return self._waivers

    def _finding_matches_waiver(self, finding: Finding, waiver: Waiver) -> bool:
        """Best-effort match at ingest; the recalculation re-anchors a moved location finding."""
        route = route_waiver(waiver)
        if route == "vulnerability":
            return False
        if route == "signature" and waiver.match is not None:
            return finding.match is not None and waiver_strong_match(finding.match, waiver.match, waiver.status)
        criteria = waiver_criteria(waiver)
        record = {
            "finding_id": finding.id,
            "component": finding.component,
            "version": finding.version,
            "type": finding.type,
            "details": finding.details,
        }
        return bool(criteria) and record_matches(record, criteria)

    async def apply_waivers(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        """Apply waivers to findings, returning (non_waived_findings, waived_count)."""
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

    async def store_results(self, analyzer_name: str, result: dict[str, Any], scan_id: str) -> str:
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
        update_ops: dict[str, Any] = {
            "$set": {
                "last_result_at": now,
                "updated_at": now,
            },
            "$addToSet": {"received_results": analyzer_name},
        }

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

        if current_status in SCAN_USABLE_STATUSES:
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
