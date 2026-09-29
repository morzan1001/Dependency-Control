"""ScanManager - scan lifecycle: find/create scans, apply waivers, register scanner results."""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import SCAN_STATUS_PENDING, SCAN_USABLE_STATUSES
from app.core.worker import worker_manager
from app.models.finding import Finding
from app.models.project import Project
from app.models.release import Release
from app.models.waiver import Waiver
from app.repositories.projects import ProjectRepository
from app.repositories.releases import ReleaseRepository
from app.repositories.scans import ScanRepository
from app.schemas.ingest import BaseIngest
from app.services.waivers.matching import record_matches, route_waiver, waiver_criteria, waiver_strong_match

logger = logging.getLogger(__name__)


def deterministic_scan_id(project_id: str, pipeline_id: int | None, commit_hash: str | None) -> str | None:
    """The scan one CI run's SBOM, scanner results and callgraphs share, or None without a pipeline."""
    if not pipeline_id:
        return None
    seed = f"{project_id}-{pipeline_id}-{commit_hash}" if commit_hash else f"{project_id}-{pipeline_id}"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


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
                "status": SCAN_STATUS_PENDING,
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
        return deterministic_scan_id(str(self.project.id), data.pipeline_id, data.commit_hash) or str(uuid.uuid4())

    async def find_or_create_scan(self, data: BaseIngest, scan_type: str | None = None) -> str:
        """The run's scan id; the upsert lets concurrent scanners of one run share it across pods.
        ``scan_type`` is only ever set, never cleared, since the run's other scanners pass none."""
        scan_id = self.run_scan_id(data)
        update = await self.scan_upsert(data, scan_id, datetime.now(timezone.utc))
        update["$setOnInsert"]["sbom_refs"] = []
        if scan_type is not None:
            update["$set"]["scan_type"] = scan_type
        await ScanRepository(self.db).upsert({"_id": scan_id}, update)
        return scan_id

    async def _get_waivers(self) -> list[Waiver]:
        """Fetch active waivers for this project, memoized for this request-scoped instance."""
        if self._waivers is None:
            from app.repositories.waivers import WaiverRepository

            waiver_repo = WaiverRepository(self.db)
            self._waivers = await waiver_repo.find_active_for_project(str(self.project.id))

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
        # Keyed by what a matching finding must equal, so each finding meets only the waivers that can match it.
        by_anchor: dict[tuple[str, str | None], list[Waiver]] = defaultdict(list)
        by_finding_id: dict[str, list[Waiver]] = defaultdict(list)
        unkeyed: list[Waiver] = []
        for waiver in await self._get_waivers():
            route = route_waiver(waiver)
            if route == "signature" and waiver.match is not None and waiver.match.is_strong:
                by_anchor[(waiver.match.file_key, waiver.match.anchor)].append(waiver)
            elif route == "query" and (criteria := waiver_criteria(waiver)):
                if "finding_id" in criteria:
                    by_finding_id[criteria["finding_id"]].append(waiver)
                else:
                    unkeyed.append(waiver)

        final_findings = []
        waived_count = 0

        for finding in findings:
            candidates = [*by_finding_id.get(finding.id, ()), *unkeyed]
            if finding.match is not None:
                candidates += by_anchor.get((finding.match.file_key, finding.match.anchor), ())
            is_waived = any(self._finding_matches_waiver(finding, waiver) for waiver in candidates)

            if is_waived:
                waived_count += 1
            else:
                final_findings.append(finding)

        return final_findings, waived_count

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
        if analyzer_name == "cbom":
            # The crypto analyzers read the assets this post replaced, so a run under way must start over.
            update_ops["$inc"] = {"sbom_generation": 1}

        scan_repo = ScanRepository(self.db)
        await ProjectRepository(self.db).update_raw(str(self.project.id), {"$set": {"last_scan_at": now}})

        scan = await self.db.scans.find_one_and_update(
            {"_id": scan_id},
            update_ops,
            return_document=True,
        )

        if not scan:
            logger.warning(f"Scan {scan_id} not found during register_result")
            return

        should_reaggregate = False
        if scan.get("status") in SCAN_USABLE_STATUSES:
            logger.info(
                f"Late result from {analyzer_name} for completed scan {scan_id}. "
                f"Resetting to pending for re-aggregation."
            )
            # Acting on the write rather than on the status read above, so two late results queue one run.
            should_reaggregate = await scan_repo.reopen_finished(scan_id)

        if trigger_analysis or should_reaggregate:
            await worker_manager.add_job(scan_id)
