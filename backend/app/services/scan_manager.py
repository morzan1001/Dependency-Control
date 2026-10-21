import asyncio
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError

from app.core.constants import SCAN_STATUS_PENDING, SCAN_USABLE_STATUSES
from app.core.worker import worker_manager
from app.models.finding import Finding
from app.models.match_signature import MatchSignature
from app.models.project import Project
from app.models.release import Release
from app.models.waiver import Waiver
from app.repositories.projects import ProjectRepository
from app.repositories.releases import ReleaseRepository
from app.repositories.scans import ScanRepository
from app.schemas.ingest import IngestEnvelope
from app.services.archive import roll_back_dead_restore
from app.services.waivers.matching import record_matches, route_waiver, waiver_criteria, waiver_strong_match

logger = logging.getLogger(__name__)

# Well below the CI client's and the ingress's timeouts; scanner.sh does not retry a 409.
_RESTORE_WAIT_SECONDS = 10.0
_RESTORE_POLL_SECONDS = 0.5


def _restoring_conflict() -> HTTPException:
    return HTTPException(
        status.HTTP_409_CONFLICT, "The scan is being restored from its archive; retry once the restore is done"
    )


def deterministic_scan_id(project_id: str, pipeline_id: int | None, commit_hash: str | None) -> str | None:
    """Shared by one CI run's SBOM, scanner results and callgraphs."""
    if not pipeline_id:
        return None
    seed = f"{project_id}-{pipeline_id}-{commit_hash}" if commit_hash else f"{project_id}-{pipeline_id}"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


def apply_waivers(findings: list[Finding], waivers: list[Waiver]) -> tuple[list[Finding], int]:
    """Best effort: the recalculation re-anchors a moved location finding."""
    # Keyed by what a matching finding must equal, so each finding meets only the waivers that can match it.
    by_anchor: dict[tuple[str, str | None], list[tuple[MatchSignature, str]]] = defaultdict(list)
    by_finding_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unkeyed: list[dict[str, Any]] = []
    for waiver in waivers:
        route = route_waiver(waiver)
        if route == "signature" and waiver.match is not None and waiver.match.is_strong:
            by_anchor[(waiver.match.file_key, waiver.match.anchor)].append((waiver.match, waiver.status))
        elif route == "query" and (criteria := waiver_criteria(waiver)):
            (by_finding_id[criteria["finding_id"]] if "finding_id" in criteria else unkeyed).append(criteria)

    kept = []
    for finding in findings:
        record = {
            "finding_id": finding.id,
            "component": finding.component,
            "version": finding.version,
            "type": finding.type,
            "details": finding.details,
        }
        waived = any(record_matches(record, criteria) for criteria in (*by_finding_id.get(finding.id, ()), *unkeyed))
        if not waived and (match := finding.match) is not None:
            signed = by_anchor.get((match.file_key, match.anchor), ())
            waived = any(waiver_strong_match(match, signature, status) for signature, status in signed)
        if not waived:
            kept.append(finding)
    return kept, len(findings) - len(kept)


class ScanManager:
    def __init__(self, db: AsyncIOMotorDatabase, project: Project):
        self.db = db
        self.project = project

    def build_pipeline_url(self, data: IngestEnvelope) -> str | None:
        if data.pipeline_url:
            return data.pipeline_url
        if data.project_url and data.pipeline_id:
            if self.project.github_instance_id:
                return f"{data.project_url}/actions/runs/{data.pipeline_id}"
            return f"{data.project_url}/-/pipelines/{data.pipeline_id}"
        return None

    async def record_release_and_build_scan_upsert(
        self, data: IngestEnvelope, scan_id: str, now: datetime
    ) -> dict[str, Any]:
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
            # The row before the flag: a flag whose row is missing shows a release that is not there.
            await ReleaseRepository(self.db).record(
                Release(project_id=str(self.project.id), scan_id=scan_id, **release), data.commit_tag
            )
            update["$set"]["is_release"] = True
        return update

    def run_scan_id(self, data: IngestEnvelope) -> str:
        # pipeline_id 0 derives nothing and still needs a scan of its own.
        return deterministic_scan_id(str(self.project.id), data.pipeline_id, data.commit_hash) or str(uuid.uuid4())

    async def refuse_while_restoring(self, scan_id: str) -> None:
        """Called before an upload's first scan-scoped write, since a rollback of the restore would delete it."""
        deadline = time.monotonic() + _RESTORE_WAIT_SECONDS
        while await self.db.scans.find_one(
            {"_id": scan_id, "restore_in_progress": True}, {"_id": 1}
        ) and not await roll_back_dead_restore(self.db, scan_id):
            if time.monotonic() >= deadline:
                raise _restoring_conflict()
            await asyncio.sleep(_RESTORE_POLL_SECONDS)

    async def upsert_scan(self, scan_id: str, update: dict[str, Any]) -> None:
        try:
            await ScanRepository(self.db).upsert_unless_restoring(scan_id, update)
        except DuplicateKeyError:
            raise _restoring_conflict() from None

    async def find_or_create_scan(self, data: IngestEnvelope, scan_id: str, scan_type: str | None = None) -> None:
        """scan_type is only set, never cleared, since the run's other scanners pass none."""
        update = await self.record_release_and_build_scan_upsert(data, scan_id, datetime.now(timezone.utc))
        update["$setOnInsert"]["sbom_refs"] = []
        if scan_type is not None:
            update["$set"]["scan_type"] = scan_type
        await self.upsert_scan(scan_id, update)

    async def register_result(self, scan_id: str, analyzer_name: str, trigger_analysis: bool = False) -> None:
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

        scan = await scan_repo.add_received_result(scan_id, update_ops)

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
