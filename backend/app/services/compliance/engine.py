"""
ComplianceReportEngine — orchestrates report generation.

Workflow (idempotent, fail-safe):
    pending -> generating -> (completed | failed)

Renderers are invoked in-memory; artifact bytes go to GridFS. Metadata
persists even if the artifact is later pruned.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import (
    FrameworkEvaluation, ReportFormat, ReportStatus,
)

logger = logging.getLogger(__name__)

_DEFAULT_RETENTION_DAYS = 90
_PLACEHOLDER_MSG = "Implemented in PR D."


class ComplianceReportEngine:
    """Thin orchestrator. Renderers + frameworks live elsewhere.

    `_gather_inputs` is responsible for:
        1. Resolving scope -> project_ids (via ScopeResolver).
        2. Loading crypto_assets / findings / policy rules for that scope.
        3. Running the framework evaluator to produce a FrameworkEvaluation.
    The result object carries the evaluation plus snapshot metadata. Keeping
    the framework call on that side of the seam lets unit tests mock the
    whole pipeline with a single patch.
    """

    async def generate(
        self, *, report: ComplianceReport,
        db: AsyncIOMotorDatabase, user,
    ) -> None:
        repo = ComplianceReportRepository(db)
        await repo.update_status(report.id, status=ReportStatus.GENERATING)
        try:
            from app.services.compliance.frameworks import FRAMEWORK_REGISTRY

            gathered = await self._gather_inputs(db, user, report)
            framework = FRAMEWORK_REGISTRY[report.framework]
            evaluation = getattr(gathered, "evaluation", None)
            artifact_bytes, filename, mime = self._render(
                report.format, framework, evaluation, report,
            )
            gridfs_id = await self._store_artifact(
                db, artifact_bytes, filename, mime,
            )
            await repo.update_status(
                report.id,
                status=ReportStatus.COMPLETED,
                artifact_gridfs_id=gridfs_id,
                artifact_filename=filename,
                artifact_size_bytes=len(artifact_bytes),
                artifact_mime_type=mime,
                summary=getattr(evaluation, "summary", None),
                policy_version_snapshot=getattr(gathered, "policy_version", None),
                iana_catalog_version_snapshot=getattr(gathered, "iana_catalog_version", None),
                completed_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=_DEFAULT_RETENTION_DAYS),
            )
            logger.info("Compliance report %s completed (%s bytes)", report.id, len(artifact_bytes))
        except Exception as exc:
            logger.exception("Compliance report %s failed: %s", report.id, exc)
            await repo.update_status(
                report.id,
                status=ReportStatus.FAILED,
                error_message=str(exc)[:500],
                completed_at=datetime.now(timezone.utc),
            )

    async def _gather_inputs(self, db, user, report: ComplianceReport):
        """PR D will flesh this out. Placeholder lets C-tests mock it.

        Returns an object with attributes: `evaluation` (FrameworkEvaluation),
        `policy_version` (int), `iana_catalog_version` (int).
        """
        raise NotImplementedError(_PLACEHOLDER_MSG)

    def _render(
        self, fmt: ReportFormat, framework, evaluation: FrameworkEvaluation,
        report: ComplianceReport,
    ) -> Tuple[bytes, str, str]:
        """PR D will flesh this out. Placeholder lets C-tests mock it."""
        raise NotImplementedError(_PLACEHOLDER_MSG)

    async def _store_artifact(
        self, db, artifact_bytes: bytes, filename: str, mime: str,
    ) -> str:
        """PR D will flesh this out. Placeholder lets C-tests mock it."""
        raise NotImplementedError(_PLACEHOLDER_MSG)
