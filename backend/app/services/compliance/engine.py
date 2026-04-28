"""
ComplianceReportEngine — orchestrates report generation.

Workflow (idempotent, fail-safe):
    pending -> generating -> (completed | failed)

Renderers are invoked in-memory; artifact bytes go to GridFS. Metadata
persists even if the artifact is later pruned.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, List, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.models.compliance_report import ComplianceReport
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.compliance import (
    FrameworkEvaluation,
    ReportFormat,
    ReportStatus,
)
from app.services.analytics.scopes import ResolvedScope, ScopeResolver
from app.services.analyzers.crypto.catalogs.loader import CURRENT_IANA_CATALOG_VERSION
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.compliance.frameworks.base import ComplianceFramework, EvaluationInput
from app.services.compliance.renderers import RENDERER_REGISTRY

logger = logging.getLogger(__name__)

_DEFAULT_RETENTION_DAYS = 90
_FINDINGS_LIMIT = 20000


class ComplianceReportEngine:
    """Thin orchestrator. Renderers + frameworks live elsewhere.

    `_gather_inputs` is responsible for:
        1. Loading crypto_assets / findings / policy rules for the resolved scope.
        2. Returning an `EvaluationInput` for the framework to evaluate.

    The framework evaluation itself happens in `generate()` after `_gather_inputs`,
    so unit tests can mock each seam (scope resolver, inputs, framework, render,
    store) independently.
    """

    async def generate(
        self,
        *,
        report: ComplianceReport,
        db: AsyncIOMotorDatabase,
        user: User,
    ) -> None:
        repo = ComplianceReportRepository(db)
        await repo.update_status(report.id, status=ReportStatus.GENERATING)
        try:
            resolved = await ScopeResolver(db, user).resolve(
                scope=report.scope,
                scope_id=report.scope_id,
            )
            inputs = await self._gather_inputs(db, resolved)
            framework = FRAMEWORK_REGISTRY[report.framework]
            if hasattr(framework, "evaluate_async"):
                evaluation = await framework.evaluate_async(inputs)  # type: ignore[attr-defined]
            else:
                evaluation = framework.evaluate(inputs)
            artifact_bytes, filename, mime = self._render(
                report.format,
                framework,
                evaluation,
                report,
            )
            gridfs_id = await self._store_artifact(
                db,
                artifact_bytes,
                filename,
                mime,
            )
            await repo.update_status(
                report.id,
                status=ReportStatus.COMPLETED,
                artifact_gridfs_id=gridfs_id,
                artifact_filename=filename,
                artifact_size_bytes=len(artifact_bytes),
                artifact_mime_type=mime,
                summary=evaluation.summary,
                policy_version_snapshot=inputs.policy_version,
                iana_catalog_version_snapshot=inputs.iana_catalog_version,
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

    async def _gather_inputs(
        self,
        db: AsyncIOMotorDatabase,
        resolved: ResolvedScope,
    ) -> EvaluationInput:
        scan_ids = await self._pick_scan_ids(db, resolved)
        assets = await self._collect_crypto_assets(db, resolved, scan_ids)
        findings = await self._collect_findings(db, resolved, scan_ids)
        policy_repo = CryptoPolicyRepository(db)
        system = await policy_repo.get_system_policy()
        policy_version = getattr(system, "version", None) if system else None
        policy_rules = [r.model_dump() for r in system.rules] if system else []
        scope_desc = self._scope_description(resolved)
        return EvaluationInput(
            resolved=resolved,
            scope_description=scope_desc,
            crypto_assets=assets,
            findings=findings,
            policy_rules=policy_rules,
            policy_version=policy_version,
            iana_catalog_version=CURRENT_IANA_CATALOG_VERSION,
            scan_ids=scan_ids,
            db=db,
        )

    async def _pick_scan_ids(self, db: AsyncIOMotorDatabase, resolved: ResolvedScope) -> List[str]:
        match: dict[str, Any] = {"status": {"$in": ["completed", "partial"]}}
        if resolved.project_ids is not None:
            match["project_id"] = {"$in": resolved.project_ids}
        pipeline: list[dict[str, Any]] = [
            {"$match": match},
            {"$sort": {"created_at": -1}},
            {"$group": {"_id": "$project_id", "scan_id": {"$first": "$_id"}}},
        ]
        return [row["scan_id"] async for row in db.scans.aggregate(pipeline)]

    async def _collect_crypto_assets(
        self, db: AsyncIOMotorDatabase, resolved: ResolvedScope, scan_ids: List[str]
    ) -> List[Any]:
        repo = CryptoAssetRepository(db)
        out: List[Any] = []
        for sid in scan_ids:
            scan_doc = await db.scans.find_one({"_id": sid}, {"project_id": 1})
            if not scan_doc:
                continue
            pid = scan_doc.get("project_id")
            if pid is None:
                continue
            assets = await repo.list_by_scan(pid, sid, limit=10000)
            out.extend(assets)
        return out

    async def _collect_findings(
        self, db: AsyncIOMotorDatabase, resolved: ResolvedScope, scan_ids: List[str]
    ) -> List[dict]:
        query: dict[str, Any] = {
            "scan_id": {"$in": scan_ids},
            "type": {"$regex": "^crypto_"},
        }
        if resolved.project_ids is not None:
            query["project_id"] = {"$in": resolved.project_ids}
        # Drop fields no compliance framework reads to keep peak memory bounded.
        projection = {
            "description": 0,
            "scanners": 0,
            "found_in": 0,
            "aliases": 0,
            "related_findings": 0,
        }
        cursor = db.findings.find(query, projection).limit(_FINDINGS_LIMIT)
        results = [doc async for doc in cursor]
        if len(results) >= _FINDINGS_LIMIT:
            logger.warning(
                "Compliance evaluation hit findings cap (%d) for scope %s; "
                "report may understate exposure — consider narrowing the scope",
                _FINDINGS_LIMIT,
                self._scope_description(resolved),
            )
        return results

    def _scope_description(self, resolved: ResolvedScope) -> str:
        if resolved.scope == "project":
            return f"project '{resolved.scope_id}'"
        if resolved.scope == "team":
            return f"team '{resolved.scope_id}'"
        if resolved.scope == "user":
            count = len(resolved.project_ids or [])
            return f"user scope ({count} project(s))"
        return "global (all projects)"

    def _render(
        self,
        fmt: ReportFormat,
        framework: ComplianceFramework,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
    ) -> Tuple[bytes, str, str]:
        renderer = RENDERER_REGISTRY[fmt]
        disclaimer = getattr(framework, "disclaimer", None)
        return renderer.render(evaluation, report, disclaimer=disclaimer)

    async def _store_artifact(
        self,
        db: AsyncIOMotorDatabase,
        artifact_bytes: bytes,
        filename: str,
        mime: str,
    ) -> str:
        bucket = AsyncIOMotorGridFSBucket(db)
        gridfs_id = await bucket.upload_from_stream(
            filename,
            artifact_bytes,
            metadata={"content_type": mime, "kind": "compliance_report"},
        )
        return str(gridfs_id)
