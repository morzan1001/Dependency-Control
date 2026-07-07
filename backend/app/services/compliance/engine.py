"""Orchestrates compliance report generation: pending -> generating -> completed|failed."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.core.config import settings
from app.core.metrics import compliance_reports_total
from app.models.compliance_report import ComplianceReport
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.compliance import (
    FrameworkEvaluation,
    ReportFormat,
    ReportFramework,
    ReportStatus,
)
from app.services.analytics.scopes import ResolvedScope, ScopeResolver
from app.services.analyzers.crypto.catalogs.loader import CURRENT_IANA_CATALOG_VERSION
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.compliance.frameworks.base import ComplianceFramework, EvaluationInput
from app.services.compliance.renderers import RENDERER_REGISTRY

logger = logging.getLogger(__name__)

_FINDINGS_LIMIT = 20000


class ComplianceReportEngine:
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
            framework = FRAMEWORK_REGISTRY[report.framework]
            inputs = await self._gather_inputs(db, resolved, framework)
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
            framework_label = (
                str(report.framework.value) if hasattr(report.framework, "value") else str(report.framework)
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
                expires_at=datetime.now(timezone.utc) + timedelta(days=settings.COMPLIANCE_REPORT_RETENTION_DAYS),
            )
            compliance_reports_total.labels(framework=framework_label, status="success").inc()
            logger.info("Compliance report %s completed (%s bytes)", report.id, len(artifact_bytes))
        except Exception as exc:
            logger.exception("Compliance report %s failed: %s", report.id, exc)
            framework_label = (
                str(report.framework.value) if hasattr(report.framework, "value") else str(report.framework)
            )
            compliance_reports_total.labels(framework=framework_label, status="error").inc()
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
        framework: Optional[ComplianceFramework] = None,
    ) -> EvaluationInput:
        scan_pairs = await self._pick_scan_ids(db, resolved)
        scan_ids = [sid for _, sid in scan_pairs]
        assets = await self._collect_crypto_assets(db, scan_pairs)
        findings = await self._collect_findings(db, resolved, scan_ids, framework)
        policy_repo = CryptoPolicyRepository(db)
        system = await policy_repo.get_system_policy()
        policy_version = getattr(system, "version", None) if system else None
        policy_rules = [r.model_dump() for r in system.rules] if system else []
        # License Audit reads its toggles from policy_rules[0]; prepend the
        # project license policy there. Crypto frameworks key by rule_id and ignore it.
        license_policy = await self._resolve_license_policy(db, resolved, framework)
        if license_policy is not None:
            policy_rules = [license_policy, *policy_rules]
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

    async def _pick_scan_ids(
        self, db: AsyncIOMotorDatabase, resolved: ResolvedScope
    ) -> List[Tuple[str, str]]:
        match: dict[str, Any] = {"status": {"$in": ["completed", "partial"]}}
        if resolved.project_ids is not None:
            match["project_id"] = {"$in": resolved.project_ids}
        pipeline: list[dict[str, Any]] = [
            {"$match": match},
            {"$sort": {"created_at": -1}},
            {"$group": {"_id": "$project_id", "scan_id": {"$first": "$_id"}}},
        ]
        # Return (project_id, scan_id) pairs so callers avoid re-querying each scan's project.
        return [(row["_id"], row["scan_id"]) async for row in db.scans.aggregate(pipeline)]

    async def _collect_crypto_assets(
        self, db: AsyncIOMotorDatabase, scan_pairs: List[Tuple[str, str]]
    ) -> List[Any]:
        repo = CryptoAssetRepository(db)
        out: List[Any] = []
        for pid, sid in scan_pairs:
            if pid is None or sid is None:
                continue
            assets = await repo.list_by_scan(pid, sid, limit=10000)
            out.extend(assets)
        return out

    async def _collect_findings(
        self,
        db: AsyncIOMotorDatabase,
        resolved: ResolvedScope,
        scan_ids: List[str],
        framework: Optional[ComplianceFramework] = None,
    ) -> List[dict]:
        query: dict[str, Any] = {
            "scan_id": {"$in": scan_ids},
            "type": self._finding_type_filter(framework),
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

    def _finding_type_filter(self, framework: Optional[ComplianceFramework]) -> Any:
        """Findings-query `type` clause per framework; unknown framework loads the union."""
        key = getattr(framework, "key", None)
        if key == ReportFramework.CVE_REMEDIATION_SLA:
            return "vulnerability"
        if key == ReportFramework.LICENSE_AUDIT:
            return "license"
        if key is None:
            return {"$regex": "^crypto_|^vulnerability$|^license$"}
        return {"$regex": "^crypto_"}

    async def _resolve_license_policy(
        self,
        db: AsyncIOMotorDatabase,
        resolved: ResolvedScope,
        framework: Optional[ComplianceFramework],
    ) -> Optional[Dict[str, Any]]:
        """Effective project license policy; None unless scope is a single project carrying the toggles."""
        key = getattr(framework, "key", None)
        if key not in (ReportFramework.LICENSE_AUDIT, None):
            return None
        project_ids = resolved.project_ids
        if resolved.scope != "project" or not project_ids or len(project_ids) != 1:
            return None
        doc = await db["projects"].find_one(
            {"_id": project_ids[0]},
            {"license_policy": 1, "analyzer_settings": 1},
        )
        if not doc:
            return None
        return self._effective_license_policy(doc)

    @staticmethod
    def _effective_license_policy(project_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Precedence: analyzer_settings.license_compliance (or its nested license_policy) over top-level project.license_policy."""
        license_keys = ("allow_strong_copyleft", "allow_network_copyleft", "distribution_model")

        def _matches(candidate: Any) -> bool:
            return isinstance(candidate, dict) and any(k in candidate for k in license_keys)

        analyzer_settings = project_doc.get("analyzer_settings") or {}
        settings = analyzer_settings.get("license_compliance") if isinstance(analyzer_settings, dict) else None
        if isinstance(settings, dict):
            nested = settings.get("license_policy")
            if _matches(nested):
                return nested
            if _matches(settings):
                return settings
        legacy = project_doc.get("license_policy")
        if _matches(legacy):
            return legacy
        return None

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
