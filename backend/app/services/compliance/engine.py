"""Orchestrates compliance report generation: pending -> generating -> completed|failed."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.core.config import settings
from app.core.metrics import compliance_reports_total
from app.models.compliance_report import ComplianceReport
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.compliance import (
    EvaluationCoverage,
    FrameworkEvaluation,
    InputCoverage,
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

# Findings held in memory for one report. The projection measures 2.66 KiB per document and
# MAX_CONCURRENT_COMPLIANCE_REPORTS reports can run at once, so this is ~530 MiB at saturation.
_FINDINGS_LIMIT = 20000

# Crypto assets held in memory for one report, across every scan in scope. A CryptoAsset measures
# 3.74 KiB validated, so this is ~365 MiB once MAX_CONCURRENT_COMPLIANCE_REPORTS reports saturate it.
_CRYPTO_ASSETS_LIMIT = 10000


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
            # Every framework builds its own FrameworkEvaluation, so the engine is the one place
            # that can guarantee no renderer receives a verdict without its coverage. A framework
            # bounded by an input the engine does not gather widens it and keeps its own.
            evaluation.coverage = evaluation.coverage or inputs.coverage
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
                coverage=evaluation.coverage,
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
        framework: ComplianceFramework | None = None,
    ) -> EvaluationInput:
        scan_pairs = await self._pick_scan_ids(db, resolved)
        scan_ids = [sid for _, sid in scan_pairs]
        assets, assets_in_scope = await self._collect_crypto_assets(db, scan_pairs)
        findings, findings_in_scope = await self._collect_findings(db, resolved, scan_ids, framework)
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
            coverage=EvaluationCoverage(
                findings=InputCoverage(
                    evaluated=len(findings),
                    in_scope=findings_in_scope,
                    limit=_FINDINGS_LIMIT,
                ),
                crypto_assets=InputCoverage(
                    evaluated=len(assets),
                    in_scope=assets_in_scope,
                    limit=_CRYPTO_ASSETS_LIMIT,
                ),
            ),
        )

    async def _pick_scan_ids(self, db: AsyncIOMotorDatabase, resolved: ResolvedScope) -> list[tuple[str, str]]:
        """(project_id, scan_id) pairs so callers avoid re-querying each scan's project."""
        from app.services.releases import resolve_scan_ids

        return list((await resolve_scan_ids(db, resolved.project_ids)).items())

    async def _collect_crypto_assets(
        self,
        db: AsyncIOMotorDatabase,
        scan_pairs: list[tuple[str, str]],
    ) -> tuple[list[Any], int]:
        """The inventory the controls are evaluated over, and how many assets the scope holds.
        The budget spans the whole report, so a global scope cannot multiply it by its scan count;
        a scan costs a count round trip only once the budget can no longer swallow it whole."""
        repo = CryptoAssetRepository(db)
        out: list[Any] = []
        in_scope = 0
        for pid, sid in scan_pairs:
            if pid is None or sid is None:
                continue
            remaining = _CRYPTO_ASSETS_LIMIT - len(out)
            if remaining > 0:
                assets = await repo.list_by_scan(pid, sid, limit=remaining)
                out.extend(assets)
                if len(assets) < remaining:
                    in_scope += len(assets)
                    continue
            in_scope += await repo.count_by_scan(pid, sid)
        if len(out) < in_scope:
            logger.warning(
                "Compliance evaluation hit crypto-asset cap (%d of %d); "
                "inventory-backed verdicts are withheld — consider narrowing the scope",
                _CRYPTO_ASSETS_LIMIT,
                in_scope,
            )
        return out, in_scope

    async def _collect_findings(
        self,
        db: AsyncIOMotorDatabase,
        resolved: ResolvedScope,
        scan_ids: list[str],
        framework: ComplianceFramework | None = None,
    ) -> tuple[list[dict], int]:
        """The findings the controls are evaluated over, and how many the scope holds. The count
        costs a round trip only once the fetch has saturated."""
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
        if len(results) < _FINDINGS_LIMIT:
            return results, len(results)
        in_scope: int = await db.findings.count_documents(query)
        logger.warning(
            "Compliance evaluation hit findings cap (%d of %d) for scope %s; "
            "report may understate exposure — consider narrowing the scope",
            _FINDINGS_LIMIT,
            in_scope,
            self._scope_description(resolved),
        )
        return results, in_scope

    def _finding_type_filter(self, framework: ComplianceFramework | None) -> Any:
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
        framework: ComplianceFramework | None,
    ) -> dict[str, Any] | None:
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
    def _effective_license_policy(project_doc: dict[str, Any]) -> dict[str, Any] | None:
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
    ) -> tuple[bytes, str, str]:
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
