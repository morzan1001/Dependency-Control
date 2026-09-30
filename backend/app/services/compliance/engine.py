"""Orchestrates compliance report generation: pending -> generating -> completed|failed."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.core.config import settings
from app.core.metrics import compliance_reports_total
from app.models.compliance_report import ComplianceReport
from app.models.crypto_asset import CryptoAsset
from app.models.user import User
from app.repositories.base import find_window
from app.repositories.compliance_report import ComplianceReportRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.compliance import (
    EvaluationCoverage,
    FrameworkEvaluation,
    InputCoverage,
    ReportFormat,
    ReportFramework,
    ReportStatus,
)
from app.schemas.project import LicensePolicySchema, license_policy_from_settings
from app.services.analysis.registry import CRYPTO_ANALYZERS, SELECTABLE_ANALYZERS, VULNERABILITY_ANALYZERS
from app.services.analytics.scopes import ResolvedScope, ScopeResolver, read_scope_projects
from app.services.analyzers.crypto.catalogs.loader import IANA_WEAKNESS_RULES_VERSION
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.compliance.frameworks.base import ComplianceFramework, EvaluationInput, SeedFramework
from app.services.compliance.frameworks.cve_remediation_sla import SLA_DAYS
from app.services.compliance.frameworks.fips_140_3 import AlgorithmConformanceFramework
from app.services.compliance.frameworks.license_audit import LICENSE_AUDIT_CATEGORIES
from app.services.compliance.renderers import RENDERER_REGISTRY
from app.services.crypto_policy.resolver import CryptoPolicyResolver

logger = logging.getLogger(__name__)

# Findings held in memory for one report. The widest projection, a crypto finding's, measures 1.7 KiB per
# document and MAX_CONCURRENT_COMPLIANCE_REPORTS reports can run at once, so this is ~330 MiB at saturation.
_FINDINGS_LIMIT = 20000

# Crypto assets held in memory for one report, across every scan in scope. A projected CryptoAsset measures
# 2.3 KiB validated, so this is ~220 MiB once MAX_CONCURRENT_COMPLIANCE_REPORTS reports saturate it.
_CRYPTO_ASSETS_LIMIT = 10000

_NON_CRYPTO_FRAMEWORKS = frozenset(
    {ReportFramework.CVE_REMEDIATION_SLA, ReportFramework.LICENSE_AUDIT, ReportFramework.PQC_MIGRATION_PLAN}
)
_BASE_FINDING_FIELDS = ("type", "severity", "scan_id", "waived", "waiver_reason")
_CRYPTO_FINDING_FIELDS = ("details.rule_id", "details.matched_rules.rule_id", "details.bom_ref")
_CRYPTO_ASSET_FIELDS = (
    "project_id",
    "scan_id",
    "bom_ref",
    "name",
    "asset_type",
    "primitive",
    "variant",
    "curve",
    "key_size_bits",
    "protocol_type",
    "version",
)


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
            inputs, evaluation = await self.evaluate(db, resolved, framework)
            policy_version, iana_version = inputs.policy_version, inputs.iana_catalog_version
            # The findings stay alive through render, upload and the status write otherwise.
            del inputs
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
                coverage=evaluation.coverage,
                policy_version_snapshot=policy_version,
                iana_catalog_version_snapshot=iana_version,
                completed_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=settings.COMPLIANCE_REPORT_RETENTION_DAYS),
            )
            compliance_reports_total.labels(framework=report.framework, status="success").inc()
            logger.info("Compliance report %s completed (%s bytes)", report.id, len(artifact_bytes))
        except Exception as exc:
            logger.exception("Compliance report %s failed: %s", report.id, exc)
            compliance_reports_total.labels(framework=report.framework, status="error").inc()
            await repo.update_status(
                report.id,
                status=ReportStatus.FAILED,
                error_message=str(exc)[:500],
                completed_at=datetime.now(timezone.utc),
            )

    async def evaluate(
        self,
        db: AsyncIOMotorDatabase,
        resolved: ResolvedScope,
        framework: ComplianceFramework,
    ) -> tuple[EvaluationInput, FrameworkEvaluation]:
        inputs = await self._gather_inputs(db, resolved, framework)
        return inputs, await framework.evaluate(inputs)

    async def _gather_inputs(
        self,
        db: AsyncIOMotorDatabase,
        resolved: ResolvedScope,
        framework: ComplianceFramework,
    ) -> EvaluationInput:
        finding_query = self._finding_type_filter(framework)
        clause, fields, producers = finding_query or ({}, (), frozenset())
        scan_by_project, gaps = await self._pick_scan_ids(db, resolved, producers)
        scan_ids = list(scan_by_project.values())
        findings: list[dict] = []
        findings_read = assets_read = None
        if finding_query:
            findings, in_scope = await self._collect_findings(db, resolved, scan_ids, clause, fields)
            findings_read = InputCoverage(evaluated=len(findings), in_scope=in_scope, limit=_FINDINGS_LIMIT)
        assets: list[CryptoAsset] = []
        if framework.key not in _NON_CRYPTO_FRAMEWORKS:
            assets, in_scope = await self._collect_crypto_assets(db, scan_by_project)
            assets_read = InputCoverage(evaluated=len(assets), in_scope=in_scope, limit=_CRYPTO_ASSETS_LIMIT)
        project_ids = resolved.project_ids or []
        if resolved.scope == "project" and len(project_ids) == 1:
            effective = await CryptoPolicyResolver(db).resolve(project_ids[0])
            policy_rules, policy_version = effective.rules, effective.system_version
            override_version = None if effective.override_locked else effective.override_version
        else:
            system = await CryptoPolicyRepository(db).require_system_policy()
            policy_rules, policy_version = system.rules, system.version
            override_version = None
        scope_desc = self._scope_description(resolved)
        return EvaluationInput(
            resolved=resolved,
            scope_description=scope_desc,
            crypto_assets=assets,
            findings=findings,
            policy_rules=policy_rules,
            license_policy=await self._resolve_license_policy(db, resolved, framework),
            policy_version=policy_version,
            override_version=override_version,
            iana_catalog_version=IANA_WEAKNESS_RULES_VERSION,
            scan_ids=scan_ids,
            db=db,
            coverage=EvaluationCoverage(findings=findings_read, crypto_assets=assets_read, gaps=gaps),
        )

    async def _pick_scan_ids(
        self,
        db: AsyncIOMotorDatabase,
        resolved: ResolvedScope,
        producers: frozenset[str],
    ) -> tuple[dict[str, str], list[str]]:
        """project_id -> the scan evaluated for it, and each part of the scope no input covers: a project
        without a usable scan, a scan whose producing analyzer failed, a project running none of them."""
        from app.services.releases import resolve_scan_ids

        projects = resolved.projects
        if projects is None:
            query = {} if resolved.project_ids is None else {"_id": {"$in": resolved.project_ids}}
            projects = await read_scope_projects(db, query)
        scan_by_project = await resolve_scan_ids(db, resolved.project_ids, projects=projects)
        failed_by_scan: dict[str, list[str]] = {}
        if producers and scan_by_project:
            docs = await db.scans.find(
                {"_id": {"$in": list(scan_by_project.values())}, "failed_analyzers": {"$in": sorted(producers)}},
                {"failed_analyzers": 1},
            ).to_list(length=len(scan_by_project))
            failed_by_scan = {doc["_id"]: sorted(producers.intersection(doc["failed_analyzers"])) for doc in docs}
        switchable = producers & SELECTABLE_ANALYZERS
        gaps: list[str] = []
        for project in projects:
            scan_id = scan_by_project.get(project.id)
            if scan_id is None:
                gaps.append(f"project '{project.name}' has no usable scan")
            elif failed := failed_by_scan.get(scan_id):
                gaps.append(f"project '{project.name}': {', '.join(failed)} failed in scan {scan_id}")
            elif switchable and switchable.isdisjoint(project.active_analyzers):
                gaps.append(f"project '{project.name}' runs none of {', '.join(sorted(switchable))}")
        return scan_by_project, gaps

    async def _collect_crypto_assets(
        self,
        db: AsyncIOMotorDatabase,
        scan_by_project: dict[str, str],
    ) -> tuple[list[CryptoAsset], int]:
        """The inventory the controls are evaluated over, and how many assets the scope holds. The
        budget spans the whole report, so a global scope cannot multiply it by its scan count."""
        query = {"project_id": {"$in": list(scan_by_project)}, "scan_id": {"$in": list(scan_by_project.values())}}
        docs, in_scope = await find_window(
            db.crypto_assets, query, _CRYPTO_ASSETS_LIMIT, projection=dict.fromkeys(_CRYPTO_ASSET_FIELDS, 1)
        )
        if len(docs) < in_scope:
            logger.warning(
                "Compliance evaluation hit crypto-asset cap (%d of %d); "
                "inventory-backed verdicts are withheld — consider narrowing the scope",
                _CRYPTO_ASSETS_LIMIT,
                in_scope,
            )
        return [CryptoAsset.model_validate(doc) for doc in docs], in_scope

    async def _collect_findings(
        self,
        db: AsyncIOMotorDatabase,
        resolved: ResolvedScope,
        scan_ids: list[str],
        clause: dict[str, Any],
        fields: tuple[str, ...],
    ) -> tuple[list[dict], int]:
        """The findings the controls are evaluated over, and how many the scope holds. The count
        costs a round trip only once the fetch has saturated."""
        query = {"scan_id": {"$in": scan_ids}, **clause}
        projection = dict.fromkeys((*_BASE_FINDING_FIELDS, *fields), 1)
        results, in_scope = await find_window(db.findings, query, _FINDINGS_LIMIT, projection=projection)
        if in_scope == len(results):
            return results, in_scope
        logger.warning(
            "Compliance evaluation hit findings cap (%d of %d) for scope %s; "
            "report may understate exposure — consider narrowing the scope",
            _FINDINGS_LIMIT,
            in_scope,
            self._scope_description(resolved),
        )
        return results, in_scope

    def _finding_type_filter(
        self, framework: ComplianceFramework
    ) -> tuple[dict[str, Any], tuple[str, ...], frozenset[str]] | None:
        """The findings clause, the fields beyond the base ones and the analyzers producing those
        findings, per framework; None for one that reads no findings."""
        if framework.key == ReportFramework.PQC_MIGRATION_PLAN:
            return None
        if framework.key == ReportFramework.CVE_REMEDIATION_SLA:
            clause = {"type": "vulnerability", "severity": {"$in": [severity.value for severity in SLA_DAYS]}}
            return clause, ("first_seen_at", "scan_created_at"), frozenset(VULNERABILITY_ANALYZERS)
        if framework.key == ReportFramework.LICENSE_AUDIT:
            clause = {"type": "license", "details.category": {"$in": list(LICENSE_AUDIT_CATEGORIES)}}
            return clause, ("details.category",), frozenset({"license_compliance"})
        assert isinstance(framework, SeedFramework | AlgorithmConformanceFramework)
        types = sorted({t.value for control in framework.controls for t in control.maps_to_finding_types})
        return {"type": {"$in": types}}, _CRYPTO_FINDING_FIELDS, CRYPTO_ANALYZERS.intersection(types)

    async def _resolve_license_policy(
        self,
        db: AsyncIOMotorDatabase,
        resolved: ResolvedScope,
        framework: ComplianceFramework,
    ) -> LicensePolicySchema:
        """The single project's saved policy; every other scope, and a crypto framework, gets the default."""
        project_ids = resolved.project_ids or []
        if framework.key != ReportFramework.LICENSE_AUDIT or resolved.scope != "project" or len(project_ids) != 1:
            return LicensePolicySchema()
        doc = await db["projects"].find_one({"_id": project_ids[0]}, {"analyzer_settings.license_compliance": 1})
        return license_policy_from_settings(((doc or {}).get("analyzer_settings") or {}).get("license_compliance"))

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
        return RENDERER_REGISTRY[fmt].render(evaluation, report, disclaimer=framework.disclaimer)

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
