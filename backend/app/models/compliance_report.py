from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.core.constants import ScopeName
from app.models.types import MongoDocument


class ReportStatus(StrEnum):
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportFormat(StrEnum):
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    SARIF = "sarif"


class ReportFramework(StrEnum):
    NIST_SP_800_131A = "nist-sp-800-131a"
    BSI_TR_02102 = "bsi-tr-02102"
    CNSA_2_0 = "cnsa-2.0"
    FIPS_140_3 = "fips-140-3"
    ISO_19790 = "iso-19790"
    PQC_MIGRATION_PLAN = "pqc-migration-plan"
    LICENSE_AUDIT = "license-audit"
    CVE_REMEDIATION_SLA = "cve-remediation-sla"


class InputCoverage(BaseModel):
    """What one bounded input covers of what the scope holds."""

    evaluated: int
    in_scope: int
    limit: int

    @property
    def complete(self) -> bool:
        return self.evaluated >= self.in_scope


class EvaluationCoverage(BaseModel):
    """What the control verdicts were computed over: the scope's gaps and, for a plan framework, its bounded plan."""

    # Set only by a framework that builds one control per row of a bounded plan.
    plan_items: InputCoverage | None = None
    # Parts of the scope no input covers, e.g. no projects, no usable scan, a failed analyzer, no SBOM or CBOM.
    gaps: list[str] = Field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.gaps and (self.plan_items is None or self.plan_items.complete)


class ComplianceReport(MongoDocument):
    scope: ScopeName
    scope_id: str | None = None
    framework: ReportFramework
    format: ReportFormat
    status: ReportStatus
    requested_by: str
    requested_at: datetime
    completed_at: datetime | None = None
    artifact_gridfs_id: str | None = None
    artifact_filename: str | None = None
    artifact_size_bytes: int | None = None
    artifact_mime_type: str | None = None
    policy_version_snapshot: int | None = None
    iana_catalog_version_snapshot: int | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    # Without it, a reader of summary cannot tell a full evaluation from a windowed one.
    coverage: EvaluationCoverage | None = None
    error_message: str | None = None
    expires_at: datetime | None = None
    comment: str | None = None
