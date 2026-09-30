"""
Compliance reporting schemas — enums, control definitions, framework
evaluation result, residual risks. Pure data types, no I/O.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.models.finding import FindingType, Severity


class ReportStatus(str, Enum):
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportFormat(str, Enum):
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    SARIF = "sarif"


class ReportFramework(str, Enum):
    NIST_SP_800_131A = "nist-sp-800-131a"
    BSI_TR_02102 = "bsi-tr-02102"
    CNSA_2_0 = "cnsa-2.0"
    FIPS_140_3 = "fips-140-3"
    ISO_19790 = "iso-19790"
    PQC_MIGRATION_PLAN = "pqc-migration-plan"
    LICENSE_AUDIT = "license-audit"
    CVE_REMEDIATION_SLA = "cve-remediation-sla"


class ControlStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WAIVED = "waived"
    NOT_APPLICABLE = "not_applicable"
    # The input the verdict would have rested on did not cover the scope.
    NOT_EVALUATED = "not_evaluated"


@dataclass
class ControlDefinition:
    control_id: str
    title: str
    description: str
    severity: Severity
    remediation: str
    maps_to_rule_ids: list[str] = field(default_factory=list)
    maps_to_finding_types: list[FindingType] = field(default_factory=list)
    # Called as (control, data) in place of the default evaluator.
    custom_evaluator: Callable[..., "ControlResult"] | None = None


class ControlResult(BaseModel):
    control_id: str
    title: str
    description: str
    status: ControlStatus
    severity: Severity
    evidence_finding_ids: list[str] = Field(default_factory=list)
    evidence_asset_bom_refs: list[str] = Field(default_factory=list)
    waiver_reasons: list[str] = Field(default_factory=list)
    remediation: str
    # Why NOT_EVALUATED was returned in place of a verdict.
    status_reason: str | None = None

    model_config = ConfigDict(use_enum_values=True)


class ResidualRisk(BaseModel):
    control_id: str
    title: str
    severity: Severity
    description: str

    model_config = ConfigDict(use_enum_values=True)


class InputCoverage(BaseModel):
    """What one bounded input covers of what the scope holds."""

    evaluated: int
    in_scope: int
    limit: int

    @property
    def complete(self) -> bool:
        return self.evaluated >= self.in_scope


class EvaluationCoverage(BaseModel):
    """What the control verdicts were computed over, per input the framework reads; None for one it never reads."""

    crypto_assets: InputCoverage | None = None
    # Set only by a framework that builds one control per row of a bounded plan.
    plan_items: InputCoverage | None = None
    # Parts of the scope no input could cover: an unscanned project or a missing or failed analyzer.
    gaps: list[str] = Field(default_factory=list)

    @property
    def complete(self) -> bool:
        inputs = (self.crypto_assets, self.plan_items)
        return not self.gaps and all(read.complete for read in inputs if read is not None)


class FrameworkEvaluation(BaseModel):
    framework_key: ReportFramework
    framework_name: str
    framework_version: str
    generated_at: datetime
    scope_description: str
    controls: list[ControlResult] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
    residual_risks: list[ResidualRisk] = Field(default_factory=list)
    inputs_fingerprint: str
    coverage: EvaluationCoverage

    model_config = ConfigDict(use_enum_values=True)
