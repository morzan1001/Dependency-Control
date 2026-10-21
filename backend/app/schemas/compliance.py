from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.models.compliance_report import EvaluationCoverage, ReportFramework
from app.models.finding import Severity


class ControlStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WAIVED = "waived"
    NOT_APPLICABLE = "not_applicable"
    # The input the verdict would have rested on did not cover the scope.
    NOT_EVALUATED = "not_evaluated"


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

    @property
    def evidence_count(self) -> int:
        # A finding names the asset it flags, so the longer list counts each piece of evidence once.
        return max(len(self.evidence_finding_ids), len(self.evidence_asset_bom_refs))


class ResidualRisk(BaseModel):
    control_id: str
    title: str
    severity: Severity
    description: str

    model_config = ConfigDict(use_enum_values=True)


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
