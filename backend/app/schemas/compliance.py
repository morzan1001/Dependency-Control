"""
Compliance reporting schemas — enums, control definitions, framework
evaluation result, residual risks. Pure data types, no I/O.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Literal, Optional

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
    PQC_MIGRATION_PLAN = "pqc-migration-plan"  # meta-framework, used in PR E


class ControlStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WAIVED = "waived"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ControlDefinition:
    control_id: str
    title: str
    description: str
    severity: Severity
    remediation: str
    maps_to_rule_ids: List[str] = field(default_factory=list)
    maps_to_finding_types: List[FindingType] = field(default_factory=list)
    # Optional override of the default evaluator. If set, this callable is
    # responsible for producing a ControlResult given the evaluation input.
    custom_evaluator: Optional[Callable[..., "ControlResult"]] = None


class ControlResult(BaseModel):
    control_id: str
    title: str
    description: str
    status: ControlStatus
    severity: Severity
    evidence_finding_ids: List[str] = Field(default_factory=list)
    evidence_asset_bom_refs: List[str] = Field(default_factory=list)
    waiver_reasons: List[str] = Field(default_factory=list)
    remediation: str

    model_config = ConfigDict(use_enum_values=True)


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
    controls: List[ControlResult] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)
    residual_risks: List[ResidualRisk] = Field(default_factory=list)
    inputs_fingerprint: str

    model_config = ConfigDict(use_enum_values=True)
