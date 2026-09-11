"""Request and response models for the stateless ad-hoc analysis endpoint."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.stats import Stats
from app.schemas.project import LicensePolicySchema

MAX_ADHOC_SBOMS: int = 10
# Above the 18 names in the analyzer registry; a literal because importing it here would
# construct every analyzer class at schema import time.
MAX_ADHOC_ANALYZERS: int = 25


class AdhocScannerPayloads(BaseModel):
    """Inner scanner result shapes, not the ingest envelopes: TruffleHog/OpenGrep/Bearer
    carry ``findings``, KICS carries ``queries``."""

    # A misspelled scanner name must not silently analyse nothing: the response is the caller's
    # only feedback channel.
    model_config = ConfigDict(extra="forbid")

    trufflehog: dict[str, Any] | None = None
    opengrep: dict[str, Any] | None = None
    bearer: dict[str, Any] | None = None
    kics: dict[str, Any] | None = None

    def carries_payload(self) -> bool:
        return any(getattr(self, name) is not None for name in type(self).model_fields)


class AdhocAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sboms: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_ADHOC_SBOMS)
    scanners: AdhocScannerPayloads | None = None
    analyzers: list[str] | None = Field(default=None, max_length=MAX_ADHOC_ANALYZERS)
    callgraph: dict[str, Any] | None = None
    apply_global_waivers: bool = True
    license_policy: LicensePolicySchema | None = None
    format: Literal["json", "html"] = "json"

    @model_validator(mode="after")
    def _require_input(self) -> "AdhocAnalyzeRequest":
        # An SBOM document with no keys carries nothing to analyse, just as an empty scanners
        # object does; either way the caller would get a 200 over an empty analysis.
        if not any(self.sboms) and not (self.scanners and self.scanners.carries_payload()):
            raise ValueError("at least one non-empty entry in 'sboms' or 'scanners' must be supplied")
        return self


class AnalyzerReport(BaseModel):
    """Which analyzers contributed. Reasons are carried per name so a timeout is
    distinguishable from missing coverage."""

    ran: list[str] = Field(default_factory=list)
    skipped: dict[str, str] = Field(default_factory=dict)
    # Every failure is kept: "failed on one of ten inputs" must not read like "failed on all ten".
    errored: dict[str, list[str]] = Field(default_factory=dict)
    # Defects in the posted inputs, keyed by input label rather than analyzer name.
    skipped_inputs: dict[str, str] = Field(default_factory=dict)
    # What a stage did that its findings do not show: where the posted data went, which
    # policy graded it. Storing nothing is not the same as sending nothing.
    notes: dict[str, str] = Field(default_factory=dict)


class AdhocTruncation(BaseModel):
    """What the findings ceiling cut. On a security endpoint "something was dropped" is not an
    answer: a caller has to be able to see whether a CRITICAL or a whole finding type went."""

    limit: int
    dropped: int
    dropped_by_type: dict[str, int] = Field(default_factory=dict)
    dropped_by_severity: dict[str, int] = Field(default_factory=dict)


class AdhocAnalyzeResponse(BaseModel):
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: Stats = Field(default_factory=Stats)
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    epss_kev_summary: dict[str, Any] = Field(default_factory=dict)
    reachability_summary: dict[str, Any] | None = None
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    analyzers: AnalyzerReport = Field(default_factory=AnalyzerReport)
    waivers_applied: Literal["global", "none"] = "none"
    waived_count: int = 0
    # Null when the whole result is returned, so a caller never has to read a count to find out.
    truncated: AdhocTruncation | None = None
