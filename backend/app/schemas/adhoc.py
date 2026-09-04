"""Request and response models for the stateless ad-hoc analysis endpoint."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.stats import Stats

MAX_ADHOC_SBOMS: int = 10
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
    license_policy: dict[str, Any] | None = None
    format: Literal["json", "html"] = "json"

    @model_validator(mode="after")
    def _require_input(self) -> "AdhocAnalyzeRequest":
        if not self.sboms and not (self.scanners and self.scanners.carries_payload()):
            raise ValueError("at least one of 'sboms' or 'scanners' must be supplied")
        return self


class AnalyzerReport(BaseModel):
    """Which analyzers contributed. Reasons are carried per name so a timeout is
    distinguishable from missing coverage."""

    ran: list[str] = Field(default_factory=list)
    skipped: dict[str, str] = Field(default_factory=dict)
    errored: dict[str, str] = Field(default_factory=dict)
    # Inputs the pipeline could not use, keyed by input label rather than analyzer name.
    skipped_inputs: dict[str, str] = Field(default_factory=dict)


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
    truncated: bool = False
