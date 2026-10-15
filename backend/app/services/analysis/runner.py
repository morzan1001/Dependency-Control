from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from app.schemas.sbom import SBOMFormat
from app.services.aggregation import is_error_result
from app.services.analysis.registry import analyzer_factories
from app.services.analyzers.cli_base import CLIAnalyzer

_PARTIAL_RESULT_KEYS: tuple[tuple[str, str], ...] = (
    ("partial_components_skipped", "{count} component(s) were not scanned"),
    ("partial_vulnerabilities_unhydrated", "{count} vulnerability record(s) could not be fetched"),
)


def _partial_result_reason(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None
    reasons = [template.format(count=result[key]) for key, template in _PARTIAL_RESULT_KEYS if result.get(key)]
    return "; ".join(reasons) if reasons else None


def sbom_name(sbom: dict[str, Any]) -> str | None:
    metadata = sbom.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        # An explicit ``"name": null`` is a present key, so a dict default would never fire.
        name = metadata["component"].get("name")
        if name:
            return str(name)
    serial = sbom.get("serialNumber")
    return str(serial) if serial else None


def build_settings_resolver(
    system_settings: Any,
    project_analyzer_settings: dict[str, dict[str, Any]] | None,
    github_token: str | None = None,
) -> Callable[[str], dict[str, Any]]:
    base_settings = system_settings.model_dump() if system_settings else {}
    base_settings["github_token"] = github_token

    def _settings_for(analyzer_name: str) -> dict[str, Any]:
        merged = dict(base_settings)
        if project_analyzer_settings:
            overrides = project_analyzer_settings.get(analyzer_name)
            if overrides:
                merged.update(overrides)
        return merged

    return _settings_for


def sbom_label(position: int) -> str:
    return f"SBOM #{position}"


@dataclass(frozen=True)
class AnalyzerInput:
    # 1-based, so a label names the SBOM the caller sent even when an earlier one was skipped.
    position: int
    components: list[dict[str, Any]]
    name: str | None = None
    document: dict[str, Any] = field(default_factory=dict)
    path: str | None = None
    format: SBOMFormat = SBOMFormat.UNKNOWN

    @property
    def label(self) -> str:
        return sbom_label(self.position)

    @property
    def source(self) -> str:
        return self.name or self.label


class OutcomeStatus(IntEnum):
    """Ordered from best to worst, so the worse of two outcomes compares greater."""

    SUCCESS = 0
    PARTIAL = 1
    FAILED = 2


@dataclass(frozen=True)
class AnalyzerOutcome:
    name: str
    status: OutcomeStatus
    reason: str = ""
    detail: str = ""
    error: Exception | None = None

    @classmethod
    def from_result(cls, name: str, result: Any) -> "AnalyzerOutcome":
        if is_error_result(result):
            return cls(name, OutcomeStatus.FAILED, str(result["error"]))
        partial = _partial_result_reason(result)
        return cls(name, OutcomeStatus.PARTIAL, partial) if partial else cls(name, OutcomeStatus.SUCCESS)

    @classmethod
    def from_error(cls, name: str, error: Exception) -> "AnalyzerOutcome":
        return cls(name, OutcomeStatus.FAILED, str(error), error=error)

    def __str__(self) -> str:
        if self.status is OutcomeStatus.FAILED:
            return f"{self.name}: Failed"
        status = f"Partial ({self.reason})" if self.status is OutcomeStatus.PARTIAL else "Success"
        return f"{self.name}: {status} ({self.detail})" if self.detail else f"{self.name}: {status}"


Keep = Callable[[Any], Awaitable[None]]


async def record_result(name: str, result: Any, keep: Keep) -> AnalyzerOutcome:
    try:
        await keep(result)
    except Exception as exc:
        return AnalyzerOutcome.from_error(name, exc)
    return AnalyzerOutcome.from_result(name, result)


async def run_analyzer(name: str, sbom: AnalyzerInput, settings: dict[str, Any], keep: Keep) -> AnalyzerOutcome:
    analyzer = analyzer_factories[name]()
    try:
        if isinstance(analyzer, CLIAnalyzer) and sbom.path:
            result = await analyzer.analyze_file(sbom.path, sbom.format)
        else:
            result = await analyzer.analyze(sbom.document, settings=settings, parsed_components=sbom.components)
    except Exception as exc:
        return AnalyzerOutcome.from_error(name, exc)
    return await record_result(name, result, keep)
