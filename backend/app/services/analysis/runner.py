"""Run a registered analyzer over one SBOM and judge its result."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from app.schemas.sbom import SBOMFormat
from app.services.aggregation import is_error_result
from app.services.analysis.registry import analyzer_factories
from app.services.analyzers.cli_base import CLIAnalyzer

# Analyzer result keys reporting incomplete coverage, with how to phrase each.
_PARTIAL_RESULT_KEYS: tuple[tuple[str, str], ...] = (
    ("partial_components_skipped", "{count} component(s) were not scanned"),
    ("partial_vulnerabilities_unhydrated", "{count} vulnerability record(s) could not be fetched"),
)


def _partial_result_reason(result: Any) -> str | None:
    """Why an analyzer's coverage is incomplete, or None when it is complete."""
    if not isinstance(result, dict):
        return None
    reasons = [template.format(count=result[key]) for key, template in _PARTIAL_RESULT_KEYS if result.get(key)]
    return "; ".join(reasons) if reasons else None


def sbom_source(sbom: dict[str, Any]) -> str | None:
    """The SBOM's root component name, else its serial number."""
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
    """Return a function that yields per-analyzer settings dicts."""
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
    """One SBOM as the analyzers read it."""

    # 1-based, so a label names the SBOM the caller sent even when an earlier one was skipped.
    position: int
    components: list[dict[str, Any]]
    # The root component name or serial number, which a finding's source prefers over the label.
    name: str | None = None
    # What a CLI scanner reads: the written file when there is one, else the document.
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
    # The failure message, or the coverage the analyzer missed.
    reason: str = ""
    # What the status line counts, such as "12 enriched".
    detail: str = ""
    # The exception raised in place of a judgeable result: by the analyzer, its inputs or storing its result.
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
    """Hand the result to ``keep`` and judge it; a ``keep`` that raises fails the analyzer."""
    try:
        await keep(result)
    except Exception as exc:
        return AnalyzerOutcome.from_error(name, exc)
    return AnalyzerOutcome.from_result(name, result)


async def run_analyzer(name: str, sbom: AnalyzerInput, settings: dict[str, Any], keep: Keep) -> AnalyzerOutcome:
    """Run the registered analyzer over one SBOM and record its result; what it raises is a failed outcome."""
    analyzer = analyzer_factories[name]()
    try:
        if isinstance(analyzer, CLIAnalyzer) and sbom.path:
            result = await analyzer.analyze_file(sbom.path, sbom.format)
        else:
            result = await analyzer.analyze(sbom.document, settings=settings, parsed_components=sbom.components)
    except Exception as exc:
        return AnalyzerOutcome.from_error(name, exc)
    return await record_result(name, result, keep)
