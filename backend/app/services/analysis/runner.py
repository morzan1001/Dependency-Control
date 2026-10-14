"""What the scan engine and the ad-hoc path share to run the analyzers over an SBOM."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.schemas.sbom import SBOMFormat

# Analyzer result keys reporting incomplete coverage, with how to phrase each.
_PARTIAL_RESULT_KEYS: tuple[tuple[str, str], ...] = (
    ("partial_components_skipped", "{count} component(s) were not scanned"),
    ("partial_vulnerabilities_unhydrated", "{count} vulnerability record(s) could not be fetched"),
)


def partial_result_reason(result: Any) -> str | None:
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
