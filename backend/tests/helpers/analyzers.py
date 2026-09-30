"""Registry access for tests: the registry stores factories, not instances."""

from typing import Any

import pytest

from app.services.analysis import registry
from app.services.analyzers import Analyzer
from app.services.sbom_parser import parse_sbom


def build_analyzer(name: str) -> Any:
    """The instance a run would get for this name."""
    return registry.analyzer_factories[name]()


def serve_analyzer(monkeypatch: pytest.MonkeyPatch, name: str, analyzer: Analyzer | Any) -> Any:
    """Hand this one instance to every resolution of ``name``, so a test can inspect it afterwards."""
    monkeypatch.setitem(registry.analyzer_factories, name, lambda: analyzer)
    return analyzer


async def analyze_cyclonedx(
    analyzer: Analyzer, components: list[dict[str, Any]], settings: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Run the analyzer as the engine does: on the parser's reading of a CycloneDX document with these components."""
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
    return await analyzer.analyze(
        sbom, settings, [dependency.to_dict() for dependency in parse_sbom(sbom).dependencies]
    )
