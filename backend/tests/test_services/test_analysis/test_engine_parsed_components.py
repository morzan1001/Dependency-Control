"""The parser is the only component source: analyzers get its list, and an unparseable SBOM runs only the CLI scanners."""

import json
from pathlib import Path
from typing import Any

import pytest

from app.services.aggregation import ResultAggregator
from app.services.analysis import engine
from app.services.analyzers import LicenseAnalyzer
from app.services.sbom_parser import parse_sbom

_CBOM_FIXTURE = Path(__file__).parents[2] / "fixtures" / "cbom" / "legacy_crypto_mixed.json"

# The malformed metadata makes the parser raise; the components list is what a raw re-read would pick up.
_UNPARSEABLE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": 3,
    "components": [{"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}],
}


async def _components_by_analyzer(monkeypatch, sbom: dict[str, Any], active: list[str]) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    async def record(analyzer_name, *_args, parsed_components, **_kwargs):
        seen[analyzer_name] = parsed_components
        return f"{analyzer_name}: Success"

    monkeypatch.setattr(engine, "process_analyzer", record)
    await engine._process_sbom(0, sbom, "scan-1", None, ResultAggregator(), active, None)
    return seen


@pytest.mark.asyncio
async def test_a_parse_that_skipped_every_component_hands_the_analyzers_an_empty_list(monkeypatch):
    sbom = json.loads(_CBOM_FIXTURE.read_text())

    seen = await _components_by_analyzer(monkeypatch, sbom, ["license_compliance", "typosquatting"])

    assert seen["license_compliance"] == []
    assert seen["typosquatting"] == []


@pytest.mark.asyncio
async def test_an_unparseable_sbom_runs_only_the_scanners_that_read_the_raw_document(monkeypatch):
    active = ["grype", "license_compliance", "osv", "trivy", "typosquatting"]

    seen = await _components_by_analyzer(monkeypatch, _UNPARSEABLE_SBOM, active)

    assert sorted(seen) == ["grype", "trivy"]


@pytest.mark.asyncio
async def test_components_the_parser_skipped_produce_no_license_findings():
    sbom = json.loads(_CBOM_FIXTURE.read_text())
    parsed = [dependency.to_dict() for dependency in parse_sbom(sbom).dependencies]

    result = await LicenseAnalyzer().analyze(sbom, parsed_components=parsed)

    assert result["summary"]["total_components"] == 0
    assert result["license_issues"] == []
