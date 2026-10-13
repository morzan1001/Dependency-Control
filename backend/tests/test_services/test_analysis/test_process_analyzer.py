"""process_analyzer records an analyzer that cannot run as a failed scanner naming the cause."""

import pytest

from app.schemas.sbom import SBOMFormat
from app.services.aggregation import ResultAggregator
from app.services.analysis import engine
from app.services.analyzers.trivy import TrivyAnalyzer


@pytest.mark.asyncio
async def test_a_cli_scanner_without_the_sbom_file_fails_naming_the_missing_file():
    aggregator = ResultAggregator()

    outcome = await engine.process_analyzer(
        "trivy",
        TrivyAnalyzer(),
        "scan-1",
        None,
        aggregator,
        settings={},
        source="sbom.json",
        row_source="SBOM #1",
        parsed_components=[],
        sbom_path=None,
        sbom_format=SBOMFormat.CYCLONEDX,
    )

    assert outcome == "trivy: Failed"
    [warning] = aggregator.get_findings()
    assert "SBOM file" in warning.description
