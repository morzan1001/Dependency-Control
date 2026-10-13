"""process_analyzer hands a CLI scanner the SBOM file, which the engine writes only for RAW_SBOM_ANALYZERS."""

from app.services.analysis.registry import RAW_SBOM_ANALYZERS, analyzer_factories
from app.services.analyzers.cli_base import CLIAnalyzer


def test_every_cli_scanner_gets_the_sbom_file_written():
    cli_scanners = {name for name, factory in analyzer_factories.items() if isinstance(factory(), CLIAnalyzer)}

    assert cli_scanners
    assert cli_scanners <= RAW_SBOM_ANALYZERS
