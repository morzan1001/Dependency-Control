"""Registry access for tests: the registry stores factories, not instances."""

from collections.abc import Iterable
from typing import Any

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, ScanStatus
from app.models.crypto_asset import CryptoAsset
from app.models.project import Scan
from app.models.stats import Stats
from app.repositories.crypto_asset import CryptoAssetRepository, scan_query
from app.services.analysis import engine, registry
from app.services.analysis.runner import AnalyzerInput, build_settings_resolver
from app.services.analyzers.base import Analyzer
from app.services.analyzers.crypto.catalogs.loader import CipherSuiteEntry, _load_fallback_yaml, _materialize
from app.services.crypto_policy.resolver import CryptoPolicyResolver
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
        sbom, settings, [dependency.model_dump() for dependency in parse_sbom(sbom).dependencies]
    )


def run_context(db: Any, scan: Scan | str, active_analyzers: Iterable[str] = (), **overrides: Any) -> Any:
    """The context run_analysis builds for a claimed ``scan`` (or a bare one of that id), minus the settings reads."""
    if isinstance(scan, str):
        scan = Scan(id=scan, project_id="test-project-id", branch="main")
    fields = {
        "scan": scan,
        "db": db,
        "worker_id": "pod-a/worker-0",
        "sbom_generation": scan.sbom_generation,
        "active_analyzers": list(active_analyzers),
        "github_token": None,
        "settings_for": build_settings_resolver(None, None),
    }
    return engine._RunContext(**(fields | overrides))


def verdict(status: ScanStatus = SCAN_STATUS_COMPLETED, stats: Stats | None = None, **fields: Any) -> Any:
    """A run's verdict with no findings and no failed analyzers, unless ``fields`` say otherwise."""
    defaults = {
        "status": status,
        "error": None,
        "stats": stats or Stats(),
        "findings_count": 0,
        "ignored_count": 0,
        "analyzer_outcomes": {},
        "failed_analyzers": [],
        "enrichment_failures": [],
    }
    return engine._Verdict(**(defaults | fields))


async def process_sbom_document(ctx: Any, aggregator: Any, sbom: dict[str, Any], position: int = 1) -> list[Any]:
    """Run ``engine._process_sbom`` on the document as run_analysis hands it a loaded SBOM, for the non-CLI analyzers."""
    parsed, components, name, sbom_format = engine._parse_and_track_sbom(sbom)
    return await engine._process_sbom(
        ctx, aggregator, parsed, AnalyzerInput(position, components, name=name, format=sbom_format)
    )


def bundled_iana_catalog() -> dict[str, CipherSuiteEntry]:
    return _materialize(_load_fallback_yaml())


async def evaluate_crypto(name: str, db: Any, project_id: str = "p", scan_id: str = "s") -> dict[str, Any]:
    """What the engine's crypto pass records for ``name`` over the stored assets and the resolved policy."""
    docs = await CryptoAssetRepository(db).find_all_raw(scan_query(project_id, scan_id))
    assets = [CryptoAsset.model_validate(doc) for doc in docs]
    policy = await CryptoPolicyResolver(db).resolve(project_id)
    return registry.crypto_evaluators(bundled_iana_catalog())[name](assets, policy)
