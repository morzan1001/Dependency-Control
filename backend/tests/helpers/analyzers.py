"""Registry access for tests: the registry stores factories, not instances."""

from typing import Any

import pytest

from app.core.constants import MAX_CRYPTO_ASSETS_PER_SCAN
from app.repositories.crypto_asset import CryptoAssetRepository
from app.services.analysis import registry
from app.services.analyzers import Analyzer
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
        sbom, settings, [dependency.to_dict() for dependency in parse_sbom(sbom).dependencies]
    )


def bundled_iana_catalog() -> dict[str, CipherSuiteEntry]:
    return _materialize(_load_fallback_yaml())


async def evaluate_crypto(name: str, db: Any, project_id: str = "p", scan_id: str = "s") -> dict[str, Any]:
    """What the engine's crypto pass records for ``name`` over the stored assets and the resolved policy."""
    assets = await CryptoAssetRepository(db).list_by_scan(project_id, scan_id, limit=MAX_CRYPTO_ASSETS_PER_SCAN)
    policy = await CryptoPolicyResolver(db).resolve(project_id)
    return registry.crypto_evaluators(bundled_iana_catalog())[name](assets, policy)
