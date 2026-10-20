from collections.abc import Iterable
from typing import Any

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, ScanStatus
from app.core.init_db import create_indexes
from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.models.project import Scan
from app.models.stats import Stats
from app.repositories.crypto_asset import CryptoAssetRepository, scan_query
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.services.analysis import engine, registry
from app.services.analysis.runner import build_settings_resolver
from app.services.analyzers.base import Analyzer
from app.services.analyzers.crypto.catalogs.loader import CipherSuiteEntry, _load_fallback_yaml, _materialize
from app.services.cbom_parser import parse_cbom
from app.services.crypto_policy.resolver import CryptoPolicyResolver, EffectivePolicy
from app.services.crypto_policy.seeder import load_seed_rules
from app.services.sbom_parser import parse_sbom


def build_analyzer(name: str) -> Any:
    return registry.analyzer_factories[name]()


def serve_analyzer(monkeypatch: pytest.MonkeyPatch, name: str, analyzer: Analyzer | Any) -> Any:
    monkeypatch.setitem(registry.analyzer_factories, name, lambda: analyzer)
    return analyzer


async def analyze_cyclonedx(
    analyzer: Analyzer, components: list[dict[str, Any]], settings: dict[str, Any] | None = None
) -> dict[str, Any]:
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
    return await analyzer.analyze(
        sbom, settings, parsed_components=[dependency.model_dump() for dependency in parse_sbom(sbom).dependencies]
    )


def run_context(db: Any, scan: Scan | str, active_analyzers: Iterable[str] = (), **overrides: Any) -> Any:
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
    defaults = {
        "status": status,
        "error": None,
        "stats": stats or Stats(),
        "findings_count": 0,
        "ignored_count": 0,
        "outcomes": [],
        "failed_analyzers": [],
        "enrichment_failures": [],
    }
    return engine._Verdict(**(defaults | fields))


async def process_sbom_document(ctx: Any, aggregator: Any, sbom: dict[str, Any], position: int = 1) -> list[Any]:
    return await engine._process_sbom(ctx, aggregator, *engine._parse_and_track_sbom(sbom, position))


def bundled_iana_catalog() -> dict[str, CipherSuiteEntry]:
    return _materialize(_load_fallback_yaml())


async def evaluate_crypto(name: str, db: Any, project_id: str = "p", scan_id: str = "s") -> dict[str, Any]:
    docs = await CryptoAssetRepository(db).find_all_raw(scan_query(project_id, scan_id))
    assets = [CryptoAsset.model_validate(doc) for doc in docs]
    policy = await CryptoPolicyResolver(db).resolve(project_id)
    return registry.crypto_evaluators(bundled_iana_catalog())[name](assets, policy)


def scan_cbom(cbom: dict[str, Any]) -> tuple[list[CryptoAsset], list[dict[str, Any]]]:
    """Every crypto analyzer over the CBOM's assets under the seeded system policy, without a database."""
    rules = load_seed_rules()
    policy = EffectivePolicy(rules=rules, system_rules=rules, system_version=1, override_version=None)
    assets = [CryptoAsset(project_id="p", scan_id="s", **asset.model_dump()) for asset in parse_cbom(cbom)]
    evaluators = registry.crypto_evaluators(bundled_iana_catalog()).values()
    return assets, [finding for evaluate in evaluators for finding in evaluate(assets, policy)["findings"]]


async def ingest_and_analyze_cbom(
    client: Any, db: Any, headers: dict[str, str], cbom: dict[str, Any], **payload: Any
) -> str:
    await create_indexes(db)
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", rules=list(load_seed_rules()), version=1)
    )
    resp = await client.post("/api/v1/ingest/cbom", json={**payload, "cbom": cbom}, headers=headers)
    assert resp.status_code == 202, resp.text
    scan_id: str = resp.json()["scan_id"]
    scan = await db.scans.find_one_and_update(
        {"_id": scan_id}, {"$set": {"status": "processing", "worker_id": "pod-a/worker-0"}}, return_document=True
    )
    status = await engine.run_analysis(
        scan_id, [], [], db, worker_id="pod-a/worker-0", sbom_generation=scan["sbom_generation"]
    )
    assert status == SCAN_STATUS_COMPLETED
    return scan_id
