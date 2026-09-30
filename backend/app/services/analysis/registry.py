"""Central registry of analyzers and post-processors with name-based lookup.

Each entry is a factory, not an instance: an analyzer that binds the calling project's settings to
``self`` would otherwise let one project's thresholds decide another project's severities whenever
two scans overlap.
"""

from collections.abc import Callable
from functools import partial
from typing import Any

from app.core.constants import CI_SCANNER_ANALYZERS
from app.models.crypto_asset import CryptoAsset
from app.schemas.crypto_policy import RULE_DRIVEN_FINDING_TYPES
from app.services.analyzers import (
    Analyzer,
    DepsDevAnalyzer,
    EndOfLifeAnalyzer,
    EPSSKEVAnalyzer,
    GrypeAnalyzer,
    HashVerificationAnalyzer,
    LicenseAnalyzer,
    MaintainerRiskAnalyzer,
    OpenSourceMalwareAnalyzer,
    OSVAnalyzer,
    OutdatedAnalyzer,
    ReachabilityAnalyzer,
    TrivyAnalyzer,
    TyposquattingAnalyzer,
)
from app.services.analyzers.crypto.base import evaluate_rules
from app.services.analyzers.crypto.catalogs.loader import CipherSuiteEntry
from app.services.analyzers.crypto.certificate_lifecycle import evaluate_certificates
from app.services.analyzers.crypto.protocol_cipher import evaluate_protocols
from app.services.crypto_policy.resolver import EffectivePolicy

AnalyzerFactory = Callable[[], Analyzer]

analyzer_factories: dict[str, AnalyzerFactory] = {
    "end_of_life": EndOfLifeAnalyzer,
    "os_malware": OpenSourceMalwareAnalyzer,
    "trivy": TrivyAnalyzer,
    "osv": OSVAnalyzer,
    "deps_dev": DepsDevAnalyzer,
    "license_compliance": LicenseAnalyzer,
    "grype": GrypeAnalyzer,
    "outdated_packages": OutdatedAnalyzer,
    "typosquatting": TyposquattingAnalyzer,
    "hash_verification": HashVerificationAnalyzer,
    "maintainer_risk": MaintainerRiskAnalyzer,
}

# Post-processors enrich existing findings; they run after analyzers and don't see SBOMs.
post_processor_factories: dict[str, AnalyzerFactory] = {
    "epss_kev": EPSSKEVAnalyzer,
    "reachability": ReachabilityAnalyzer,
}

# Vulnerability scanners — post-processors depend on these.
VULNERABILITY_ANALYZERS: set[str] = {"trivy", "grype", "osv", "deps_dev"}

CryptoEvaluator = Callable[[list[CryptoAsset], EffectivePolicy], dict[str, Any]]


# Scan-scoped: the engine runs these once per scan over the persisted crypto assets.
def crypto_evaluators(catalog: dict[str, CipherSuiteEntry]) -> dict[str, CryptoEvaluator]:
    return {
        **{
            finding_type.value: partial(evaluate_rules, finding_type=finding_type)
            for finding_type in sorted(RULE_DRIVEN_FINDING_TYPES)
        },
        "crypto_certificate_lifecycle": evaluate_certificates,
        "crypto_protocol_cipher": partial(evaluate_protocols, catalog=catalog),
    }


CRYPTO_ANALYZERS: frozenset[str] = frozenset(crypto_evaluators({}))


# Names a project may list; crypto analyzers are not among them because CBOM presence decides them.
SELECTABLE_ANALYZERS: frozenset[str] = frozenset(
    analyzer_factories.keys() | post_processor_factories.keys() | CI_SCANNER_ANALYZERS
)
