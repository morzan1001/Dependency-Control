"""Central registry of analyzers and post-processors with name-based lookup.

Each entry is a factory, not an instance: an analyzer that binds the calling project's settings to
``self`` would otherwise let one project's thresholds decide another project's severities whenever
two scans overlap.
"""

from collections.abc import Callable
from functools import partial

from app.core.constants import CI_SCANNER_ANALYZERS
from app.schemas.crypto_policy import RULE_DRIVEN_FINDING_TYPES
from app.services.analyzers import (
    Analyzer,
    CertificateLifecycleAnalyzer,
    CryptoRuleAnalyzer,
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
    ProtocolCipherSuiteAnalyzer,
    ReachabilityAnalyzer,
    TrivyAnalyzer,
    TyposquattingAnalyzer,
)

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
    **{
        finding_type.value: partial(CryptoRuleAnalyzer, name=finding_type.value, finding_types={finding_type})
        for finding_type in sorted(RULE_DRIVEN_FINDING_TYPES)
    },
    "crypto_certificate_lifecycle": CertificateLifecycleAnalyzer,
    "crypto_protocol_cipher": ProtocolCipherSuiteAnalyzer,
}

# Post-processors enrich existing findings; they run after analyzers and don't see SBOMs.
post_processor_factories: dict[str, AnalyzerFactory] = {
    "epss_kev": EPSSKEVAnalyzer,
    "reachability": ReachabilityAnalyzer,
}

# Vulnerability scanners — post-processors depend on these.
VULNERABILITY_ANALYZERS: set[str] = {"trivy", "grype", "osv", "deps_dev"}

# The only analyzers that read the posted document itself; every other one grades the parser's components.
RAW_SBOM_ANALYZERS: set[str] = {"trivy", "grype"}

CRYPTO_ANALYZERS: set[str] = {
    *(finding_type.value for finding_type in RULE_DRIVEN_FINDING_TYPES),
    "crypto_certificate_lifecycle",
    "crypto_protocol_cipher",
}


# Names a project may list; crypto analyzers are left out because CBOM presence decides them.
SELECTABLE_ANALYZERS: frozenset[str] = frozenset(
    (analyzer_factories.keys() - CRYPTO_ANALYZERS) | post_processor_factories.keys() | CI_SCANNER_ANALYZERS
)


def is_crypto_analyzer(name: str) -> bool:
    return name in CRYPTO_ANALYZERS
