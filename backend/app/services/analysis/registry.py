"""Central registry of analyzers and post-processors with name-based lookup."""

from app.models.finding import FindingType
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

analyzers: dict[str, Analyzer] = {
    "end_of_life": EndOfLifeAnalyzer(),
    "os_malware": OpenSourceMalwareAnalyzer(),
    "trivy": TrivyAnalyzer(),
    "osv": OSVAnalyzer(),
    "deps_dev": DepsDevAnalyzer(),
    "license_compliance": LicenseAnalyzer(),
    "grype": GrypeAnalyzer(),
    "outdated_packages": OutdatedAnalyzer(),
    "typosquatting": TyposquattingAnalyzer(),
    "hash_verification": HashVerificationAnalyzer(),
    "maintainer_risk": MaintainerRiskAnalyzer(),
    "crypto_weak_algorithm": CryptoRuleAnalyzer(
        name="crypto_weak_algorithm",
        finding_types={FindingType.CRYPTO_WEAK_ALGORITHM},
    ),
    "crypto_weak_key": CryptoRuleAnalyzer(
        name="crypto_weak_key",
        finding_types={FindingType.CRYPTO_WEAK_KEY},
    ),
    "crypto_quantum_vulnerable": CryptoRuleAnalyzer(
        name="crypto_quantum_vulnerable",
        finding_types={FindingType.CRYPTO_QUANTUM_VULNERABLE},
    ),
    "crypto_certificate_lifecycle": CertificateLifecycleAnalyzer(),
    "crypto_protocol_cipher": ProtocolCipherSuiteAnalyzer(),
}

# Post-processors enrich existing findings; they run after analyzers and don't see SBOMs.
post_processors: dict[str, Analyzer] = {
    "epss_kev": EPSSKEVAnalyzer(),
    "reachability": ReachabilityAnalyzer(),
}

# Vulnerability scanners — post-processors depend on these.
VULNERABILITY_ANALYZERS: set[str] = {"trivy", "grype", "osv", "deps_dev"}

CRYPTO_ANALYZERS: set[str] = {
    "crypto_weak_algorithm",
    "crypto_weak_key",
    "crypto_quantum_vulnerable",
    "crypto_certificate_lifecycle",
    "crypto_protocol_cipher",
}


def get_analyzer(name: str) -> Analyzer | None:
    """Look up an analyzer in either the analyzer or post-processor maps."""
    if name in analyzers:
        return analyzers[name]
    if name in post_processors:
        return post_processors[name]
    return None


def get_all_analyzer_names() -> list[str]:
    return list(analyzers.keys()) + list(post_processors.keys())


def is_vulnerability_analyzer(name: str) -> bool:
    return name in VULNERABILITY_ANALYZERS


def is_crypto_analyzer(name: str) -> bool:
    return name in CRYPTO_ANALYZERS


def is_post_processor(name: str) -> bool:
    return name in post_processors
