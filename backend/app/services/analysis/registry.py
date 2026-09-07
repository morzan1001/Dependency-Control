"""Central registry of analyzers and post-processors with name-based lookup.

Each entry is a factory, not an instance: an analyzer that binds the calling project's settings to
``self`` would otherwise let one project's thresholds decide another project's severities whenever
two scans overlap.
"""

from collections.abc import Callable
from functools import partial

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
    "crypto_weak_algorithm": partial(
        CryptoRuleAnalyzer,
        name="crypto_weak_algorithm",
        finding_types={FindingType.CRYPTO_WEAK_ALGORITHM},
    ),
    "crypto_weak_key": partial(
        CryptoRuleAnalyzer,
        name="crypto_weak_key",
        finding_types={FindingType.CRYPTO_WEAK_KEY},
    ),
    "crypto_quantum_vulnerable": partial(
        CryptoRuleAnalyzer,
        name="crypto_quantum_vulnerable",
        finding_types={FindingType.CRYPTO_QUANTUM_VULNERABLE},
    ),
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

CRYPTO_ANALYZERS: set[str] = {
    "crypto_weak_algorithm",
    "crypto_weak_key",
    "crypto_quantum_vulnerable",
    "crypto_certificate_lifecycle",
    "crypto_protocol_cipher",
}


def is_crypto_analyzer(name: str) -> bool:
    return name in CRYPTO_ANALYZERS
