"""
Analyzer Registry

Central registry for all analyzers and post-processors.
Provides lookup functions for finding analyzers by name.
"""

from typing import Dict, List, Optional, Set

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

# Regular analyzers that process SBOMs
analyzers: Dict[str, Analyzer] = {
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
}

# Post-processing analyzers that enrich existing findings
# These run AFTER regular analyzers and don't process SBOMs directly
post_processors: Dict[str, Analyzer] = {
    "epss_kev": EPSSKEVAnalyzer(),
    "reachability": ReachabilityAnalyzer(),
}

# Vulnerability scanner names (post-processors depend on these)
VULNERABILITY_ANALYZERS: Set[str] = {"trivy", "grype", "osv", "deps_dev"}


def get_analyzer(name: str) -> Optional[Analyzer]:
    """
    Get an analyzer by name, searching both regular analyzers and post-processors.

    Args:
        name: The analyzer name to look up

    Returns:
        The Analyzer instance if found, None otherwise
    """
    if name in analyzers:
        return analyzers[name]
    if name in post_processors:
        return post_processors[name]
    return None


def get_all_analyzer_names() -> List[str]:
    """
    Get all available analyzer names (both regular and post-processors).

    Returns:
        List of all analyzer names
    """
    return list(analyzers.keys()) + list(post_processors.keys())


def is_vulnerability_analyzer(name: str) -> bool:
    """
    Check if an analyzer is a vulnerability scanner.

    Args:
        name: The analyzer name to check

    Returns:
        True if the analyzer produces vulnerability findings
    """
    return name in VULNERABILITY_ANALYZERS


def is_post_processor(name: str) -> bool:
    """
    Check if an analyzer is a post-processor.

    Args:
        name: The analyzer name to check

    Returns:
        True if the analyzer is a post-processor
    """
    return name in post_processors
