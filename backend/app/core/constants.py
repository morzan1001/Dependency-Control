"""
Shared Constants

Centralized constants used across the application to ensure consistency.
"""

from typing import Dict, Optional

# Severity order for sorting (higher value = more severe)
SEVERITY_ORDER: Dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "negligible": 1,
    "info": 0,
    "unknown": 0,
    # Uppercase variants for compatibility
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "NEGLIGIBLE": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}


def get_severity_value(severity: Optional[str]) -> int:
    """Get numeric value for severity. Higher = more severe."""
    if not severity:
        return 0
    return SEVERITY_ORDER.get(severity.upper(), 0)


def sort_by_severity(items: list, key: str = "severity", reverse: bool = True) -> list:
    """
    Sort a list of dicts by severity.

    Args:
        items: List of dicts with severity field
        key: The key containing severity value
        reverse: If True, most severe first (default)
    """
    return sorted(
        items,
        key=lambda x: get_severity_value(
            x.get(key) if isinstance(x, dict) else getattr(x, key, None)
        ),
        reverse=reverse,
    )


# EPSS score thresholds based on exploitation probability
EPSS_HIGH_THRESHOLD: float = 0.1  # >= 10% - Very likely to be exploited
EPSS_MEDIUM_THRESHOLD: float = 0.01  # >= 1% - Moderate exploitation risk
EPSS_LOW_THRESHOLD: float = 0.0  # < 1% - Low exploitation risk


def classify_epss_risk(epss_score: Optional[float]) -> str:
    """
    Classify EPSS score into risk category.

    Args:
        epss_score: EPSS probability (0.0 - 1.0)

    Returns:
        Risk level: "high", "medium", "low", or "unknown"
    """
    if epss_score is None:
        return "unknown"
    if epss_score >= EPSS_HIGH_THRESHOLD:
        return "high"
    if epss_score >= EPSS_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def is_high_epss(epss_score: Optional[float]) -> bool:
    """Check if EPSS score indicates high exploitation risk."""
    return epss_score is not None and epss_score >= EPSS_HIGH_THRESHOLD


def is_actionable_epss(epss_score: Optional[float]) -> bool:
    """Check if EPSS score is significant enough to warrant action."""
    return epss_score is not None and epss_score >= EPSS_MEDIUM_THRESHOLD


# Standard finding type strings (use FindingType enum when possible)
FINDING_TYPE_VULNERABILITY = "vulnerability"
FINDING_TYPE_SECRET = "secret"
FINDING_TYPE_SAST = "sast"
FINDING_TYPE_IAC = "iac"
FINDING_TYPE_LICENSE = "license"
FINDING_TYPE_QUALITY = "quality"

ALL_FINDING_TYPES = [
    FINDING_TYPE_VULNERABILITY,
    FINDING_TYPE_SECRET,
    FINDING_TYPE_SAST,
    FINDING_TYPE_IAC,
    FINDING_TYPE_LICENSE,
    FINDING_TYPE_QUALITY,
]

# Weights for calculating adjusted risk scores
RISK_WEIGHT_SEVERITY: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "negligible": 0.1,
    "info": 0.0,
    "unknown": 0.3,
}

RISK_WEIGHT_KEV: float = 1.5  # Multiplier for KEV vulnerabilities
RISK_WEIGHT_RANSOMWARE: float = 1.8  # Multiplier for ransomware-associated CVEs
RISK_WEIGHT_REACHABLE: float = 1.3  # Multiplier for reachable code paths
RISK_WEIGHT_UNREACHABLE: float = 0.5  # Multiplier for unreachable code paths
