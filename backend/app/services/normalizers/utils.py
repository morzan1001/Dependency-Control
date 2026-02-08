"""
Shared utility functions for normalizers.

These helpers provide consistent error handling and data normalization
across all scanner result normalizers.
"""

import re
from typing import Any, Dict, List, Optional, Tuple, Union

from app.core.constants import SEVERITY_ALIASES
from app.models.finding import Severity


def safe_severity(
    value: Optional[str],
    default: Severity = Severity.UNKNOWN,
) -> Severity:
    """
    Safely parse a severity string to Severity enum.

    Handles various formats from different scanners and returns
    a valid Severity enum value, never raises ValueError.

    Args:
        value: Raw severity string from scanner output
        default: Fallback severity if parsing fails

    Returns:
        Valid Severity enum value
    """
    if not value:
        return default

    # Normalize to uppercase
    normalized = value.strip().upper()

    # Apply aliases
    normalized = SEVERITY_ALIASES.get(normalized, normalized)

    # Try to parse as Severity enum
    try:
        return Severity(normalized)
    except ValueError:
        # Check if it's a valid enum member name
        try:
            return Severity[normalized]
        except KeyError:
            return default


def normalize_list(value: Optional[Union[str, List[str]]]) -> List[str]:
    """
    Normalize a value that could be a string or list to always be a list.

    Args:
        value: String, list of strings, or None

    Returns:
        List of strings (empty list if input is None/empty)
    """
    if not value:
        return []
    if isinstance(value, list):
        return [v for v in value if v]  # Filter out None/empty values
    return [value]


def normalize_cwe_list(cwe: Optional[Union[str, List[str]]]) -> List[str]:
    """
    Normalize CWE references to a list of CWE IDs (just the numbers).

    Handles various formats from different scanners:
    - "327" -> "327"
    - "CWE-327" -> "327"
    - "CWE-327: Use of a Broken or Risky Cryptographic Algorithm" -> "327"

    Args:
        cwe: CWE reference(s) in various formats

    Returns:
        List of CWE ID numbers as strings
    """
    if not cwe:
        return []

    cwe_list = normalize_list(cwe)
    result = []

    # Regex to extract CWE number from various formats
    cwe_pattern = re.compile(r"(?:CWE-)?(\d+)", re.IGNORECASE)

    for item in cwe_list:
        if isinstance(item, str):
            match = cwe_pattern.search(item)
            if match:
                result.append(match.group(1))

    return result


def safe_get(
    data: Dict[str, Any],
    key: str,
    default: Any = "",
) -> Any:
    """
    Safely get a value from a dict with a default fallback.

    Unlike dict.get(), this also handles None values by returning the default.

    Args:
        data: Dictionary to get value from
        key: Key to look up
        default: Value to return if key is missing or value is None

    Returns:
        Value from dict or default
    """
    value = data.get(key)
    return value if value is not None else default


def build_finding_id(
    prefix: str,
    *parts: Any,
    separator: str = "-",
) -> str:
    """
    Build a unique finding ID from parts, handling None/empty values safely.

    Args:
        prefix: ID prefix (e.g., "MALWARE", "CVE", "SAST")
        *parts: Variable parts to include in the ID
        separator: Separator between parts

    Returns:
        Finding ID string like "PREFIX-part1-part2"
    """
    # Filter out None and empty values, convert to strings
    valid_parts = [str(p) for p in parts if p]

    if not valid_parts:
        return f"{prefix}{separator}unknown"

    return f"{prefix}{separator}{separator.join(valid_parts)}"


def extract_cvss(
    cvss_data: Dict[str, Any],
    prefer_v3: bool = True,
) -> Tuple[Optional[float], Optional[str]]:
    """
    Extract CVSS score and vector from various scanner formats.

    Handles Trivy and Grype CVSS structures with preference for CVSS v3.

    Args:
        cvss_data: CVSS data from scanner output
        prefer_v3: Whether to prefer CVSS v3 over v2

    Returns:
        Tuple of (score, vector) or (None, None) if not available
    """
    if not cvss_data:
        return None, None

    # Priority order for sources
    source_priority = ["nvd", "redhat", "ghsa", "bitnami"]

    best_score = None
    best_vector = None
    best_version = 0

    for source in source_priority:
        if source not in cvss_data:
            continue

        data = cvss_data[source]

        # Check V3 first (preferred)
        if prefer_v3 and "V3Score" in data:
            v3_score = data.get("V3Score")
            if v3_score is not None:
                # V3 is preferred, take it immediately
                return float(v3_score), data.get("V3Vector")

        # Check V2 as fallback
        if "V2Score" in data and best_version < 2:
            v2_score = data.get("V2Score")
            if v2_score is not None:
                best_score = float(v2_score)
                best_vector = data.get("V2Vector")
                best_version = 2

    return best_score, best_vector


def extract_grype_cvss(
    cvss_list: List[Dict[str, Any]],
) -> Tuple[Optional[float], Optional[str]]:
    """
    Extract best CVSS score from Grype's CVSS list format.

    Grype returns CVSS as a list of objects with version info.
    We prefer the highest version (3.1 > 3.0 > 2.0).

    Args:
        cvss_list: List of CVSS objects from Grype

    Returns:
        Tuple of (score, vector) or (None, None) if not available
    """
    if not cvss_list:
        return None, None

    best_cvss = None
    best_version = (0, 0)

    def _parse_cvss_version(v: str) -> Tuple[int, ...]:
        """Parse CVSS version string to numeric tuple for correct comparison."""
        try:
            return tuple(int(p) for p in v.split("."))
        except (ValueError, AttributeError):
            return (0, 0)

    for cvss in cvss_list:
        version = _parse_cvss_version(cvss.get("version", "0.0"))
        if version > best_version:
            best_version = version
            best_cvss = cvss

    if not best_cvss:
        return None, None

    # Safely extract score - handle None case
    metrics = best_cvss.get("metrics", {})
    base_score = metrics.get("baseScore") if metrics else None

    if base_score is not None:
        return float(base_score), best_cvss.get("vector")

    return None, best_cvss.get("vector")
