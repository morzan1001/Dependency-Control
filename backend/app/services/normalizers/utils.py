"""Shared helpers for normalizing scanner result data."""

import re
from typing import Any, Dict, List, Optional, Tuple

from app.core.constants import SEVERITY_ALIASES
from app.models.finding import Severity


def safe_severity(
    value: Optional[str],
    default: Severity = Severity.UNKNOWN,
) -> Severity:
    """Parse a scanner severity string to a Severity enum, never raising."""
    if not value:
        return default

    normalized = value.strip().upper()
    normalized = SEVERITY_ALIASES.get(normalized, normalized)

    try:
        return Severity(normalized)
    except ValueError:
        try:
            return Severity[normalized]
        except KeyError:
            return default


def normalize_list(value: str | List[str] | None) -> List[str]:
    """Coerce a string, list, or None into a list of non-empty strings."""
    if not value:
        return []
    if isinstance(value, list):
        return [v for v in value if v]
    return [value]


def normalize_cwe_list(cwe: str | List[str] | None) -> List[str]:
    """Extract bare CWE number strings from any scanner CWE format (e.g. "CWE-327" -> "327")."""
    if not cwe:
        return []

    cwe_list = normalize_list(cwe)
    result = []

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
    """Like dict.get but returns default when the value is None, not just missing."""
    value = data.get(key)
    return value if value is not None else default


def build_finding_id(
    prefix: str,
    *parts: Any,
    separator: str = "-",
) -> str:
    """Build a finding ID like "PREFIX-part1-part2", skipping None/empty parts."""
    valid_parts = [str(p) for p in parts if p]

    if not valid_parts:
        return f"{prefix}{separator}unknown"

    return f"{prefix}{separator}{separator.join(valid_parts)}"


def _find_v3_score(cvss_data: Dict[str, Any], source_priority: List[str]) -> Tuple[Optional[float], Optional[str]]:
    for source in source_priority:
        data = cvss_data.get(source)
        if not data or "V3Score" not in data:
            continue
        v3_score = data.get("V3Score")
        if v3_score is not None:
            return float(v3_score), data.get("V3Vector")
    return None, None


def extract_cvss(
    cvss_data: Dict[str, Any],
    prefer_v3: bool = True,
) -> Tuple[Optional[float], Optional[str]]:
    """Extract a (score, vector) CVSS pair from Trivy/Grype data, preferring v3."""
    if not cvss_data:
        return None, None

    source_priority = ["nvd", "redhat", "ghsa", "bitnami"]

    if prefer_v3:
        v3_result = _find_v3_score(cvss_data, source_priority)
        if v3_result[0] is not None:
            return v3_result

    for source in source_priority:
        if source not in cvss_data:
            continue
        data = cvss_data[source]
        if "V2Score" in data:
            v2_score = data.get("V2Score")
            if v2_score is not None:
                return float(v2_score), data.get("V2Vector")

    return None, None


def extract_grype_cvss(
    cvss_list: List[Dict[str, Any]],
) -> Tuple[Optional[float], Optional[str]]:
    """Pick the highest-version CVSS (score, vector) from Grype's CVSS list."""
    if not cvss_list:
        return None, None

    best_cvss = None
    best_version: Tuple[int, ...] = (0, 0)

    def _parse_cvss_version(v: str) -> Tuple[int, ...]:
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

    metrics = best_cvss.get("metrics", {})
    base_score = metrics.get("baseScore") if metrics else None

    if base_score is not None:
        return float(base_score), best_cvss.get("vector")

    return None, best_cvss.get("vector")


def prefer_cve_as_primary_id(vuln_id: str, aliases: List[str]) -> Tuple[str, List[str]]:
    """Swap a non-CVE primary id with a CVE from aliases, keeping the original as an alias."""
    cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
    if cve_alias and vuln_id and not vuln_id.startswith("CVE-"):
        if vuln_id not in aliases:
            aliases.append(vuln_id)
        return cve_alias, aliases
    return vuln_id, aliases
