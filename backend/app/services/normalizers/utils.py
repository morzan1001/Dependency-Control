import re
from enum import StrEnum
from typing import Any

from app.core.constants import SEVERITY_ALIASES
from app.models.finding import Severity


def safe_severity(
    value: str | None,
    default: Severity = Severity.UNKNOWN,
) -> Severity:
    if not value:
        return default

    normalized = value.strip().upper()
    normalized = SEVERITY_ALIASES.get(normalized, normalized)

    try:
        return Severity(normalized)
    except ValueError:
        return default


def normalize_list(value: str | list[str] | None) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [v for v in value if v]
    return [value]


def normalize_cwe_list(cwe: str | list[str] | None) -> list[str]:
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
            elif item.startswith("NVD-CWE-"):
                # NVD's markers for "no info" and "other" carry no number but are part of the advisory.
                result.append(item)

    return result


def safe_get(
    data: dict[str, Any],
    key: str,
    default: Any = "",
) -> Any:
    """Like dict.get but returns default when the value is None, not just missing."""
    value = data.get(key)
    return value if value is not None else default


# Rule id of a finding whose scanner named none; every such finding shares it, so it names no rule to widen to.
UNKNOWN_RULE_ID = "unknown"


class FindingIdPrefix(StrEnum):
    """Id prefixes that readers dispatch on (quality buckets, waiver signatures and scoping)."""

    SCORECARD = "SCORECARD"
    MAINT = "MAINT"
    OPENGREP = "OPENGREP"
    BEARER = "BEARER"
    KICS = "KICS"
    SECRET = "SECRET"
    LICENSE = "LIC"
    EOL = "EOL"


def build_finding_id(prefix: str, *parts: Any) -> str:
    valid_parts = [str(p) for p in parts if p]
    return "-".join([prefix, *(valid_parts or ["unknown"])])


_TRIVY_CVSS_SOURCES = ("nvd", "redhat", "ghsa", "bitnami")
_TRIVY_CVSS_VERSIONS = (("V3Score", "V3Vector"), ("V40Score", "V40Vector"), ("V2Score", "V2Vector"))


def extract_cvss(cvss_data: dict[str, Any]) -> tuple[float | None, str | None]:
    if not cvss_data:
        return None, None
    for score_key, vector_key in _TRIVY_CVSS_VERSIONS:
        for source in _TRIVY_CVSS_SOURCES:
            data = cvss_data.get(source) or {}
            if (score := data.get(score_key)) is not None:
                return float(score), data.get(vector_key)
    return None, None


def extract_grype_cvss(
    cvss_list: list[dict[str, Any]],
) -> tuple[float | None, str | None]:
    if not cvss_list:
        return None, None

    best_cvss = None
    best_version: tuple[int, ...] = (0, 0)

    def _parse_cvss_version(v: str) -> tuple[int, ...]:
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


def prefer_cve_as_primary_id(vuln_id: str, aliases: list[str]) -> tuple[str, list[str]]:
    cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
    if cve_alias and vuln_id and not vuln_id.startswith("CVE-"):
        others = [alias for alias in aliases if alias != cve_alias]
        return cve_alias, others if vuln_id in others else [*others, vuln_id]
    return vuln_id, aliases
