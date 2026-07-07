from typing import Any, Dict, Optional, TYPE_CHECKING

from app.core.constants import BEARER_SEVERITY_MAP, OPENGREP_SEVERITY_MAP
from app.models.finding import Finding, FindingType
from app.services.normalizers.utils import (
    build_finding_id,
    normalize_cwe_list,
    normalize_list,
    safe_severity,
)

if TYPE_CHECKING:
    from app.services.aggregation import ResultAggregator

_CRYPTO_MISUSE_RULE_ID_PREFIX = "crypto-misuse-"


def _finding_type_from_rule(rule_id: Any) -> FindingType:
    """crypto-misuse-* rules map to CRYPTO_KEY_MANAGEMENT; check_id may be a dotted path."""
    if not isinstance(rule_id, str):
        return FindingType.SAST
    if rule_id.startswith(_CRYPTO_MISUSE_RULE_ID_PREFIX):
        return FindingType.CRYPTO_KEY_MANAGEMENT
    last_segment = rule_id.rsplit(".", 1)[-1]
    if last_segment.startswith(_CRYPTO_MISUSE_RULE_ID_PREFIX):
        return FindingType.CRYPTO_KEY_MANAGEMENT
    return FindingType.SAST


def _build_opengrep_description(check_id: str, message: str) -> str:
    if "." in check_id:
        short_rule_name = check_id.split(".")[-1]
        return f"{short_rule_name}: {message}"
    return message


def _parse_opengrep_item(item: Dict[str, Any]) -> Finding:
    check_id = item.get("check_id") or "unknown-check"
    path = item.get("path") or "unknown"

    start_obj = item.get("start") or {}
    end_obj = item.get("end") or {}

    start_line = start_obj.get("line", 0)
    start_col = start_obj.get("col", 0)
    end_line = end_obj.get("line", 0)
    end_col = end_obj.get("col", 0)

    extra = item.get("extra") or {}
    sev_str = (extra.get("severity") or "INFO").upper()
    severity = safe_severity(OPENGREP_SEVERITY_MAP.get(sev_str, sev_str))
    message = extra.get("message") or "Potential issue found"

    metadata = extra.get("metadata") or {}
    cwe = metadata.get("cwe") or []
    owasp = metadata.get("owasp") or []

    finding_id = build_finding_id("OPENGREP", check_id, path, start_line)

    description = _build_opengrep_description(check_id, message)

    details = {
        "rule_id": check_id,
        "check_id": check_id,
        "title": message,
        "code_extract": extra.get("lines"),
        "start": {"line": start_line, "column": start_col},
        "end": {"line": end_line, "column": end_col},
        "cwe_ids": normalize_cwe_list(cwe),
        "owasp": normalize_list(owasp),
        "impact": metadata.get("impact"),
        "confidence": metadata.get("confidence"),
        "likelihood": metadata.get("likelihood"),
        "category": metadata.get("category"),
        "category_groups": metadata.get("category_groups") or [],
        "subcategory": normalize_list(metadata.get("subcategory")),
        "technology": normalize_list(metadata.get("technology")),
        "vulnerability_class": normalize_list(metadata.get("vulnerability_class")),
        "references": metadata.get("references") or [],
        "source_rule_url": metadata.get("source-rule-url") or metadata.get("source_rule_url"),
        "source": metadata.get("source"),
        "shortlink": metadata.get("shortlink"),
        "license": metadata.get("license"),
        "fingerprint": extra.get("fingerprint"),
    }

    return Finding(
        id=finding_id,
        type=_finding_type_from_rule(check_id),
        severity=severity,
        component=path,  # SAST findings attach to files, not packages
        version=None,
        description=description,
        scanners=["opengrep"],
        location={
            "file": path,
            "start_line": start_line,
            "end_line": end_line,
            "start_column": start_col,
            "end_column": end_col,
        },
        details=details,
    )


def normalize_opengrep(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None) -> None:
    # OpenGrep emits either "findings" or "results" depending on version.
    results = result.get("findings") or result.get("results") or []
    if not results:
        return

    for item in results:
        aggregator.add_finding(_parse_opengrep_item(item), source=source)


def normalize_bearer(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None) -> None:
    findings_container = result.get("findings") or {}

    # Bearer emits either a flat list or a dict keyed by severity.
    all_findings = []
    if isinstance(findings_container, list):
        all_findings = findings_container
    elif isinstance(findings_container, dict):
        for sev_key, items in findings_container.items():
            if isinstance(items, list):
                for item in items:
                    if "severity" not in item:
                        item["severity"] = sev_key.lower()
                    all_findings.append(item)

    for item in all_findings:
        title = item.get("title") or "Unknown data risk"
        desc = item.get("description") or ""
        sev_str = (item.get("severity") or "info").lower()
        severity = safe_severity(BEARER_SEVERITY_MAP.get(sev_str, sev_str))

        filename = item.get("full_filename") or item.get("filename") or item.get("file") or "unknown"

        source_obj = item.get("source") or {}
        line_number = item.get("line_number") or source_obj.get("start") or 0
        end_line = source_obj.get("end") or item.get("end_line_number") or line_number

        column_obj = source_obj.get("column") or {}
        start_col = column_obj.get("start") or item.get("column_number") or 0
        end_col = column_obj.get("end") or item.get("end_column_number") or 0

        rule_id = item.get("id") or item.get("rule_id") or "unknown"

        finding_id = build_finding_id("BEARER", rule_id, filename, line_number)

        details = {
            "rule_id": rule_id,
            "title": title,
            "code_extract": item.get("code_extract") or item.get("snippet"),
            "start": {"line": line_number, "column": start_col},
            "end": {"line": end_line, "column": end_col},
            "cwe_ids": normalize_cwe_list(item.get("cwe_ids") or item.get("cwe_id")),
            "category": item.get("category"),
            "category_groups": item.get("category_groups") or [],
            "documentation_url": item.get("documentation_url"),
            "references": item.get("references") or [],
            "full_description": desc,
            "fingerprint": item.get("fingerprint"),
            "old_fingerprint": item.get("old_fingerprint"),
        }

        aggregator.add_finding(
            Finding(
                id=finding_id,
                type=FindingType.SAST,
                severity=severity,
                component=filename,
                version=None,
                description=title,
                scanners=["bearer"],
                location={
                    "file": filename,
                    "start_line": line_number,
                    "end_line": end_line,
                    "start_column": start_col,
                    "end_column": end_col,
                },
                details=details,
            ),
            source=source,
        )
