from typing import Any, Dict, Optional, TYPE_CHECKING

from app.core.constants import KICS_SEVERITY_MAP
from app.models.finding import Finding, FindingType
from app.services.normalizers.utils import (
    build_finding_id,
    normalize_cwe_list,
    safe_severity,
)

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_kics(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """Normalize KICS IaC scan results."""
    queries = result.get("queries") or []
    if not queries:
        return

    for query in queries:
        query_name = query.get("query_name") or "Unknown Issue"
        query_id = query.get("query_id") or "unknown"
        sev_str = (query.get("severity") or "INFO").upper()
        severity = safe_severity(KICS_SEVERITY_MAP.get(sev_str, sev_str))
        description = query.get("description") or ""
        platform = query.get("platform") or "unknown"
        category = query.get("category") or "infrastructure"

        for f in query.get("files") or []:
            file_name = f.get("file_name") or "unknown"
            line = f.get("line", 0)
            end_line = f.get("end_line") or line

            # Unique ID per file location
            finding_id = build_finding_id("KICS", query_id, file_name, line)

            # Build comprehensive details
            details = {
                "rule_id": query_id,
                "title": query_name,
                "start": {"line": line},
                "end": {"line": end_line},
                # Classification
                "category": category,
                "platform": platform,
                # KICS-specific: expected vs actual values
                "actual_value": f.get("actual_value"),
                "expected_value": f.get("expected_value"),
                "search_key": f.get("search_key"),
                # Code context
                "code_extract": f.get("code_sample") or f.get("line_content"),
                # CWE if available
                "cwe_ids": normalize_cwe_list(query.get("cwe")),
                # Documentation
                "documentation_url": query.get("description_url")
                or f.get("resource_url"),
                "references": query.get("references") or [],
                # Remediation
                "full_description": description,
            }

            aggregator.add_finding(
                Finding(
                    id=finding_id,
                    type=FindingType.IAC,
                    severity=severity,
                    component=file_name,  # IaC findings are attached to files, not packages
                    version=None,
                    description=f"{query_name}: {description}",
                    scanners=["kics"],
                    location={
                        "file": file_name,
                        "start_line": line,
                        "end_line": end_line,
                    },
                    details=details,
                ),
                source=source,
            )
