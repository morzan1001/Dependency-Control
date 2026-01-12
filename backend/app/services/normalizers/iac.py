from typing import Any, Dict, Optional, TYPE_CHECKING
from app.models.finding import Finding, FindingType, Severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_kics(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """Normalize KICS IaC scan results."""
    # KICS JSON schema:
    # {
    #   "queries": [
    #      {
    #          "query_name": "...",
    #          "query_id": "...",
    #          "severity": "HIGH",
    #          "description": "...",
    #          "files": [
    #               {
    #                   "file_name": "...",
    #                   "line": 10,
    #                   ...
    #               }
    #          ]
    #      }
    #   ]
    # }

    severity_map = {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "TRACE": Severity.INFO,
    }

    queries = result.get("queries", [])
    if not queries:
        return

    for query in queries:
        query_name = query.get("query_name", "Unknown Issue")
        query_id = query.get("query_id")
        sev_str = query.get("severity", "INFO").upper()
        severity = severity_map.get(sev_str, Severity.INFO)
        description = query.get("description", "")
        platform = query.get("platform", "unknown")
        category = query.get("category", "infrastructure")

        for f in query.get("files", []):
            file_name = f.get("file_name", "unknown")
            line = f.get("line", 0)

            # Unique ID per file location
            finding_id = f"KICS-{query_id}-{file_name}-{line}"

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
                        "end_line": line,  # KICS typically provides just start line
                    },
                    details={
                        "query_id": query_id,
                        "category": category,
                        "platform": platform,
                        "actual_value": f.get("actual_value"),
                        "expected_value": f.get("expected_value"),
                        "search_key": f.get("search_key"),
                    },
                ),
                source=source,
            )
