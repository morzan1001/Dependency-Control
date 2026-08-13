from typing import TYPE_CHECKING, Any

from app.core.constants import KICS_SEVERITY_MAP
from app.models.finding import Finding, FindingType
from app.schemas.finding_details import IacDetails, LineSpan
from app.services.normalizers.utils import (
    build_finding_id,
    normalize_cwe_list,
    safe_severity,
)

if TYPE_CHECKING:
    from app.services.aggregation import ResultAggregator


def _process_kics_file(
    aggregator: "ResultAggregator",
    f: dict[str, Any],
    query: dict[str, Any],
    severity: str,
    source: str | None,
) -> None:
    query_name = query.get("query_name") or "Unknown Issue"
    query_id = query.get("query_id") or "unknown"
    description = query.get("description") or ""
    platform = query.get("platform") or "unknown"
    category = query.get("category") or "infrastructure"

    file_name = f.get("file_name") or "unknown"
    line = f.get("line", 0)
    end_line = f.get("end_line") or line

    finding_id = build_finding_id("KICS", query_id, file_name, line)

    details = IacDetails(
        rule_id=query_id,
        title=query_name,
        start=LineSpan(line=line),
        end=LineSpan(line=end_line),
        category=category,
        platform=platform,
        actual_value=f.get("actual_value"),
        expected_value=f.get("expected_value"),
        search_key=f.get("search_key"),
        similarity_id=f.get("similarity_id"),
        code_extract=f.get("code_sample") or f.get("line_content"),
        cwe_ids=normalize_cwe_list(query.get("cwe")),
        documentation_url=query.get("description_url") or f.get("resource_url"),
        references=query.get("references") or [],
        full_description=description,
    ).model_dump(exclude_none=True)

    aggregator.add_finding(
        Finding(
            id=finding_id,
            type=FindingType.IAC,
            severity=severity,
            component=file_name,  # IaC findings attach to files, not packages
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


def normalize_kics(aggregator: "ResultAggregator", result: dict[str, Any], source: str | None = None) -> None:
    queries = result.get("queries") or []
    if not queries:
        return

    for query in queries:
        sev_str = (query.get("severity") or "INFO").upper()
        severity = safe_severity(KICS_SEVERITY_MAP.get(sev_str, sev_str))

        for f in query.get("files") or []:
            _process_kics_file(aggregator, f, query, severity, source)
