import logging
from typing import TYPE_CHECKING, Any

from app.models.finding import Finding, FindingType
from app.schemas.bearer import BearerFinding, BearerSourceLocation, bearer_entries
from app.schemas.finding_details import LineSpan, SastScannerDetails
from app.services.normalizers.utils import (
    FindingIdPrefix,
    build_finding_id,
    normalize_cwe_list,
    normalize_list,
    safe_severity,
)

if TYPE_CHECKING:
    from app.services.aggregation import ResultAggregator

logger = logging.getLogger(__name__)

_CRYPTO_MISUSE_RULE_ID_PREFIX = "crypto-misuse-"
# Semgrep CE writes this into extra.fingerprint and extra.lines of every result when run without login.
_SEMGREP_LOGIN_PLACEHOLDER = "requires login"
# OpenGrep uses INFO for low-signal rules, not for informational notes.
_OPENGREP_OVERRIDES = {"INFO": "LOW"}
# Bearer ranks warning below low, unlike the global WARNING alias.
_BEARER_OVERRIDES = {"WARNING": "LOW"}


def _finding_type_from_rule(rule_id: Any) -> FindingType:
    """check_id may be a dotted path."""
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


def _parse_opengrep_item(item: dict[str, Any]) -> Finding:
    check_id = item.get("check_id") or "unknown-check"
    path = item.get("path") or "unknown"

    start_obj = item.get("start") or {}
    end_obj = item.get("end") or {}

    start_line = start_obj.get("line", 0)
    start_col = start_obj.get("col", 0)
    end_line = end_obj.get("line", 0)
    end_col = end_obj.get("col", 0)

    extra = {k: v for k, v in (item.get("extra") or {}).items() if v != _SEMGREP_LOGIN_PLACEHOLDER}
    sev_str = (extra.get("severity") or "INFO").upper()
    severity = safe_severity(_OPENGREP_OVERRIDES.get(sev_str, sev_str))
    message = extra.get("message") or "Potential issue found"

    metadata = extra.get("metadata") or {}
    cwe = metadata.get("cwe") or []
    owasp = metadata.get("owasp") or []

    finding_id = build_finding_id(FindingIdPrefix.OPENGREP, check_id, path, start_line)

    description = _build_opengrep_description(check_id, message)

    details = SastScannerDetails(
        rule_id=check_id,
        check_id=check_id,
        title=message,
        code_extract=extra.get("lines"),
        start=LineSpan(line=start_line, column=start_col),
        end=LineSpan(line=end_line, column=end_col),
        cwe_ids=normalize_cwe_list(cwe),
        owasp=normalize_list(owasp),
        impact=metadata.get("impact"),
        confidence=metadata.get("confidence"),
        likelihood=metadata.get("likelihood"),
        category=metadata.get("category"),
        category_groups=metadata.get("category_groups") or [],
        subcategory=normalize_list(metadata.get("subcategory")),
        technology=normalize_list(metadata.get("technology")),
        vulnerability_class=normalize_list(metadata.get("vulnerability_class")),
        references=normalize_list(metadata.get("references")),
        source_rule_url=metadata.get("source-rule-url") or metadata.get("source_rule_url"),
        source=metadata.get("source"),
        shortlink=metadata.get("shortlink"),
        license=metadata.get("license"),
        fingerprint=extra.get("fingerprint"),
    ).model_dump(exclude_none=True)

    return Finding(
        id=finding_id,
        type=_finding_type_from_rule(check_id),
        severity=severity,
        component=path,  # SAST findings attach to files, not packages
        version=None,
        description=description,
        scanners=["opengrep"],
        details=details,
    )


def normalize_opengrep(aggregator: "ResultAggregator", result: dict[str, Any], source: str | None = None) -> None:
    # OpenGrep emits either "findings" or "results" depending on version.
    for item in result.get("findings") or result.get("results") or []:
        try:
            finding = _parse_opengrep_item(item)
        except Exception as exc:
            logger.warning(
                "normalize_opengrep: dropping unparseable finding (%s) — check_id=%s, path=%s",
                exc,
                item.get("check_id"),
                item.get("path"),
            )
            continue
        aggregator.add_finding(finding, source=source)


def _parse_bearer_item(item: Any) -> Finding:
    entry = BearerFinding.model_validate(item)
    title = entry.title or "Unknown data risk"
    sev_str = (entry.severity or "info").upper()
    filename = entry.full_filename or entry.filename or "unknown"

    location = entry.source or BearerSourceLocation()
    line_number = entry.line_number or location.start or 0
    column = location.column or {}

    details = SastScannerDetails(
        rule_id=entry.id,
        title=title,
        code_extract=entry.code_extract or entry.snippet,
        start=LineSpan(line=line_number, column=column.get("start") or 0),
        end=LineSpan(line=location.end or line_number, column=column.get("end") or 0),
        cwe_ids=normalize_cwe_list(entry.cwe_ids),
        category_groups=entry.category_groups,
        documentation_url=entry.documentation_url,
    ).model_dump(exclude_none=True)

    return Finding(
        id=build_finding_id(FindingIdPrefix.BEARER, entry.id, filename, line_number),
        type=FindingType.SAST,
        severity=safe_severity(_BEARER_OVERRIDES.get(sev_str, sev_str)),
        component=filename,
        version=None,
        description=title,
        scanners=["bearer"],
        details=details,
    )


def normalize_bearer(aggregator: "ResultAggregator", result: dict[str, Any], source: str | None = None) -> None:
    for item in bearer_entries(result.get("findings")) or []:
        try:
            finding = _parse_bearer_item(item)
        except Exception as exc:
            logger.warning(
                "normalize_bearer: dropping unparseable finding (%s) — id=%s",
                exc,
                item.get("id") if isinstance(item, dict) else None,
            )
            continue
        aggregator.add_finding(finding, source=source)
