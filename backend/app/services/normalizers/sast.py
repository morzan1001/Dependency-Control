from typing import Any, Dict, List, Optional, TYPE_CHECKING, Union
from app.models.finding import Finding, FindingType, Severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


import re


def _normalize_cwe_list(cwe: Optional[Union[str, List[str]]]) -> List[str]:
    """Normalize CWE references to a list of CWE IDs (just the numbers).
    
    Handles formats like:
    - "327" -> "327"
    - "CWE-327" -> "327"  
    - "CWE-327: Use of a Broken or Risky Cryptographic Algorithm" -> "327"
    """
    if not cwe:
        return []
    
    if isinstance(cwe, str):
        cwe_list = [cwe]
    else:
        cwe_list = cwe
    
    result = []
    # Regex to extract CWE number from various formats
    cwe_pattern = re.compile(r'(?:CWE-)?(\d+)', re.IGNORECASE)
    
    for item in cwe_list:
        if isinstance(item, str):
            match = cwe_pattern.search(item)
            if match:
                result.append(match.group(1))
    return result


def _normalize_list(value: Optional[Union[str, List[str]]]) -> List[str]:
    """Normalize a value that could be a string or list to always be a list."""
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_opengrep(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """Normalize OpenGrep (Semgrep) SAST results."""
    # OpenGrep JSON schema (from actual data):
    # {
    #   "findings": [
    #     {
    #       "check_id": "go.lang.security.audit.crypto...",
    #       "path": "repositories/email_repo.go",
    #       "start": { "line": 236, "col": 10, "offset": 6073 },
    #       "end": { "line": 239, "col": 3, "offset": 6136 },
    #       "extra": {
    #           "message": "...",
    #           "severity": "WARNING",
    #           "metadata": {
    #               "cwe": ["CWE-327: Use of a Broken..."],
    #               "owasp": ["A03:2017 - Sensitive Data Exposure", ...],
    #               "source-rule-url": "https://...",
    #               "references": [...],
    #               "category": "security",
    #               "technology": ["go"],
    #               "confidence": "HIGH",
    #               "subcategory": ["audit"],
    #               "likelihood": "MEDIUM",
    #               "impact": "LOW",
    #               "license": "...",
    #               "vulnerability_class": ["Cryptographic Issues"],
    #               "source": "https://semgrep.dev/r/...",
    #               "shortlink": "https://sg.run/..."
    #           }
    #       }
    #     }
    #   ]
    # }

    severity_map = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }

    # OpenGrep can send data as "findings" or "results"
    results = result.get("findings", []) or result.get("results", [])
    if not results:
        return

    for item in results:
        check_id = item.get("check_id", "unknown-check")
        path = item.get("path", "unknown")

        start_obj = item.get("start", {})
        end_obj = item.get("end", {})

        start_line = start_obj.get("line", 0)
        start_col = start_obj.get("col", 0)
        end_line = end_obj.get("line", 0)
        end_col = end_obj.get("col", 0)

        extra = item.get("extra", {})
        sev_str = extra.get("severity", "INFO").upper()
        severity = severity_map.get(sev_str, Severity.INFO)
        message = extra.get("message", "Potential issue found")

        # OpenGrep (semgrep) metadata
        metadata = extra.get("metadata", {})
        cwe = metadata.get("cwe", [])
        owasp = metadata.get("owasp", [])

        # Unique ID combining rule and location
        finding_id = f"OPENGREP-{check_id}-{path}-{start_line}"

        description = message
        # If check_id is meaningful (not generated), prefix it
        if "rules." in check_id or "." in check_id:
            short_rule_name = check_id.split(".")[-1]
            description = f"{short_rule_name}: {message}"

        # Build details with full SAST context
        # Include all available metadata for rich frontend display
        details = {
            "rule_id": check_id,
            "check_id": check_id,
            "title": message,
            "code_extract": extra.get("lines"),  # Snippet if available
            "start": {"line": start_line, "column": start_col},
            "end": {"line": end_line, "column": end_col},
            # CWE handling - normalize to array of IDs
            "cwe_ids": _normalize_cwe_list(cwe),
            "owasp": _normalize_list(owasp),
            # Risk assessment
            "impact": metadata.get("impact"),
            "confidence": metadata.get("confidence"),
            "likelihood": metadata.get("likelihood"),
            # Classification
            "category": metadata.get("category"),
            "category_groups": metadata.get("category_groups", []),
            "subcategory": _normalize_list(metadata.get("subcategory")),
            "technology": _normalize_list(metadata.get("technology")),
            "vulnerability_class": _normalize_list(metadata.get("vulnerability_class")),
            # Documentation
            "references": metadata.get("references", []),
            "source_rule_url": metadata.get("source-rule-url") or metadata.get("source_rule_url"),
            "source": metadata.get("source"),
            "shortlink": metadata.get("shortlink"),
            "license": metadata.get("license"),
            # Original extra for any fields we might have missed
            "fingerprint": extra.get("fingerprint"),
        }

        aggregator.add_finding(
            Finding(
                id=finding_id,
                type=FindingType.SAST,
                severity=severity,
                component=path,  # SAST findings are attached to files
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
            ),
            source=source,
        )


def normalize_bearer(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """Normalize Bearer SAST results."""
    # Bearer JSON format (from actual data):
    # {
    #   "findings": {
    #       "high": [
    #           {
    #               "cwe_ids": ["327"],
    #               "id": "go_lang_missing_tls_minversion",
    #               "title": "Missing TLS MinVersion",
    #               "description": "## Description\n...",
    #               "documentation_url": "https://docs.bearer.com/...",
    #               "line_number": 236,
    #               "full_filename": "repositories/email_repo.go",
    #               "filename": "repositories/email_repo.go",
    #               "category_groups": ["PII", "Personal Data"],
    #               "source": { "start": 236, "end": 239, "column": { "start": 10, "end": 3 } },
    #               "sink": { ... },
    #               "fingerprint": "853b3b31cb2af54cbc42abb2c2309443_0",
    #               "code_extract": "\treturn &tls.Config{..."
    #           }
    #       ],
    #       "low": [ ... ]
    #   }
    # }

    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "warning": Severity.LOW,
        "info": Severity.INFO,
    }

    findings_container = result.get("findings", {})

    # Bearer groups by severity key (high, low, medium, etc.)
    all_findings = []
    if isinstance(findings_container, list):
        # Flattened structure
        all_findings = findings_container
    elif isinstance(findings_container, dict):
        # Grouped by severity - also capture the severity from the key
        for sev_key, items in findings_container.items():
            if isinstance(items, list):
                for item in items:
                    # Add severity from the grouping key if not present in item
                    if "severity" not in item:
                        item["severity"] = sev_key.lower()
                    all_findings.append(item)

    for item in all_findings:
        title = item.get("title", "Unknown data risk")
        desc = item.get("description", "")
        sev_str = item.get("severity", "info").lower()
        severity = severity_map.get(sev_str, Severity.INFO)

        # Bearer uses full_filename or filename
        filename = item.get("full_filename") or item.get("filename") or item.get("file") or "unknown"
        
        # Line numbers from direct fields or source object
        source_obj = item.get("source", {})
        line_number = item.get("line_number") or source_obj.get("start") or 0
        end_line = source_obj.get("end") or item.get("end_line_number") or line_number
        
        # Column info from source.column object
        column_obj = source_obj.get("column", {})
        start_col = column_obj.get("start") or item.get("column_number") or 0
        end_col = column_obj.get("end") or item.get("end_column_number") or 0

        # Rule ID
        rule_id = item.get("id") or item.get("rule_id") or "unknown"

        finding_id = f"BEARER-{rule_id}-{filename}-{line_number}"

        # Build comprehensive details for rich frontend display
        details = {
            "rule_id": rule_id,
            "title": title,
            "code_extract": item.get("code_extract") or item.get("snippet"),
            "start": {"line": line_number, "column": start_col},
            "end": {"line": end_line, "column": end_col},
            # CWE handling - Bearer uses cwe_ids as array of strings
            "cwe_ids": _normalize_cwe_list(item.get("cwe_ids") or item.get("cwe_id")),
            # Classification
            "category": item.get("category"),
            "category_groups": item.get("category_groups", []),
            # Documentation
            "documentation_url": item.get("documentation_url"),
            "references": item.get("references", []),
            # Full description for remediation info (includes markdown)
            "full_description": desc,
            # Fingerprint
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
