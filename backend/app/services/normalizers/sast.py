from typing import Any, Dict, TYPE_CHECKING
from app.models.finding import Finding, FindingType, Severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator

def normalize_opengrep(aggregator: "ResultAggregator", result: Dict[str, Any], source: str = None):
    """Normalize OpenGrep (Semgrep) SAST results."""
    # OpenGrep JSON schema:
    # {
    #   "results": [
    #     {
    #       "check_id": "rules.guardrails.python.sqli",
    #       "path": "app/main.py",
    #       "start": { "line": 10, "col": 5 },
    #       "end": { "line": 10, "col": 20 },
    #       "extra": {
    #           "severity": "ERROR",
    #           "message": "Potential SQL Injection",
    #           "metadata": { ... }
    #       }
    #     }
    #   ]
    # }

    severity_map = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }

    results = result.get("results", [])
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
        cwe = metadata.get("cwe")
        owasp = metadata.get("owasp")

        # Unique ID combining rule and location
        finding_id = f"OPENGREP-{check_id}-{path}-{start_line}"

        description = message
        # If check_id is meaningful (not generated), prefix it
        if "rules." in check_id or "." in check_id:
            short_rule_name = check_id.split(".")[-1]
            description = f"{short_rule_name}: {message}"

        # Build details with extra SAST context
        details = {
            "check_id": check_id,
            "lines": extra.get("lines"), # Snippet if available
            "cwe": cwe,
            "owasp": owasp,
            "impact": metadata.get("impact"),
            "confidence": metadata.get("confidence"),
            "references": metadata.get("references", []),
        }

        aggregator.add_finding(
            Finding(
                id=finding_id,
                type=FindingType.SAST,
                severity=severity,
                component=path, # SAST findings are attached to files
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

def normalize_bearer(aggregator: "ResultAggregator", result: Dict[str, Any], source: str = None):
    """Normalize Bearer SAST results."""
    # Bearer JSON format:
    # {
    #   "findings": {
    #       "HIGH": [
    #           {
    #               "title": "Unencrypted communication",
    #               "description": "...",
    #               "severity": "high",
    #               "filename": "app/main.py",
    #               "line_number": 42,
    #               "cwe_id": ["CWE-319"],
    #               ...
    #           }
    #       ]
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
    
    # Bearer groups usually by severity key, but let's iterate safely
    # It might be a flat list in some versions or grouped
    # Assuming grouped based on standard reports

    all_findings = []
    if isinstance(findings_container, list):
        # Flattened structure
        all_findings = findings_container
    elif isinstance(findings_container, dict):
        # Grouped by severity
        for sev_key, items in findings_container.items():
            if isinstance(items, list):
                all_findings.extend(items)

    for item in all_findings:
        title = item.get("title", "Unknown data risk")
        desc = item.get("description", "")
        sev_str = item.get("severity", "info").lower()
        severity = severity_map.get(sev_str, Severity.INFO)
        
        filename = item.get("filename") or item.get("file") or "unknown"
        line_number = item.get("line_number") or item.get("line") or 0
        
        # Rule ID or hash
        rule_id = item.get("rule_id") or item.get("id") or "unknown"

        finding_id = f"BEARER-{rule_id}-{filename}-{line_number}"

        aggregator.add_finding(
            Finding(
                id=finding_id,
                type=FindingType.SAST,
                severity=severity,
                component=filename,
                version=None,
                description=f"{title}",
                scanners=["bearer"],
                location={
                    "file": filename,
                    "start_line": line_number,
                    "end_line": line_number,
                },
                details={
                    "full_description": desc,
                    "cwe_id": item.get("cwe_id"),
                    "rule_id": rule_id,
                    "snippet": item.get("snippet"),
                },
            ),
            source=source,
        )
