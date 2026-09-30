"""Extract vulnerable function/symbol names from structured scanner data (e.g. OSV ecosystem_specific), not heuristic text parsing."""

from typing import Any


def extract_symbols_from_vulnerability(vuln_data: dict[str, Any]) -> list[str]:
    """The symbols a vulnerability entry names in its OSV ecosystem_specific payload."""
    eco = vuln_data.get("ecosystem_specific")
    if not isinstance(eco, dict):
        return []
    symbols, imports = eco.get("symbols"), eco.get("imports")
    if isinstance(symbols, list):
        return symbols
    if isinstance(imports, list):
        return [symbol for imp in imports if isinstance(imp, dict) for symbol in imp.get("symbols", [])]
    return []


def get_symbols_for_finding(finding: dict[str, Any]) -> list[str]:
    """The sorted union of the symbols every entry of a finding's details.vulnerabilities names."""
    vulnerabilities = finding.get("details", {}).get("vulnerabilities", [])
    return sorted({symbol for vuln in vulnerabilities for symbol in extract_symbols_from_vulnerability(vuln)})
