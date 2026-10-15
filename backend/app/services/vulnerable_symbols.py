"""Symbols come from structured scanner data only, never from heuristic text parsing."""

from typing import Any


def extract_symbols_from_vulnerability(vuln_data: dict[str, Any]) -> list[str]:
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
    vulnerabilities = finding.get("details", {}).get("vulnerabilities", [])
    return sorted({symbol for vuln in vulnerabilities for symbol in extract_symbols_from_vulnerability(vuln)})
