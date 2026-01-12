"""
Vulnerable Symbols Extraction

Extracts vulnerable function/symbol names from structured vulnerability data.
Relys on authoritative data from scanners (e.g. OSV ecosystem_specific fields)
rather than heuristic text parsing.
"""

import logging
from typing import Dict, List, Set

from app.schemas.enrichment import ExtractedSymbols

logger = logging.getLogger(__name__)


def extract_symbols_from_vulnerability(vuln_data: Dict) -> ExtractedSymbols:
    """
    Extract symbols from a vulnerability object (from scanner results).

    Uses structured data from:
    - OSV 'ecosystem_specific'
    - 'affected_symbols' fields
    - Other known structured locations

    Args:
        vuln_data: Vulnerability dict from trivy/grype/osv scanner

    Returns:
        ExtractedSymbols with found symbols
    """
    cve = vuln_data.get("id", "") or vuln_data.get("cve", "")
    package = vuln_data.get("package", "") or vuln_data.get("component", "")

    # 1. Check OSV-style ecosystem_specific.imports or symbols
    if "ecosystem_specific" in vuln_data:
        eco = vuln_data["ecosystem_specific"]
        if isinstance(eco, dict):
            # Generalized OSV symbols
            if "symbols" in eco and isinstance(eco["symbols"], list):
                return ExtractedSymbols(
                    cve=cve,
                    package=package,
                    symbols=eco["symbols"],
                    confidence="high",
                    extraction_method="osv_ecosystem",
                )
            
            # Go specific OSV
            if "imports" in eco and isinstance(eco["imports"], list):
                symbols = []
                for imp in eco["imports"]:
                    if isinstance(imp, dict) and "symbols" in imp:
                        symbols.extend(imp["symbols"])
                if symbols:
                    return ExtractedSymbols(
                        cve=cve,
                        package=package,
                        symbols=symbols,
                        confidence="high",
                        extraction_method="osv_go_imports",
                    )

    # 2. Check for 'affected_symbols' (common in some internal formats)
    if "affected_symbols" in vuln_data and isinstance(
        vuln_data["affected_symbols"], list
    ):
        return ExtractedSymbols(
            cve=cve,
            package=package,
            symbols=vuln_data["affected_symbols"],
            confidence="high",
            extraction_method="scanner_provided",
        )

    # No symbols found in structured data
    return ExtractedSymbols(cve=cve, package=package)


def get_symbols_for_finding(finding: Dict) -> ExtractedSymbols:
    """
    Extract vulnerable symbols for a finding from our scanner results.

    Looks at the finding's details.vulnerabilities array and extracts
    symbols from each vulnerability's description.

    Args:
        finding: Finding dict with details.vulnerabilities

    Returns:
        Combined ExtractedSymbols from all vulnerabilities
    """
    component = finding.get("component", "")

    all_symbols: Set[str] = set()
    all_cves: List[str] = []
    best_confidence = "low"
    extraction_method = "none"

    # Get vulnerabilities from the finding
    details = finding.get("details", {})
    vulnerabilities = details.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", "")
        if vuln_id:
            all_cves.append(vuln_id)

        # Extract symbols from this vulnerability
        extracted = extract_symbols_from_vulnerability(vuln)

        if extracted.symbols:
            all_symbols.update(extracted.symbols)

            # Track best confidence
            if extracted.confidence == "high":
                best_confidence = "high"
            elif extracted.confidence == "medium" and best_confidence == "low":
                best_confidence = "medium"

            if extracted.extraction_method != "none":
                extraction_method = extracted.extraction_method

    return ExtractedSymbols(
        cve=",".join(all_cves) if all_cves else "",
        package=component,
        symbols=list(all_symbols),
        confidence=best_confidence,
        extraction_method=extraction_method,
    )
