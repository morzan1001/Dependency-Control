"""Extract vulnerable function/symbol names from structured scanner data (e.g. OSV ecosystem_specific), not heuristic text parsing."""

from typing import Any, Dict, List, Set

from app.schemas.enrichment import ExtractedSymbols


def extract_symbols_from_vulnerability(vuln_data: Dict[str, Any]) -> ExtractedSymbols:
    """Extract symbols from a scanner vulnerability dict via OSV ecosystem_specific / affected_symbols."""
    cve = vuln_data.get("id", "") or vuln_data.get("cve", "")
    package = vuln_data.get("package", "") or vuln_data.get("component", "")

    if "ecosystem_specific" in vuln_data:
        eco = vuln_data["ecosystem_specific"]
        if isinstance(eco, dict):
            if "symbols" in eco and isinstance(eco["symbols"], list):
                return ExtractedSymbols(
                    cve=cve,
                    package=package,
                    symbols=eco["symbols"],
                    confidence="high",
                    extraction_method="osv_ecosystem",
                )

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

    if "affected_symbols" in vuln_data and isinstance(vuln_data["affected_symbols"], list):
        return ExtractedSymbols(
            cve=cve,
            package=package,
            symbols=vuln_data["affected_symbols"],
            confidence="high",
            extraction_method="scanner_provided",
        )

    return ExtractedSymbols(cve=cve, package=package)


def get_symbols_for_finding(finding: Dict[str, Any]) -> ExtractedSymbols:
    """Combine ExtractedSymbols across all vulnerabilities in a finding's details.vulnerabilities."""
    component = finding.get("component", "")

    all_symbols: Set[str] = set()
    all_cves: List[str] = []
    best_confidence = "low"
    extraction_method = "none"

    details = finding.get("details", {})
    vulnerabilities = details.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", "")
        if vuln_id:
            all_cves.append(vuln_id)

        extracted = extract_symbols_from_vulnerability(vuln)

        if extracted.symbols:
            all_symbols.update(extracted.symbols)

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
