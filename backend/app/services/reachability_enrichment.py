"""
Reachability Enrichment Service

Analyzes whether vulnerable code paths are actually reachable
in a project based on call graph data.

Two-level approach:
1. Import-based: Is the vulnerable package imported? (reliable)
2. Symbol-based: Are vulnerable functions used? (heuristic, extracted from CVE descriptions)

This service enriches vulnerability findings with reachability
information, helping teams prioritize truly exploitable issues.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.constants import sort_by_severity
from app.services.vulnerable_symbols import (ExtractedSymbols,
                                             get_symbols_for_finding)

logger = logging.getLogger(__name__)


async def enrich_findings_with_reachability(
    findings: List[Dict[str, Any]],
    project_id: str,
    db,
    scan_id: Optional[str] = None,
) -> int:
    """
    Enrich vulnerability findings with reachability analysis.

    Args:
        findings: List of finding dicts (will be modified in-place)
        project_id: Project ID to fetch callgraph for
        db: Database connection
        scan_id: Scan ID to find the matching callgraph (preferred)

    Returns:
        Number of findings enriched
    """
    if not findings:
        return 0

    # Determine scan_id from findings if not provided
    if not scan_id and findings:
        scan_id = findings[0].get("scan_id")

    if not scan_id:
        logger.warning("No scan_id available for reachability enrichment")
        return 0

    # Fetch callgraph linked to this scan
    # Priority: exact scan_id match > fallback to pipeline_id match
    callgraph = await db.callgraphs.find_one(
        {"project_id": project_id, "scan_id": scan_id}
    )

    if not callgraph:
        # Fallback: try to find callgraph via pipeline_id
        scan = await db.scans.find_one({"_id": scan_id})
        if scan and scan.get("pipeline_id"):
            callgraph = await db.callgraphs.find_one(
                {"project_id": project_id, "pipeline_id": scan["pipeline_id"]}
            )

    if not callgraph:
        logger.debug(f"No callgraph available for scan {scan_id}")
        return 0

    logger.debug(f"Found callgraph for scan {scan_id}")

    # Extract module usage from callgraph
    module_usage = callgraph.get("module_usage", {})
    import_map = callgraph.get("import_map", {})
    language = callgraph.get("language", "unknown")

    enriched_count = 0

    for finding in findings:
        if finding.get("type") != "vulnerability":
            continue

        component = finding.get("component", "")
        if not component:
            continue

        # Analyze reachability
        reachability = _analyze_reachability(
            finding=finding,
            component=component,
            module_usage=module_usage,
            import_map=import_map,
            language=language,
        )

        # Add to finding details
        if "details" not in finding:
            finding["details"] = {}
        finding["details"]["reachability"] = reachability
        enriched_count += 1

    return enriched_count


def _analyze_reachability(
    finding: Dict[str, Any],
    component: str,
    module_usage: Dict[str, Any],
    import_map: Dict[str, List[str]],
    language: str,
) -> Dict[str, Any]:
    """
    Analyze reachability for a single finding.

    Two-level analysis:
    1. Import-based: Is the package imported anywhere?
    2. Symbol-based: Are vulnerable functions (extracted from CVE text) used?
    """
    result = {
        "is_reachable": False,
        "confidence_score": 0.0,
        "analysis_level": "none",
        "matched_symbols": [],
        "import_locations": [],
        "message": "",
    }

    # Normalize component name for lookup
    normalized = _normalize_component(component, language)

    usage = module_usage.get(normalized) or module_usage.get(component)

    # Also check import_map for package presence
    package_in_imports = _check_package_in_imports(normalized, import_map, language)

    if not usage and not package_in_imports:
        # Package not found in imports - not reachable
        result["is_reachable"] = False
        result["confidence_score"] = 0.9  # High confidence it's NOT used
        result["analysis_level"] = "import"
        result["message"] = (
            f"Package '{component}' is not imported in any analyzed source file."
        )
        return result

    # Package is imported - collect import locations
    import_locations = []
    if usage:
        import_locations = usage.get("import_locations", [])[:10]  # Limit to 10
    elif package_in_imports:
        import_locations = package_in_imports[:10]

    result["import_locations"] = import_locations
    import_count = len(import_locations)

    # Extract vulnerable symbols from CVE descriptions
    extracted = get_symbols_for_finding(finding)

    if not extracted.symbols:
        # No symbols extracted - can only confirm import-level reachability
        result["is_reachable"] = True
        result["confidence_score"] = (
            0.5  # Medium - package is imported but unknown functions
        )
        result["analysis_level"] = "import"
        result["message"] = (
            f"Package is imported in {import_count} file(s). Could not determine specific vulnerable functions."
        )
        return result

    # We have extracted symbols - check if they're used
    used_symbols = usage.get("used_symbols", []) if usage else []

    # Match extracted vulnerable symbols against used symbols
    matched_symbols = _match_symbols(extracted.symbols, used_symbols)

    if matched_symbols:
        # Vulnerable functions ARE used
        result["is_reachable"] = True
        result["confidence_score"] = _calculate_confidence(
            extracted.confidence, "matched"
        )
        result["analysis_level"] = "symbol"
        result["matched_symbols"] = matched_symbols
        result["message"] = (
            f"Vulnerable function(s) {', '.join(matched_symbols[:5])} are used in the codebase."
        )
    elif used_symbols:
        # Package is used but not the vulnerable functions (potentially)
        result["is_reachable"] = True  # Still mark as reachable but lower confidence
        result["confidence_score"] = _calculate_confidence(
            extracted.confidence, "partial"
        )
        result["analysis_level"] = "symbol"
        result["message"] = (
            f"Package is imported but extracted vulnerable functions "
            f"({', '.join(extracted.symbols[:3])}) were not found in direct usage. "
            f"May still be reachable through indirect calls."
        )
    else:
        # Package imported but no symbol usage info
        result["is_reachable"] = True
        result["confidence_score"] = 0.4
        result["analysis_level"] = "import"
        result["message"] = (
            f"Package is imported in {import_count} file(s). Symbol-level analysis not available."
        )

    # Add extraction metadata
    result["extraction_method"] = extracted.extraction_method
    result["extraction_confidence"] = extracted.confidence
    result["vulnerable_symbols"] = extracted.symbols[:10]  # Limit

    return result


def _normalize_component(component: str, language: str) -> str:
    """
    Normalize component name for matching with callgraph data.
    """
    if not component:
        return component

    # Remove version suffix if present (npm style: package@1.0.0)
    if "@" in component and not component.startswith("@"):
        component = component.rsplit("@", 1)[0]

    # Handle scoped packages (@scope/package)
    if component.startswith("@"):
        parts = component.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"

    # For Python, normalize underscores/hyphens
    if language == "python":
        return component.lower().replace("-", "_").replace(".", "_")

    # For JavaScript/TypeScript
    if language in ("javascript", "typescript"):
        return component.lower()

    # For Go, keep full path
    if language == "go":
        return component

    return component.lower()


def _check_package_in_imports(
    package: str, import_map: Dict[str, List[str]], language: str
) -> List[str]:
    """
    Check if a package appears anywhere in the import map.
    Returns list of files that import it.
    """
    files_importing = []
    package_lower = package.lower()

    for file_path, imports in import_map.items():
        for imp in imports:
            imp_lower = imp.lower()

            # Direct match
            if package_lower == imp_lower:
                files_importing.append(file_path)
                break

            # Partial match (e.g., "lodash" in "lodash/merge")
            if package_lower in imp_lower or imp_lower.startswith(package_lower + "/"):
                files_importing.append(file_path)
                break

            # For Python: handle from X import Y
            if imp_lower.startswith(package_lower + "."):
                files_importing.append(file_path)
                break

    return files_importing


def _match_symbols(vulnerable_symbols: List[str], used_symbols: List[str]) -> List[str]:
    """
    Match vulnerable symbols against used symbols.
    Returns list of matched symbols.
    """
    if not vulnerable_symbols or not used_symbols:
        return []

    matched = []
    vuln_lower = {s.lower() for s in vulnerable_symbols}

    for used in used_symbols:
        used_lower = used.lower()

        # Direct match
        if used_lower in vuln_lower:
            matched.append(used)
            continue

        # Check if used symbol contains vulnerable symbol (method chaining)
        # e.g., "_.template" contains "template"
        for vuln in vulnerable_symbols:
            vuln_l = vuln.lower()
            if vuln_l in used_lower or used_lower.endswith("." + vuln_l):
                matched.append(used)
                break

    return matched


def _calculate_confidence(extraction_confidence: str, match_type: str) -> float:
    """
    Calculate overall confidence score.

    Factors:
    - extraction_confidence: How reliable is the symbol extraction (low/medium/high)
    - match_type: "matched" (direct match), "partial" (imported but not matched)
    """
    base_scores = {
        "high": 0.9,
        "medium": 0.7,
        "low": 0.5,
    }

    extraction_score = base_scores.get(extraction_confidence, 0.5)

    if match_type == "matched":
        # Direct match - high confidence
        return min(extraction_score + 0.1, 1.0)
    elif match_type == "partial":
        # Partial - lower confidence
        return extraction_score * 0.7
    else:
        return extraction_score * 0.5


async def run_pending_reachability_for_scan(
    scan_id: str,
    project_id: str,
    db,
) -> dict:
    """
    Run pending reachability analysis for a specific scan.

    This is called after a callgraph is uploaded and linked to a scan.
    Simple and direct - no complex matching logic needed since we have the scan_id.

    Args:
        scan_id: The scan ID to process
        project_id: Project ID for the scan
        db: Database connection

    Returns:
        Dict with results: {"findings_enriched": int, "error": str or None}
    """
    result = {
        "findings_enriched": 0,
        "error": None,
    }

    # Check if this scan has pending reachability
    scan = await db.scans.find_one({"_id": scan_id})
    if not scan:
        logger.debug(f"Scan {scan_id} not found")
        return result

    if not scan.get("reachability_pending"):
        logger.debug(f"Scan {scan_id} has no pending reachability analysis")
        return result

    try:
        # Fetch vulnerability findings for this scan
        findings = await db.findings.find(
            {
                "scan_id": scan_id,
                "type": "vulnerability",
            }
        ).to_list(None)

        if not findings:
            logger.debug(f"No vulnerability findings for scan {scan_id}")
            # Clear pending status even if no findings
            await db.scans.update_one(
                {"_id": scan_id},
                {
                    "$unset": {
                        "reachability_pending": "",
                        "reachability_pending_since": "",
                    }
                },
            )
            return result

        # Convert to dicts for enrichment
        findings_dicts = [dict(f) for f in findings]

        # Run reachability enrichment - callgraph lookup uses scan_id
        enriched_count = await enrich_findings_with_reachability(
            findings=findings_dicts,
            project_id=project_id,
            db=db,
            scan_id=scan_id,
        )

        # Update findings in database with reachability data
        for finding_dict in findings_dicts:
            if finding_dict.get("reachable") is not None:
                await db.findings.update_one(
                    {"_id": finding_dict["_id"]},
                    {
                        "$set": {
                            "reachable": finding_dict.get("reachable"),
                            "reachability_level": finding_dict.get(
                                "reachability_level"
                            ),
                            "reachable_functions": finding_dict.get(
                                "reachable_functions", []
                            ),
                        }
                    },
                )

        # Store reachability summary in analysis_results for raw data view
        callgraph = await db.callgraphs.find_one(
            {"project_id": project_id, "scan_id": scan_id}
        )
        if callgraph:
            reachability_summary = _build_reachability_summary_for_pending(
                findings_dicts, callgraph, enriched_count
            )
            await db.analysis_results.insert_one(
                {
                    "_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "analyzer_name": "reachability",
                    "result": reachability_summary,
                    "created_at": datetime.now(timezone.utc),
                }
            )

        # Clear pending status
        await db.scans.update_one(
            {"_id": scan_id},
            {
                "$unset": {
                    "reachability_pending": "",
                    "reachability_pending_since": "",
                },
                "$set": {"reachability_completed_at": datetime.now(timezone.utc)},
            },
        )

        result["findings_enriched"] = enriched_count
        logger.info(
            f"[reachability] Processed scan {scan_id}: enriched {enriched_count} findings"
        )

    except Exception as e:
        result["error"] = str(e)
        logger.error(f"[reachability] Failed to process scan {scan_id}: {e}")

    return result


def _build_reachability_summary_for_pending(
    findings: List[Dict[str, Any]], callgraph: Dict[str, Any], enriched_count: int
) -> Dict[str, Any]:
    """
    Build a summary of reachability analysis for raw data view.
    Used when processing pending reachability after callgraph upload.
    """
    summary: Dict[str, Any] = {
        "total_vulnerabilities": len(findings),
        "analyzed": enriched_count,
        "reachability_levels": {
            "confirmed": 0,
            "likely": 0,
            "unknown": 0,
            "unreachable": 0,
        },
        "callgraph_info": {
            "language": callgraph.get("language", "unknown"),
            "total_modules": len(callgraph.get("module_usage", {})),
            "total_imports": len(callgraph.get("import_map", {})),
            "generated_at": (
                callgraph.get("created_at", "").isoformat()
                if hasattr(callgraph.get("created_at", ""), "isoformat")
                else str(callgraph.get("created_at", ""))
            ),
        },
        "reachable_vulnerabilities": [],
        "unreachable_vulnerabilities": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    for finding in findings:
        reachable = finding.get("reachable")
        reachability_level = finding.get("reachability_level", "unknown")

        vuln_info = {
            "cve": finding.get("finding_id") or finding.get("id", ""),
            "component": finding.get("component", ""),
            "version": finding.get("version", ""),
            "severity": finding.get("severity", "unknown"),
            "reachability_level": reachability_level,
            "reachable_functions": finding.get("reachable_functions", [])[:5],
        }

        if reachability_level in summary["reachability_levels"]:
            summary["reachability_levels"][reachability_level] += 1

        if reachable is True:
            summary["reachable_vulnerabilities"].append(vuln_info)
        elif reachable is False:
            summary["unreachable_vulnerabilities"].append(vuln_info)

    # Sort by severity (most severe first)
    summary["reachable_vulnerabilities"] = sort_by_severity(
        summary["reachable_vulnerabilities"], key="severity", reverse=True
    )
    summary["unreachable_vulnerabilities"] = sort_by_severity(
        summary["unreachable_vulnerabilities"], key="severity", reverse=True
    )

    # Limit lists
    summary["reachable_vulnerabilities"] = summary["reachable_vulnerabilities"][:30]
    summary["unreachable_vulnerabilities"] = summary["unreachable_vulnerabilities"][:30]

    return summary
