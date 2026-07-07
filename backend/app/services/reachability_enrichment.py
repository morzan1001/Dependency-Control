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
from typing import Any, Dict, List, Mapping, Optional, TypedDict

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import UpdateOne

from app.core.constants import (
    REACHABILITY_CONFIDENCE_IMPORTED_NO_SYMBOLS,
    REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO,
    REACHABILITY_CONFIDENCE_NOT_USED,
    REACHABILITY_EXTRACTION_CONFIDENCE,
    REACHABILITY_HIGH_CONFIDENCE_THRESHOLD,
    REACHABILITY_LEVEL_IMPORT,
    REACHABILITY_LEVEL_NONE,
    REACHABILITY_LEVEL_SYMBOL,
)
from app.services.analyzers.purl_utils import get_purl_type
from app.services.enrichment.scoring import (
    calculate_adjusted_risk_score,
    map_reachability_level_to_modifier,
)
from app.services.vulnerable_symbols import get_symbols_for_finding

logger = logging.getLogger(__name__)

# Findings-per-round-trip cap for the bulk reachability persist. Mirrors the
# analysis engine's dependency bulk-update chunking so a large scan doesn't hold
# the callgraph-upload request open for thousands of serial Mongo updates.
_BULK_CHUNK_SIZE = 500

# Ecosystem identifier (a dependency's `type`, e.g. "pypi"/"npm"/"go-module", OR a
# purl type) -> the callgraph language(s) that can actually analyze it. Anything
# else (maven, cargo, nuget, rpm, deb, ...) has no callgraph support, so a missing
# package in those ecosystems is never treated as unreachable.
_ECOSYSTEM_TO_CALLGRAPH_LANGUAGES: Dict[str, frozenset] = {
    "pypi": frozenset({"python"}),
    "python": frozenset({"python"}),
    "npm": frozenset({"javascript", "typescript"}),
    "go": frozenset({"go"}),
    "golang": frozenset({"go"}),
    "go-module": frozenset({"go"}),
}


def _ecosystem_languages(ecosystem: Optional[str], purl: Optional[str]) -> frozenset:
    """Callgraph language(s) that can analyze a package, derived from its
    dependency ecosystem/type or (fallback) its purl. Empty when undeterminable
    or unsupported."""
    if ecosystem:
        langs = _ECOSYSTEM_TO_CALLGRAPH_LANGUAGES.get(ecosystem.lower())
        if langs:
            return langs
    if purl:
        purl_type = get_purl_type(purl)
        if purl_type:
            return _ECOSYSTEM_TO_CALLGRAPH_LANGUAGES.get(purl_type, frozenset())
    return frozenset()


async def _build_component_language_map(db: AsyncIOMotorDatabase, scan_id: str) -> Dict[str, frozenset]:
    """Map component name -> callgraph language(s) that could analyze it, derived
    from the scan's dependencies (their ``type``/``purl``).

    This is the reliable ecosystem signal: vulnerability findings themselves do
    NOT carry a purl (the OSV/Trivy/Grype normalizers don't persist one), so the
    fail-closed gate must look the package up in the dependency inventory instead.
    """
    out: Dict[str, frozenset] = {}
    cursor = db.dependencies.find({"scan_id": scan_id}, {"name": 1, "type": 1, "purl": 1})
    async for dep in cursor:
        name = dep.get("name")
        if not name:
            continue
        langs = _ecosystem_languages(dep.get("type"), dep.get("purl"))
        if langs:
            out[name] = out.get(name, frozenset()) | langs
    return out


def _callgraphs_cover_finding_ecosystem(
    finding: Dict[str, Any],
    callgraph_languages: List[str],
    component_languages: Optional[Dict[str, frozenset]] = None,
) -> bool:
    """True only when an analyzed callgraph's language can cover this finding's
    package ecosystem.

    Gates the x0.4 ``unreachable`` down-weight: absence from a wrong-language or
    unsupported callgraph (or when the ecosystem is unknown) is not evidence of
    unreachability and must be treated as unknown, not a definitive verdict. The
    ecosystem comes from the scan's dependency inventory (``component_languages``);
    a purl on the finding itself is only a rare fallback.
    """
    component = finding.get("component", "")
    langs: frozenset = frozenset()
    if component_languages and component in component_languages:
        langs = component_languages[component]
    if not langs:
        purl = (finding.get("details") or {}).get("purl")
        langs = _ecosystem_languages(None, purl)
    if not langs:
        return False
    return any(lang in langs for lang in callgraph_languages)


def _apply_adjusted_risk_score(finding: Dict[str, Any], reachability: Mapping[str, Any]) -> None:
    """Persist a reachability-adjusted risk score on the finding (W5 / Finding 13).

    Takes the per-finding base composite ``details.risk_score`` and applies the
    reachability modifier, mapping the enrichment vocabulary
    (``none``/``import``/``symbol`` + ``is_reachable``) onto the modifier
    vocabulary (``confirmed``/``unreachable``/identity). Only a symbol-level
    reachable hit boosts (x1.1); a not-reachable verdict de-prioritises (x0.4);
    everything weaker is identity. No base risk_score -> nothing to adjust.
    """
    details = finding.setdefault("details", {})
    base = details.get("risk_score")
    if base is None:
        return
    modifier_level = map_reachability_level_to_modifier(
        reachability.get("analysis_level"),
        reachability.get("is_reachable"),
    )
    details["adjusted_risk_score"] = round(
        calculate_adjusted_risk_score(
            float(base),
            is_reachable=reachability.get("is_reachable"),
            reachability_level=modifier_level,
        ),
        1,
    )


def is_high_confidence_reachable(reachability_data: Optional[Dict[str, Any]]) -> bool:
    """True only when ``is_reachable=True`` *and* confidence clears the threshold.

    Use this for any user-facing count that drives prioritisation. The
    raw boolean alone collapses two very different signals (matched
    symbol vs. "package was imported, rest is heuristic") into one bit;
    this gate keeps the noisy lower tier out of headline metrics.
    """
    if not reachability_data:
        return False
    if reachability_data.get("is_reachable") is not True:
        return False
    confidence = reachability_data.get("confidence_score")
    if confidence is None:
        return False
    return bool(confidence >= REACHABILITY_HIGH_CONFIDENCE_THRESHOLD)


def reachability_display_tier(is_reachable: Optional[bool], analysis_level: Optional[str]) -> str:
    """Map persisted reachability (is_reachable + analysis_level in
    none/import/symbol) onto the display vocabulary confirmed/likely/unreachable/
    unknown. Shared by the comprehensive-stats summary and the persisted pending
    summary so the two cannot drift (audit MF6)."""
    if is_reachable is False:
        return "unreachable"
    if is_reachable is True:
        if analysis_level == REACHABILITY_LEVEL_SYMBOL:
            return "confirmed"
        if analysis_level == REACHABILITY_LEVEL_IMPORT:
            return "likely"
    return "unknown"


class ReachabilityResult(TypedDict, total=False):
    """Result of reachability analysis for a finding."""

    is_reachable: bool
    confidence_score: float
    analysis_level: str
    matched_symbols: List[str]
    import_locations: List[str]
    message: str
    extraction_method: str
    extraction_confidence: str
    vulnerable_symbols: List[str]


async def _fetch_callgraphs(
    project_id: str,
    scan_id: str,
    db: AsyncIOMotorDatabase,
) -> List[Any]:
    """
    Fetch all callgraphs for a scan (one per language), falling back to pipeline_id match.

    Returns a list of callgraph objects (may be empty).
    """
    from app.repositories import CallgraphRepository, ScanRepository

    callgraph_repo = CallgraphRepository(db)
    scan_repo = ScanRepository(db)

    # Priority: exact scan_id match > fallback to pipeline_id match
    callgraphs = await callgraph_repo.find_all_minimal_by_scan(project_id, scan_id)
    if callgraphs:
        return callgraphs

    # Fallback: try to find callgraphs via pipeline_id
    scan = await scan_repo.get_by_id(scan_id)
    if scan and scan.pipeline_id:
        return await callgraph_repo.find_all_minimal_by_pipeline(project_id, scan.pipeline_id)

    return []


def _enrich_single_finding(
    finding: Dict[str, Any],
    module_usage: Dict[str, Any],
    import_map: Dict[str, List[str]],
    language: str,
) -> bool:
    """
    Enrich a single finding with reachability data. Returns True if enriched.
    """
    if finding.get("type") != "vulnerability":
        return False

    component = finding.get("component", "")
    if not component:
        return False

    reachability = _analyze_reachability(
        finding=finding,
        component=component,
        module_usage=module_usage,
        import_map=import_map,
        language=language,
    )

    if "details" not in finding:
        finding["details"] = {}
    finding["details"]["reachability"] = reachability
    _apply_adjusted_risk_score(finding, reachability)
    return True


def _is_package_in_callgraph(
    component: str,
    module_usage: Dict[str, Any],
    import_map: Dict[str, List[str]],
    language: str,
) -> bool:
    """Check whether a package appears in a callgraph's module usage or imports."""
    normalized = _normalize_component(component, language)
    usage = module_usage.get(normalized) or module_usage.get(component)
    return bool(usage or _check_package_in_imports(normalized, import_map))


def _enrich_finding_from_callgraphs(
    finding: Dict[str, Any],
    callgraphs: List[Any],
    component_languages: Optional[Dict[str, frozenset]] = None,
) -> bool:
    """
    Try each callgraph for a finding. Returns True if enriched.

    Uses the first callgraph where the package is imported.
    If no callgraph matches, marks the finding as not reachable.
    """
    component = finding.get("component", "")
    if not component:
        return False

    for callgraph in callgraphs:
        module_usage = callgraph.module_usage or {}
        import_map = callgraph.import_map or {}
        language = callgraph.language or "unknown"

        if _is_package_in_callgraph(component, module_usage, import_map, language):
            _enrich_single_finding(finding, module_usage, import_map, language)
            return True

    # Package not found in any callgraph
    languages = [cg.language or "unknown" for cg in callgraphs]
    if "details" not in finding:
        finding["details"] = {}
    if _callgraphs_cover_finding_ecosystem(finding, languages, component_languages):
        # A callgraph of the finding's own ecosystem analyzed the code and the
        # package isn't imported there -> genuinely unreachable (fail-closed x0.4).
        reachability: Dict[str, Any] = {
            "is_reachable": False,
            "confidence_score": REACHABILITY_CONFIDENCE_NOT_USED,
            "analysis_level": REACHABILITY_LEVEL_IMPORT,
            "matched_symbols": [],
            "import_locations": [],
            "message": f"Package '{component}' is not imported in any analyzed source file ({', '.join(languages)}).",
        }
    else:
        # No analyzed callgraph covers this package's ecosystem (wrong language,
        # unsupported ecosystem, or unknown purl). Absence is NOT evidence of
        # unreachability -> record unknown (identity modifier), never down-weight.
        reachability = {
            "is_reachable": None,
            "confidence_score": 0.0,
            "analysis_level": REACHABILITY_LEVEL_NONE,
            "matched_symbols": [],
            "import_locations": [],
            "message": (
                f"Package '{component}' not found in analyzed callgraph(s) ({', '.join(languages)}); "
                "reachability unknown (its ecosystem was not analyzed)."
            ),
        }
    finding["details"]["reachability"] = reachability
    _apply_adjusted_risk_score(finding, reachability)
    return True


async def enrich_findings_with_reachability(
    findings: List[Dict[str, Any]],
    project_id: str,
    db: AsyncIOMotorDatabase,
    scan_id: Optional[str] = None,
) -> int:
    """
    Enrich vulnerability findings with reachability analysis.

    Supports multiple callgraphs (one per language). For each finding,
    the matching callgraph is used (i.e. the one where the package is imported).

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

    callgraphs = await _fetch_callgraphs(project_id, scan_id, db)

    if not callgraphs:
        logger.debug(f"No callgraph available for scan {scan_id}")
        return 0

    languages = [cg.language or "unknown" for cg in callgraphs]
    logger.debug(f"Found {len(callgraphs)} callgraph(s) for scan {scan_id}: {languages}")

    # Reliable per-finding ecosystem (vuln findings don't carry a purl), used to
    # gate the fail-closed unreachable down-weight to the analyzed languages.
    component_languages = await _build_component_language_map(db, scan_id)

    enriched_count = 0

    for finding in findings:
        if finding.get("type") != "vulnerability":
            continue
        if _enrich_finding_from_callgraphs(finding, callgraphs, component_languages):
            enriched_count += 1

    return enriched_count


def _analyze_reachability(
    finding: Dict[str, Any],
    component: str,
    module_usage: Dict[str, Any],
    import_map: Dict[str, List[str]],
    language: str,
) -> ReachabilityResult:
    """
    Analyze reachability for a single finding.

    Two-level analysis:
    1. Import-based: Is the package imported anywhere?
    2. Symbol-based: Are vulnerable functions (extracted from CVE text) used?

    Returns:
        ReachabilityResult with analysis details
    """
    result: ReachabilityResult = {
        "is_reachable": False,
        "confidence_score": 0.0,
        "analysis_level": REACHABILITY_LEVEL_NONE,
        "matched_symbols": [],
        "import_locations": [],
        "message": "",
    }

    # Normalize component name for lookup
    normalized = _normalize_component(component, language)

    usage = module_usage.get(normalized) or module_usage.get(component)

    # Also check import_map for package presence
    package_in_imports = _check_package_in_imports(normalized, import_map)

    if not usage and not package_in_imports:
        # Package not found in imports - not reachable
        result["is_reachable"] = False
        result["confidence_score"] = REACHABILITY_CONFIDENCE_NOT_USED
        result["analysis_level"] = REACHABILITY_LEVEL_IMPORT
        result["message"] = f"Package '{component}' is not imported in any analyzed source file."
        return result

    # Package is imported - collect import locations
    import_locations: List[str] = []
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
        result["confidence_score"] = REACHABILITY_CONFIDENCE_IMPORTED_NO_SYMBOLS
        result["analysis_level"] = REACHABILITY_LEVEL_IMPORT
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
        result["confidence_score"] = _calculate_confidence(extracted.confidence, "matched")
        result["analysis_level"] = REACHABILITY_LEVEL_SYMBOL
        result["matched_symbols"] = matched_symbols
        result["message"] = f"Vulnerable function(s) {', '.join(matched_symbols[:5])} are used in the codebase."
    elif used_symbols:
        # Package is used but not the vulnerable functions (potentially)
        result["is_reachable"] = True  # Still mark as reachable but lower confidence
        result["confidence_score"] = _calculate_confidence(extracted.confidence, "partial")
        result["analysis_level"] = REACHABILITY_LEVEL_SYMBOL
        result["message"] = (
            f"Package is imported but extracted vulnerable functions "
            f"({', '.join(extracted.symbols[:3])}) were not found in direct usage. "
            f"May still be reachable through indirect calls."
        )
    else:
        # Package imported but no symbol usage info
        result["is_reachable"] = True
        result["confidence_score"] = REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO
        result["analysis_level"] = REACHABILITY_LEVEL_IMPORT
        result["message"] = f"Package is imported in {import_count} file(s). Symbol-level analysis not available."

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


def _check_package_in_imports(package: str, import_map: Dict[str, List[str]]) -> List[str]:
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

            # Boundary-anchored subpath / submodule match only. A bare
            # ``package_lower in imp_lower`` substring test spuriously matches
            # unrelated packages (npm "ms" -> "forms"/"aws-sdk/clients/sms",
            # Python "requests" -> "requests_oauthlib"), inflating reachability.
            # Require a real path ("/") or module (".") boundary, mirroring the
            # symbol-boundary fix in ``_match_symbols`` (audit #6 / SC#7).
            # Direct equality is already handled above.
            if imp_lower.startswith(package_lower + "/") or imp_lower.startswith(package_lower + "."):
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

        # Qualified-call boundary match on EITHER side (method chaining / dotted
        # usage), e.g. used "openssl.SSL_read" vs vuln "SSL_read", or vuln
        # "Conn.Read" vs the bare used "Read" that production callgraphs actually
        # store. A bare substring test ("get" in "getUser"/"forget") would
        # spuriously promote findings, so we require a real symbol boundary, not
        # any substring (audit #6 / SC#7).
        for vuln in vulnerable_symbols:
            vuln_l = vuln.lower()
            if used_lower.endswith("." + vuln_l) or vuln_l.endswith("." + used_lower):
                matched.append(used)
                break

    return matched


def _calculate_confidence(extraction_confidence: str, match_type: str) -> float:
    """
    Calculate overall confidence score.

    Args:
        extraction_confidence: How reliable is the symbol extraction (low/medium/high)
        match_type: "matched" (direct match), "partial" (imported but not matched)

    Returns:
        Confidence score between 0.0 and 1.0
    """
    extraction_score = REACHABILITY_EXTRACTION_CONFIDENCE.get(
        extraction_confidence, REACHABILITY_EXTRACTION_CONFIDENCE["low"]
    )

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
    db: AsyncIOMotorDatabase,
) -> Dict[str, Any]:
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
    result: Dict[str, Any] = {
        "findings_enriched": 0,
        "error": None,
    }

    # Use repositories for consistent data access
    from app.repositories import (
        ScanRepository,
        FindingRepository,
        CallgraphRepository,
        AnalysisResultRepository,
    )

    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    callgraph_repo = CallgraphRepository(db)
    result_repo = AnalysisResultRepository(db)

    # Check if this scan has pending reachability
    scan = await scan_repo.get_by_id(scan_id)
    if not scan:
        logger.debug(f"Scan {scan_id} not found")
        return result

    if not scan.reachability_pending:
        logger.debug(f"Scan {scan_id} has no pending reachability analysis")
        return result

    try:
        # Fetch vulnerability findings for this scan
        findings = await finding_repo.find_many({"scan_id": scan_id, "type": "vulnerability"}, limit=10000)

        if not findings:
            logger.debug(f"No vulnerability findings for scan {scan_id}")
            # Clear pending status even if no findings
            await scan_repo.update_raw(
                scan_id,
                {
                    "$unset": {
                        "reachability_pending": "",
                        "reachability_pending_since": "",
                    }
                },
            )
            return result

        # Convert to dicts for enrichment (enrichment modifies dicts in place)
        findings_dicts = [f.model_dump(by_alias=True) for f in findings]

        # Run reachability enrichment - callgraph lookup uses scan_id
        enriched_count = await enrich_findings_with_reachability(
            findings=findings_dicts,
            project_id=project_id,
            db=db,
            scan_id=scan_id,
        )

        # Update findings in database with reachability data. Collect UpdateOne
        # operations and flush them in chunked, unordered bulk_write round-trips
        # instead of one sequential update per finding: a 10k-finding scan would
        # otherwise fire 10k serial Mongo calls inline in the callgraph-upload
        # request. Mirrors the analysis engine's dependency bulk-update pattern.
        bulk_ops: List[UpdateOne] = []
        for finding_dict in findings_dicts:
            details = finding_dict.get("details", {})
            reachability_data = details.get("reachability")
            if reachability_data is None:
                continue
            update_fields: Dict[str, Any] = {
                "reachable": reachability_data.get("is_reachable"),
                "reachability_level": reachability_data.get("analysis_level"),
                "reachable_functions": reachability_data.get("matched_symbols", []),
                "details.reachability": reachability_data,
            }
            # Persist the reachability-adjusted risk score (W5 / Finding 13)
            # when enrichment computed one (i.e. the finding had a base
            # details.risk_score to adjust).
            if "adjusted_risk_score" in details:
                update_fields["details.adjusted_risk_score"] = details["adjusted_risk_score"]
            bulk_ops.append(UpdateOne({"_id": finding_dict["_id"]}, {"$set": update_fields}))

        for i in range(0, len(bulk_ops), _BULK_CHUNK_SIZE):
            await finding_repo.collection.bulk_write(bulk_ops[i : i + _BULK_CHUNK_SIZE], ordered=False)

        # Store reachability summary in analysis_results for raw data view. Reuse
        # the canonical builder from analysis/stats so the pending path and the
        # inline analysis path cannot drift (e.g. the high-confidence flag).
        # Lazy import to avoid the stats -> reachability_enrichment import cycle.
        callgraphs = await callgraph_repo.find_all_minimal_by_scan(project_id, scan_id)
        if callgraphs:
            from app.services.analysis.stats import build_reachability_summary

            reachability_summary = build_reachability_summary(
                findings_dicts,
                [cg.model_dump(by_alias=True) for cg in callgraphs],
                enriched_count,
            )
            await result_repo.create_raw(
                {
                    "_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "analyzer_name": "reachability",
                    "result": reachability_summary,
                    "created_at": datetime.now(timezone.utc),
                }
            )

        # Clear pending status via repository
        await scan_repo.update_raw(
            scan_id,
            {
                "$unset": {
                    "reachability_pending": "",
                    "reachability_pending_since": "",
                },
                "$set": {"reachability_completed_at": datetime.now(timezone.utc)},
            },
        )

        result["findings_enriched"] = enriched_count
        logger.info(f"[reachability] Processed scan {scan_id}: enriched {enriched_count} findings")

    except Exception as e:
        result["error"] = str(e)
        logger.exception("[reachability] Failed to process scan %s: %s", scan_id, e)

    return result
