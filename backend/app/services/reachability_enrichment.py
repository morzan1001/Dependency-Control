"""Enrich vulnerability findings with call-graph reachability: import-based (reliable) and symbol-based (heuristic)."""

import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypedDict

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import UpdateOne

from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    REACHABILITY_CONFIDENCE_IMPORTED_NO_SYMBOLS,
    REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO,
    REACHABILITY_CONFIDENCE_NOT_USED,
    REACHABILITY_EXTRACTION_CONFIDENCE,
    REACHABILITY_HIGH_CONFIDENCE_THRESHOLD,
    REACHABILITY_LEVEL_IMPORT,
    REACHABILITY_LEVEL_NONE,
    REACHABILITY_LEVEL_SYMBOL,
    REACHABILITY_REASON_LANGUAGE_NOT_ANALYZED,
    REACHABILITY_REASON_NO_COVERAGE_UNIVERSE,
    REACHABILITY_REASON_OUTSIDE_COVERAGE,
    REACHABILITY_REASON_UNSUPPORTED_ECOSYSTEM,
)
from app.services.aggregation.components import build_component_index, canonical_module_key, lookup_component
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

_FINDINGS_PAGE_SIZE = 1000
# Upper bound on findings held in memory for one enrichment run; whatever it cuts
# off is logged and reported, never dropped silently.
_MAX_FINDINGS_PER_RUN = 100_000

# Ecosystem identifier (a dependency's `type`, e.g. "pypi"/"npm"/"go-module", OR a
# purl type) -> the callgraph language(s) that can actually analyze it. Anything
# else (maven, cargo, nuget, rpm, deb, ...) has no callgraph support, so a missing
# package in those ecosystems is never treated as unreachable.
_ECOSYSTEM_TO_CALLGRAPH_LANGUAGES: dict[str, frozenset] = {
    "pypi": frozenset({"python"}),
    "python": frozenset({"python"}),
    "npm": frozenset({"javascript", "typescript"}),
    "go": frozenset({"go"}),
    "golang": frozenset({"go"}),
    "go-module": frozenset({"go"}),
}


def _ecosystem_languages(ecosystem: str | None, purl: str | None) -> frozenset:
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


async def _build_component_language_map(db: AsyncIOMotorDatabase, scan_id: str) -> dict[str, frozenset]:
    """Map component name -> callgraph language(s) that could analyze it, derived
    from the scan's dependencies (their ``type``/``purl``).

    This is the reliable ecosystem signal: vulnerability findings themselves do
    NOT carry a purl (the OSV/Trivy/Grype normalizers don't persist one), so the
    fail-closed gate must look the package up in the dependency inventory instead.
    """
    out: dict[str, frozenset] = {}
    cursor = db.dependencies.find({"scan_id": scan_id}, {"name": 1, "type": 1, "purl": 1})
    async for dep in cursor:
        name = dep.get("name")
        if not name:
            continue
        langs = _ecosystem_languages(dep.get("type"), dep.get("purl"))
        if langs:
            out[name] = out.get(name, frozenset()) | langs
    # Findings carry the qualified component while the inventory keeps the bare name.
    return build_component_index(out)


async def count_coverable_findings(db: AsyncIOMotorDatabase, scan_id: str) -> int:
    """Vulnerability findings whose ecosystem a callgraph could ever analyze.

    Tells a team whether reachability is worth enabling at all. A container scan is almost
    entirely OS packages, which no callgraph tool covers, so this stays zero however many
    callgraph jobs the pipeline runs — a distinction the plain unknown count cannot make.
    """
    component_languages = await _build_component_language_map(db, scan_id)
    if not component_languages:
        return 0

    coverable = 0
    cursor = db.findings.find(
        {"scan_id": scan_id, "type": "vulnerability", "waived": {"$ne": True}},
        {"component": 1},
    )
    async for finding in cursor:
        component = finding.get("component")
        if component and lookup_component(component_languages, component):
            coverable += 1
    return coverable


@dataclass(frozen=True)
class _PreparedCallgraph:
    """One callgraph's lookup structures, built once per enrichment run."""

    language: str
    usage_index: dict[str, Any]
    import_map: dict[str, list[str]]
    analyzed_index: dict[str, bool]


def _prepare_callgraph(callgraph: Any) -> _PreparedCallgraph:
    analyzed_modules = callgraph.analyzed_modules or []
    return _PreparedCallgraph(
        language=callgraph.language or "unknown",
        usage_index=build_component_index(callgraph.module_usage or {}),
        import_map=callgraph.import_map or {},
        analyzed_index=build_component_index(dict.fromkeys(analyzed_modules, True)),
    )


def _find_usage(prepared: _PreparedCallgraph, component: str) -> Any | None:
    """The callgraph's usage entry for a component, under either spelling.

    The single resolution point for the gate and the analysis, so a component the
    gate resolves can never be missed by the verdict that follows it.
    """
    normalized = _normalize_component(component, prepared.language)
    return lookup_component(prepared.usage_index, component) or lookup_component(prepared.usage_index, normalized)


def _find_import_locations(prepared: _PreparedCallgraph, component: str) -> list[str]:
    return _check_package_in_imports(_normalize_component(component, prepared.language), prepared.import_map)


def _callgraph_can_falsify(
    prepared: _PreparedCallgraph,
    component: str,
    component_languages: dict[str, frozenset] | None,
) -> bool:
    """True only when this callgraph's absence of a component is real evidence.

    Requires the producer to have listed the component in its coverage universe
    (``analyzed_modules``) for a language that covers the component's ecosystem.
    Anything weaker — wrong language, unknown ecosystem, empty or non-matching
    coverage universe — means the package was never inspected.
    """
    langs = lookup_component(component_languages or {}, component) or frozenset()
    if prepared.language not in langs:
        return False
    if not prepared.analyzed_index:
        return False
    normalized = _normalize_component(component, prepared.language)
    return bool(
        lookup_component(prepared.analyzed_index, component) or lookup_component(prepared.analyzed_index, normalized)
    )


def _apply_adjusted_risk_score(finding: dict[str, Any], reachability: Mapping[str, Any]) -> None:
    """Apply the reachability modifier to ``details.risk_score`` and store ``adjusted_risk_score``.

    Symbol-level reachable boosts (x1.1); not-reachable de-prioritises (x0.4); else
    identity. No base risk_score -> nothing to adjust.
    """
    details = finding.setdefault("details", {})
    base = details.get("risk_score")
    if base is None:
        return
    is_reachable = reachability.get("is_reachable")
    analysis_level = reachability.get("analysis_level")
    modifier_level = map_reachability_level_to_modifier(analysis_level, is_reachable)
    down_weighting = is_reachable is False or modifier_level == "unreachable"
    if down_weighting and analysis_level != REACHABILITY_LEVEL_SYMBOL and details.get(DETAILS_KEY_IN_KEV):
        # A known-exploited CVE is never de-prioritised on import-level absence alone.
        is_reachable, modifier_level = None, None
    details["adjusted_risk_score"] = round(
        calculate_adjusted_risk_score(
            float(base),
            is_reachable=is_reachable,
            reachability_level=modifier_level,
        ),
        1,
    )


def is_high_confidence_reachable(reachability_data: dict[str, Any] | None) -> bool:
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


def reachability_display_tier(is_reachable: bool | None, analysis_level: str | None) -> str:
    """Map persisted reachability (is_reachable + analysis_level in
    none/import/symbol) onto the display vocabulary confirmed/likely/unreachable/
    unknown. Shared by the comprehensive-stats and persisted-pending summaries so they cannot drift."""
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
    matched_symbols: list[str]
    import_locations: list[str]
    message: str
    extraction_method: str
    extraction_confidence: str
    vulnerable_symbols: list[str]


async def _fetch_callgraphs(
    project_id: str,
    scan_id: str,
    db: AsyncIOMotorDatabase,
) -> list[Any]:
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


def store_reachability(finding: dict[str, Any], reachability: Mapping[str, Any]) -> None:
    """Persist a verdict under ``details.reachability`` and mirror it to the top level.

    The stats pipeline and the recommendation readers query the top-level fields; writing
    only the nested block leaves every reachability counter at zero.
    """
    details = finding.setdefault("details", {})
    details["reachability"] = reachability
    finding["reachable"] = reachability.get("is_reachable")
    finding["reachability_level"] = reachability.get("analysis_level")
    finding["reachable_functions"] = reachability.get("matched_symbols", [])
    _apply_adjusted_risk_score(finding, reachability)


def _enrich_single_finding(finding: dict[str, Any], prepared: _PreparedCallgraph) -> bool:
    """
    Enrich a single finding with reachability data. Returns True if enriched.
    """
    if finding.get("type") != "vulnerability":
        return False

    component = finding.get("component", "")
    if not component:
        return False

    store_reachability(finding, _analyze_reachability(finding, component, prepared))
    return True


def _is_package_in_callgraph(prepared: _PreparedCallgraph, component: str) -> bool:
    """Check whether a package appears in a callgraph's module usage or imports."""
    return bool(_find_usage(prepared, component) or _find_import_locations(prepared, component))


def _unknown_verdict(
    component: str,
    prepared_graphs: list[_PreparedCallgraph],
    component_languages: dict[str, frozenset] | None,
) -> tuple[str, str]:
    """Why absence from the analyzed callgraphs yields no verdict, as (reason, message).

    The reason separates "no callgraph tooling can ever cover this package" — the case for
    OS packages, which dominate container scans — from the cases a pipeline change would fix.
    Readers must be able to tell those apart without parsing prose.
    """
    langs = lookup_component(component_languages or {}, component) or frozenset()
    if not langs:
        return (
            REACHABILITY_REASON_UNSUPPORTED_ECOSYSTEM,
            f"Package '{component}' is in an ecosystem no callgraph tool supports; reachability unknown.",
        )

    covering = [p for p in prepared_graphs if p.language in langs]
    if not covering:
        analyzed = ", ".join(p.language for p in prepared_graphs) or "none"
        return (
            REACHABILITY_REASON_LANGUAGE_NOT_ANALYZED,
            (
                f"No {'/'.join(sorted(langs))} callgraph was uploaded for this scan "
                f"(analyzed: {analyzed}); reachability unknown."
            ),
        )

    covering_langs = ", ".join(p.language for p in covering)
    if all(not p.analyzed_index for p in covering):
        return (
            REACHABILITY_REASON_NO_COVERAGE_UNIVERSE,
            (
                f"Package '{component}' is absent from the {covering_langs} callgraph(s), "
                "which published no coverage universe; reachability unknown."
            ),
        )
    return (
        REACHABILITY_REASON_OUTSIDE_COVERAGE,
        (
            f"Package '{component}' is outside the coverage universe resolved by the "
            f"{covering_langs} callgraph(s); reachability unknown."
        ),
    )


def _enrich_finding_from_callgraphs(
    finding: dict[str, Any],
    prepared_graphs: list[_PreparedCallgraph],
    component_languages: dict[str, frozenset] | None = None,
) -> bool:
    """
    Try each callgraph for a finding. Returns True if enriched.

    Uses the first callgraph where the package is imported. Absence only becomes
    an unreachable verdict when a callgraph can falsify it.
    """
    component = finding.get("component", "")
    if not component:
        return False

    for prepared in prepared_graphs:
        if _is_package_in_callgraph(prepared, component):
            _enrich_single_finding(finding, prepared)
            return True

    falsifying = [p.language for p in prepared_graphs if _callgraph_can_falsify(p, component, component_languages)]
    if falsifying:
        reachability: dict[str, Any] = {
            "is_reachable": False,
            "confidence_score": REACHABILITY_CONFIDENCE_NOT_USED,
            "analysis_level": REACHABILITY_LEVEL_IMPORT,
            "matched_symbols": [],
            "import_locations": [],
            "message": (
                f"Package '{component}' was analyzed but is not imported in any source file ({', '.join(falsifying)})."
            ),
        }
    else:
        reason, message = _unknown_verdict(component, prepared_graphs, component_languages)
        reachability = {
            "is_reachable": None,
            "confidence_score": 0.0,
            "analysis_level": REACHABILITY_LEVEL_NONE,
            "matched_symbols": [],
            "import_locations": [],
            "unknown_reason": reason,
            "message": message,
        }
    store_reachability(finding, reachability)
    return True


async def enrich_findings_with_reachability(
    findings: list[dict[str, Any]],
    project_id: str,
    db: AsyncIOMotorDatabase,
    scan_id: str | None = None,
) -> int:
    """Enrich vulnerability findings (modified in-place) with reachability; return count enriched.

    Uses the per-language callgraph where each finding's package is imported.
    """
    if not findings:
        return 0

    if not scan_id and findings:
        scan_id = findings[0].get("scan_id")

    if not scan_id:
        logger.warning("No scan_id available for reachability enrichment")
        return 0

    callgraphs = await _fetch_callgraphs(project_id, scan_id, db)

    if not callgraphs:
        logger.debug(f"No callgraph available for scan {scan_id}")
        return 0

    prepared_graphs = [_prepare_callgraph(cg) for cg in callgraphs]
    logger.debug(f"Found {len(callgraphs)} callgraph(s) for scan {scan_id}: {[p.language for p in prepared_graphs]}")

    # Per-finding ecosystem gates the unreachable down-weight to the analyzed languages.
    component_languages = await _build_component_language_map(db, scan_id)

    enriched_count = 0

    for finding in findings:
        if finding.get("type") != "vulnerability":
            continue
        if _enrich_finding_from_callgraphs(finding, prepared_graphs, component_languages):
            enriched_count += 1

    return enriched_count


def _analyze_reachability(
    finding: dict[str, Any],
    component: str,
    prepared: _PreparedCallgraph,
) -> ReachabilityResult:
    """Analyze reachability for one finding: import-based, then symbol-based.

    Callers establish presence with :func:`_is_package_in_callgraph` first, so the
    package is known to be imported here.
    """
    usage = _find_usage(prepared, component)
    locations = usage.get("import_locations") or [] if usage else _find_import_locations(prepared, component)
    import_count = len(locations[:10])

    result: ReachabilityResult = {
        "is_reachable": True,
        "confidence_score": REACHABILITY_CONFIDENCE_IMPORTED_NO_SYMBOLS,
        "analysis_level": REACHABILITY_LEVEL_IMPORT,
        "matched_symbols": [],
        "import_locations": locations[:10],
        "message": (
            f"Package is imported in {import_count} file(s). Could not determine specific vulnerable functions."
        ),
    }

    extracted = get_symbols_for_finding(finding)
    if not extracted.symbols:
        return result

    used_symbols = usage.get("used_symbols", []) if usage else []
    matched_symbols = _match_symbols(extracted.symbols, used_symbols)

    if matched_symbols:
        result["confidence_score"] = _calculate_confidence(extracted.confidence, "matched")
        result["analysis_level"] = REACHABILITY_LEVEL_SYMBOL
        result["matched_symbols"] = matched_symbols
        result["message"] = f"Vulnerable function(s) {', '.join(matched_symbols[:5])} are used in the codebase."
    elif used_symbols:
        # Symbols were searched and not found: import-level evidence only, never "confirmed".
        result["confidence_score"] = _calculate_confidence(extracted.confidence, "partial")
        result["message"] = (
            f"Package is imported but extracted vulnerable functions "
            f"({', '.join(extracted.symbols[:3])}) were not found in direct usage. "
            f"May still be reachable through indirect calls."
        )
    else:
        result["confidence_score"] = REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO
        result["message"] = f"Package is imported in {import_count} file(s). Symbol-level analysis not available."

    result["extraction_method"] = extracted.extraction_method
    result["extraction_confidence"] = extracted.confidence
    result["vulnerable_symbols"] = extracted.symbols[:10]

    return result


def _normalize_component(component: str, language: str) -> str:
    """Read-side key for a finding's component, identical to the key the parsers stored.

    Delegates the per-language rule to ``canonical_module_key`` so the write and read
    sides cannot drift; only the version suffix is stripped here, because findings carry
    it (``pkg@1.0.0``) and callgraph module names never do.
    """
    if not component:
        return component

    if "@" in component and not component.startswith("@"):
        component = component.rsplit("@", 1)[0]

    return canonical_module_key(component, language)


def _check_package_in_imports(package: str, import_map: dict[str, list[str]]) -> list[str]:
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

            # Boundary-anchored subpath/submodule match only: a bare substring test
            # spuriously matches unrelated packages (npm "ms" -> "forms"), inflating
            # reachability. Require a real path ("/") or module (".") boundary.
            if imp_lower.startswith((package_lower + "/", package_lower + ".")):
                files_importing.append(file_path)
                break

    return files_importing


def _match_symbols(vulnerable_symbols: list[str], used_symbols: list[str]) -> list[str]:
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

        # Qualified-call boundary match on either side (dotted usage), e.g. used
        # "openssl.SSL_read" vs vuln "SSL_read". Require a real symbol boundary, not
        # any substring, so "get" in "getUser" doesn't spuriously promote findings.
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


async def persist_reachability_result(result_repo: Any, scan_id: str, summary: Mapping[str, Any]) -> None:
    """Store the scan's single reachability summary, replacing any earlier one.

    Each language's callgraph re-runs enrichment over the full set, so every run supersedes
    the last; inserting instead would leave the raw-data view rendering a stale duplicate.
    """
    await result_repo.collection.update_one(
        {"scan_id": scan_id, "analyzer_name": "reachability"},
        {
            "$set": {"result": summary, "created_at": datetime.now(timezone.utc)},
            "$setOnInsert": {"_id": str(uuid.uuid4())},
        },
        upsert=True,
    )


async def _sync_project_stats_if_latest(
    db: AsyncIOMotorDatabase,
    project_id: str,
    scan_id: str,
    stats: Any,
) -> None:
    """Mirror recomputed scan stats onto the project when this scan is still its latest."""
    from app.repositories import ProjectRepository

    project_repo = ProjectRepository(db)
    project = await project_repo.get_raw_by_id(project_id)
    if project and project.get("latest_scan_id") == scan_id:
        await project_repo.update_raw(project_id, {"$set": {"stats": stats.model_dump()}})


async def _load_vulnerability_findings(finding_repo: Any, scan_id: str) -> tuple[list[Any], int]:
    """Page through a scan's vulnerability findings; second element is how many the cap left behind."""
    query = {"scan_id": scan_id, "type": "vulnerability"}
    findings: list[Any] = []
    while len(findings) < _MAX_FINDINGS_PER_RUN:
        page = await finding_repo.find_many(query, skip=len(findings), limit=_FINDINGS_PAGE_SIZE, sort_by="_id")
        findings.extend(page)
        if len(page) < _FINDINGS_PAGE_SIZE:
            return findings, 0
    total = await finding_repo.count(query)
    return findings, max(total - len(findings), 0)


async def run_pending_reachability_for_scan(
    scan_id: str,
    project_id: str,
    db: AsyncIOMotorDatabase,
) -> dict[str, Any]:
    """Run reachability for a scan after a callgraph is uploaded.

    Runs on every upload, not just the first: a multi-language repo publishes one
    callgraph per language and each one recomputes every finding from the full set.

    Returns ``{"findings_enriched": int, "findings_dropped": int, "error": str | None}``.
    """
    result: dict[str, Any] = {
        "findings_enriched": 0,
        "findings_dropped": 0,
        "error": None,
    }

    from app.repositories import (
        AnalysisResultRepository,
        CallgraphRepository,
        FindingRepository,
        ScanRepository,
    )

    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    callgraph_repo = CallgraphRepository(db)
    result_repo = AnalysisResultRepository(db)

    scan = await scan_repo.get_by_id(scan_id)
    if not scan:
        logger.debug(f"Scan {scan_id} not found")
        return result

    try:
        findings, dropped = await _load_vulnerability_findings(finding_repo, scan_id)
        if dropped:
            result["findings_dropped"] = dropped
            logger.warning(
                "[reachability] Scan %s has more than %d vulnerability findings; %d left unenriched",
                scan_id,
                _MAX_FINDINGS_PER_RUN,
                dropped,
            )

        if not findings:
            logger.debug(f"No vulnerability findings for scan {scan_id}")
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

        findings_dicts = [f.model_dump(by_alias=True) for f in findings]

        enriched_count = await enrich_findings_with_reachability(
            findings=findings_dicts,
            project_id=project_id,
            db=db,
            scan_id=scan_id,
        )

        # Chunked unordered bulk_write instead of one update per finding, so a 10k-finding
        # scan doesn't fire 10k serial Mongo calls inline in the callgraph-upload request.
        bulk_ops: list[UpdateOne] = []
        for finding_dict in findings_dicts:
            details = finding_dict.get("details", {})
            reachability_data = details.get("reachability")
            if reachability_data is None:
                continue
            # store_reachability already put every field on the dict; persist exactly those.
            update_fields: dict[str, Any] = {
                "reachable": finding_dict["reachable"],
                "reachability_level": finding_dict["reachability_level"],
                "reachable_functions": finding_dict["reachable_functions"],
                "details.reachability": reachability_data,
            }
            # Persist the reachability-adjusted risk score when enrichment computed one.
            if "adjusted_risk_score" in details:
                update_fields["details.adjusted_risk_score"] = details["adjusted_risk_score"]
            bulk_ops.append(UpdateOne({"_id": finding_dict["_id"]}, {"$set": update_fields}))

        for i in range(0, len(bulk_ops), _BULK_CHUNK_SIZE):
            await finding_repo.collection.bulk_write(bulk_ops[i : i + _BULK_CHUNK_SIZE], ordered=False)

        # Reuse the canonical builders so the pending and inline paths cannot drift.
        # Lazy import to avoid the stats -> reachability_enrichment import cycle.
        from app.services.analysis.stats import build_reachability_summary, calculate_comprehensive_stats

        callgraphs = await callgraph_repo.find_all_minimal_by_scan(project_id, scan_id)
        if callgraphs:
            reachability_summary = build_reachability_summary(
                findings_dicts,
                [cg.model_dump(by_alias=True) for cg in callgraphs],
                enriched_count,
            )
            await persist_reachability_result(result_repo, scan_id, reachability_summary)

        # The scan's stats were frozen at completion, before any reachability verdict existed.
        stats = await calculate_comprehensive_stats(db, scan_id)
        await scan_repo.update_raw(
            scan_id,
            {
                "$unset": {
                    "reachability_pending": "",
                    "reachability_pending_since": "",
                },
                "$set": {
                    "reachability_completed_at": datetime.now(timezone.utc),
                    "stats": stats.model_dump(),
                },
            },
        )
        await _sync_project_stats_if_latest(db, project_id, scan_id, stats)

        result["findings_enriched"] = enriched_count
        logger.info(f"[reachability] Processed scan {scan_id}: enriched {enriched_count} findings")

    except Exception as e:
        result["error"] = str(e)
        logger.exception("[reachability] Failed to process scan %s: %s", scan_id, e)

    return result
