"""Enrich vulnerability findings with call-graph reachability: import-based (reliable) and symbol-based (heuristic)."""

import logging
import uuid
from collections.abc import Iterable, Mapping
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
    REACHABILITY_REASON_ABSENCE_NOT_EVIDENCE,
    REACHABILITY_REASON_LANGUAGE_NOT_ANALYZED,
    REACHABILITY_REASON_NO_COVERAGE_UNIVERSE,
    REACHABILITY_REASON_OUTSIDE_COVERAGE,
    REACHABILITY_REASON_UNSUPPORTED_ECOSYSTEM,
)
from app.services.component_identity import (
    JVM_LANGUAGES,
    build_component_index,
    canonical_module_key,
    lookup_component,
)
from app.core.purl import get_purl_type
from app.services.enrichment.scoring import calculate_adjusted_risk_score
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
# purl type) -> the callgraph language(s) that can analyze it. Any other ecosystem
# (cargo, nuget, rpm, deb, ...) has no callgraph producer.
_ECOSYSTEM_TO_CALLGRAPH_LANGUAGES: dict[str, frozenset[str]] = {
    "pypi": frozenset({"python"}),
    "python": frozenset({"python"}),
    "npm": frozenset({"javascript", "typescript"}),
    "go": frozenset({"go"}),
    "golang": frozenset({"go"}),
    "go-module": frozenset({"go"}),
    "maven": JVM_LANGUAGES,
}
# jdeps cannot see classes loaded through reflection or ServiceLoader, so a missing import is no evidence.
_NON_FALSIFYING_LANGUAGES = JVM_LANGUAGES

# Per component name, one (version, callgraph languages) candidate per ecosystem that lists it.
ComponentLanguages = Mapping[str, list[tuple[str, frozenset[str]]]]


def _ecosystem_languages(ecosystem: str | None, purl: str | None) -> frozenset[str]:
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


def component_language_map(deps: Iterable[Mapping[str, Any]]) -> dict[str, list[tuple[str, frozenset[str]]]]:
    """Map component name -> a (version, callgraph languages) candidate per ecosystem listing it.

    This is the reliable ecosystem signal: vulnerability findings carry no purl (the OSV/Trivy/Grype
    normalizers do not persist one), so the fail-closed gate looks the package up in the inventory.
    Ecosystems sharing a name stay separate, so one ecosystem's callgraph never speaks for another.
    """
    out: dict[str, dict[tuple[str, frozenset[str]], None]] = {}
    for dep in deps:
        name = dep.get("name")
        if not name:
            continue
        langs = _ecosystem_languages(dep.get("type"), dep.get("purl"))
        if langs:
            out.setdefault(name, {})[(str(dep.get("version") or ""), langs)] = None
    # Findings carry the qualified component while the inventory keeps the bare name.
    return build_component_index({name: list(candidates) for name, candidates in out.items()})


async def build_component_language_map(
    db: AsyncIOMotorDatabase, scan_id: str
) -> dict[str, list[tuple[str, frozenset[str]]]]:
    projection = {"name": 1, "version": 1, "type": 1, "purl": 1}
    deps = await db.dependencies.find({"scan_id": scan_id}, projection).to_list(None)
    return component_language_map(deps)


def _candidate_languages(
    component_languages: ComponentLanguages | None, component: str, version: str | None
) -> list[frozenset[str]]:
    """The language sets of every ecosystem a finding's package may belong to, narrowed by its version."""
    candidates = lookup_component(component_languages or {}, component) or []
    matching = [langs for candidate_version, langs in candidates if candidate_version == version]
    return list(dict.fromkeys(matching or [langs for _, langs in candidates]))


@dataclass(frozen=True)
class _PreparedCallgraph:
    """One callgraph's lookup structures, built once per enrichment run."""

    language: str
    usage_index: dict[str, Any]
    analyzed_index: dict[str, bool]


def _with_enclosing_packages(module_usage: dict[str, Any]) -> dict[str, Any]:
    """Fold each submodule's usage into every enclosing package key, as unresolved from-imports name the module path."""
    locations: dict[str, dict[str, None]] = {}
    symbols: dict[str, dict[str, None]] = {}
    for key, usage in module_usage.items():
        parts = key.split(".")
        for depth in range(1, len(parts) + 1):
            target = ".".join(parts[:depth])
            locations.setdefault(target, {}).update(dict.fromkeys(usage.get("import_locations") or []))
            symbols.setdefault(target, {}).update(dict.fromkeys(usage.get("used_symbols") or []))
    return {
        key: {**module_usage.get(key, {}), "import_locations": list(found), "used_symbols": list(symbols[key])}
        for key, found in locations.items()
    }


def _prepare_callgraph(callgraph: Any) -> _PreparedCallgraph:
    analyzed_modules = callgraph.analyzed_modules or []
    language = callgraph.language or "unknown"
    module_usage = callgraph.module_usage or {}
    if language.lower() == "python":
        module_usage = _with_enclosing_packages(module_usage)
    return _PreparedCallgraph(
        language=language,
        usage_index=build_component_index(module_usage),
        analyzed_index=build_component_index(dict.fromkeys(analyzed_modules, True)),
    )


def _find_usage(prepared: _PreparedCallgraph, component: str) -> Any | None:
    """The callgraph's usage entry for a component, under either spelling.

    The single resolution point for the gate and the analysis, so a component the
    gate resolves can never be missed by the verdict that follows it.
    """
    normalized = _normalize_component(component, prepared.language)
    return lookup_component(prepared.usage_index, component) or lookup_component(prepared.usage_index, normalized)


def _lists_package(prepared: _PreparedCallgraph, component: str) -> bool:
    """Whether the producer listed the package in its coverage universe (``analyzed_modules``)."""
    normalized = _normalize_component(component, prepared.language)
    return bool(
        lookup_component(prepared.analyzed_index, component) or lookup_component(prepared.analyzed_index, normalized)
    )


def _falsifying_languages(
    component: str, prepared_graphs: list[_PreparedCallgraph], language_sets: list[frozenset[str]]
) -> list[str]:
    """Languages whose callgraphs covered the package, unused; empty unless every candidate ecosystem has one."""
    falsifying: list[str] = []
    for langs in language_sets:
        covering = [
            p.language
            for p in prepared_graphs
            if p.language in langs and p.language not in _NON_FALSIFYING_LANGUAGES and _lists_package(p, component)
        ]
        if not covering:
            return []
        falsifying.extend(covering)
    return list(dict.fromkeys(falsifying))


def _apply_adjusted_risk_score(finding: dict[str, Any], reachability: Mapping[str, Any]) -> None:
    """Store ``details.risk_score`` scaled by the reachability verdict as ``adjusted_risk_score``."""
    details = finding.setdefault("details", {})
    base = details.get("risk_score")
    if base is None:
        return
    is_reachable = reachability.get("is_reachable")
    analysis_level = reachability.get("analysis_level")
    if is_reachable is False and analysis_level != REACHABILITY_LEVEL_SYMBOL and details.get(DETAILS_KEY_IN_KEV):
        # A known-exploited CVE is never de-prioritised on import-level absence alone.
        is_reachable, analysis_level = None, None
    details["adjusted_risk_score"] = round(calculate_adjusted_risk_score(float(base), is_reachable, analysis_level), 1)


def is_high_confidence_reachable(is_reachable: Any, confidence: Any) -> bool:
    """The gate for headline reachable counts; bool is no confidence, True would pass as a perfect 1.0."""
    return (
        is_reachable is True
        and isinstance(confidence, (int, float))
        and not isinstance(confidence, bool)
        and confidence >= REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
    )


class ReachabilityResult(TypedDict, total=False):
    """Result of reachability analysis for a finding."""

    is_reachable: bool
    confidence_score: float
    analysis_level: str
    matched_symbols: list[str]
    import_locations: list[str]
    import_location_count: int
    message: str
    extraction_method: str
    extraction_confidence: str
    vulnerable_symbols: list[str]
    vulnerable_symbol_count: int


async def fetch_callgraphs(project_id: str, scan_id: str, db: AsyncIOMotorDatabase) -> list[Any]:
    """Callgraphs of the scan's lineage root (uploads land on the pipeline scan), else of the root's pipeline."""
    from app.repositories import CallgraphRepository, ScanRepository

    callgraph_repo = CallgraphRepository(db)
    scan_repo = ScanRepository(db)

    scan = await scan_repo.get_by_id(scan_id)
    root_id = await scan_repo.lineage_root(scan_id, scan)
    callgraphs = await callgraph_repo.find_all_minimal_by_scan(project_id, root_id)
    if callgraphs:
        return callgraphs

    root = scan if root_id == scan_id else await scan_repo.get_by_id(root_id)
    if root and root.pipeline_id:
        return await callgraph_repo.find_all_minimal_by_pipeline(project_id, root.pipeline_id)

    return []


def store_reachability(finding: dict[str, Any], reachability: Mapping[str, Any]) -> None:
    """Persist a verdict under ``details.reachability`` and mirror it to the top level.

    The stats fold and the recommendation readers read the top-level fields; writing only
    the nested block leaves every reachability counter at zero.
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
    """Whether the callgraph records usage under the package's whole canonical module key."""
    return _find_usage(prepared, component) is not None


def _unknown_verdict(
    component: str,
    prepared_graphs: list[_PreparedCallgraph],
    language_sets: list[frozenset[str]],
) -> tuple[str, str]:
    """Why absence from the analyzed callgraphs yields no verdict, as (reason, message).

    The reason separates "no callgraph tooling can ever cover this package" — the case for
    OS packages, which dominate container scans — from the cases a pipeline change would fix.
    Readers must be able to tell those apart without parsing prose.
    """
    if not language_sets:
        return (
            REACHABILITY_REASON_UNSUPPORTED_ECOSYSTEM,
            f"Package '{component}' is in an ecosystem no callgraph tool supports; reachability unknown.",
        )

    uncovered = next((langs for langs in language_sets if not any(p.language in langs for p in prepared_graphs)), None)
    if uncovered is not None:
        analyzed = ", ".join(p.language for p in prepared_graphs) or "none"
        return (
            REACHABILITY_REASON_LANGUAGE_NOT_ANALYZED,
            (
                f"No {'/'.join(sorted(uncovered))} callgraph was uploaded for this scan "
                f"(analyzed: {analyzed}); reachability unknown."
            ),
        )

    covering = [p for p in prepared_graphs if any(p.language in langs for langs in language_sets)]
    covering_langs = ", ".join(p.language for p in covering)
    if all(not p.analyzed_index for p in covering):
        return (
            REACHABILITY_REASON_NO_COVERAGE_UNIVERSE,
            (
                f"Package '{component}' is absent from the {covering_langs} callgraph(s), "
                "which published no coverage universe; reachability unknown."
            ),
        )
    if any(p.language in _NON_FALSIFYING_LANGUAGES and _lists_package(p, component) for p in covering):
        return (
            REACHABILITY_REASON_ABSENCE_NOT_EVIDENCE,
            (
                f"Package '{component}' was analyzed but is not imported ({covering_langs}); this callgraph "
                "cannot see reflective loading, so its absence is no evidence; reachability unknown."
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
    component_languages: ComponentLanguages | None = None,
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

    language_sets = _candidate_languages(component_languages, component, finding.get("version"))
    falsifying = _falsifying_languages(component, prepared_graphs, language_sets)
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
        reason, message = _unknown_verdict(component, prepared_graphs, language_sets)
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


def enrich_findings_from_callgraphs(
    findings: list[dict[str, Any]],
    prepared_graphs: list[_PreparedCallgraph],
    component_languages: ComponentLanguages | None = None,
) -> int:
    """Enrich vulnerability findings in place from prepared callgraphs; return how many were enriched."""
    enriched_count = 0
    for finding in findings:
        if finding.get("type") != "vulnerability":
            continue
        if _enrich_finding_from_callgraphs(finding, prepared_graphs, component_languages):
            enriched_count += 1
    return enriched_count


def enrich_findings_with_reachability(
    findings: list[dict[str, Any]],
    callgraphs: list[Any],
    component_languages: ComponentLanguages,
) -> int:
    """Enrich vulnerability findings (modified in-place) with reachability; return count enriched.

    Uses the per-language callgraph where each finding's package is imported; ``component_languages``
    comes from the inventory of the scan itself, which a rescan keeps under its own id.
    """
    if not findings or not callgraphs:
        return 0

    prepared_graphs = [_prepare_callgraph(cg) for cg in callgraphs]
    logger.debug(f"Found {len(callgraphs)} callgraph(s): {[p.language for p in prepared_graphs]}")
    return enrich_findings_from_callgraphs(findings, prepared_graphs, component_languages)


# Evidence samples kept on the finding document; the sibling *_count fields carry the totals.
_IMPORT_LOCATION_SAMPLE = 10
_VULNERABLE_SYMBOL_SAMPLE = 10
_MESSAGE_SYMBOL_SAMPLE = 5


def _named_sample(symbols: list[str]) -> str:
    """The first few symbol names, followed by how many the sentence does not name."""
    shown = ", ".join(symbols[:_MESSAGE_SYMBOL_SAMPLE])
    unnamed = len(symbols) - _MESSAGE_SYMBOL_SAMPLE
    return shown if unnamed <= 0 else f"{shown} and {unnamed} more"


def _analyze_reachability(
    finding: dict[str, Any],
    component: str,
    prepared: _PreparedCallgraph,
) -> ReachabilityResult:
    """Analyze reachability for one finding: import-based, then symbol-based.

    Callers establish presence with :func:`_is_package_in_callgraph` first, so the
    package is known to be imported here.
    """
    usage = _find_usage(prepared, component) or {}
    locations = usage.get("import_locations") or []
    import_count = len(locations)

    result: ReachabilityResult = {
        "is_reachable": True,
        "confidence_score": REACHABILITY_CONFIDENCE_IMPORTED_NO_SYMBOLS,
        "analysis_level": REACHABILITY_LEVEL_IMPORT,
        "matched_symbols": [],
        "import_locations": locations[:_IMPORT_LOCATION_SAMPLE],
        "import_location_count": import_count,
        "message": (
            f"Package is imported in {import_count} file(s). Could not determine specific vulnerable functions."
        ),
    }

    extracted = get_symbols_for_finding(finding)
    if not extracted.symbols:
        return result

    # get_symbols_for_finding unions across vulnerabilities through a set, so impose an order
    # before any sample is taken from it.
    vulnerable_symbols = sorted(extracted.symbols)
    used_symbols = usage.get("used_symbols", [])
    matched_symbols = _match_symbols(vulnerable_symbols, used_symbols)

    if matched_symbols:
        result["confidence_score"] = _calculate_confidence(extracted.confidence, "matched")
        result["analysis_level"] = REACHABILITY_LEVEL_SYMBOL
        result["matched_symbols"] = matched_symbols
        result["message"] = f"Vulnerable function(s) {_named_sample(matched_symbols)} are used in the codebase."
    elif used_symbols:
        # Symbols were searched and not found: import-level evidence only, never "confirmed".
        result["confidence_score"] = _calculate_confidence(extracted.confidence, "partial")
        result["message"] = (
            f"Package is imported but extracted vulnerable functions "
            f"({_named_sample(vulnerable_symbols)}) were not found in direct usage. "
            f"May still be reachable through indirect calls."
        )
    else:
        result["confidence_score"] = REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO
        result["message"] = f"Package is imported in {import_count} file(s). Symbol-level analysis not available."

    result["extraction_method"] = extracted.extraction_method
    result["extraction_confidence"] = extracted.confidence
    result["vulnerable_symbols"] = vulnerable_symbols[:_VULNERABLE_SYMBOL_SAMPLE]
    result["vulnerable_symbol_count"] = len(vulnerable_symbols)

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
    """Blend the symbol-extraction confidence with the match type into a 0.0-1.0 score."""
    extraction_score = REACHABILITY_EXTRACTION_CONFIDENCE.get(
        extraction_confidence, REACHABILITY_EXTRACTION_CONFIDENCE["low"]
    )

    if match_type == "matched":
        # Direct match - high confidence
        return min(extraction_score + 0.1, 1.0)
    if match_type == "partial":
        # Partial - lower confidence
        return extraction_score * 0.7
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

    from app.repositories import AnalysisResultRepository, FindingRepository, ScanRepository

    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
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

        callgraphs = await fetch_callgraphs(project_id, scan_id, db)
        component_languages = await build_component_language_map(db, scan_id)
        enriched_count = enrich_findings_with_reachability(findings_dicts, callgraphs, component_languages)

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

        if callgraphs:
            reachability_summary = build_reachability_summary(
                findings_dicts,
                [cg.model_dump(by_alias=True) for cg in callgraphs],
                enriched_count,
            )
            await persist_reachability_result(result_repo, scan_id, reachability_summary)

        # The scan's stats were frozen at completion, before any reachability verdict existed.
        stats = await calculate_comprehensive_stats(db, scan_id, component_languages)
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
