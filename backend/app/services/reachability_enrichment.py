"""Import-level reachability is reliable; symbol-level matching is a heuristic."""

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import (
    APP_PACKAGE_TYPES,
    DETAILS_KEY_IN_KEV,
    MAX_RESCAN_HOPS,
    OS_PACKAGE_TYPES,
    REACHABILITY_CONFIDENCE_IMPORTED_NO_SYMBOLS,
    REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO,
    REACHABILITY_CONFIDENCE_NOT_USED,
    REACHABILITY_CONFIDENCE_SYMBOL_MATCHED,
    REACHABILITY_CONFIDENCE_SYMBOLS_NOT_USED,
    REACHABILITY_HIGH_CONFIDENCE_THRESHOLD,
    REACHABILITY_LEVEL_IMPORT,
    REACHABILITY_LEVEL_NONE,
    REACHABILITY_LEVEL_SYMBOL,
    sort_by_severity,
)
from app.core.metrics import analysis_enrichment_total, analysis_reachable_vulnerabilities_total
from app.core.purl import get_purl_type
from app.core.risk_scoring import reachability_display_tier
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.callgraphs import CallgraphRepository
from app.repositories.projections import CallgraphMinimal
from app.repositories.scans import ScanRepository
from app.schemas.finding_details import ReachabilityInfo
from app.services.analysis.types import CallgraphInfo, ReachabilityLevelCounts, ReachabilitySummary, VulnerabilityInfo
from app.services.component_identity import (
    JVM_LANGUAGES,
    build_component_index,
    canonical_module_key,
    lookup_component,
)
from app.services.enrichment.scoring import calculate_adjusted_risk_score
from app.services.recommendation.common import display_vulnerability_id, name_some
from app.services.vulnerable_symbols import get_symbols_for_finding

logger = logging.getLogger(__name__)

# Purl type -> the callgraph language(s) that can analyze it; another known ecosystem has no producer.
_ECOSYSTEM_TO_CALLGRAPH_LANGUAGES: dict[str, frozenset[str]] = {
    **dict.fromkeys(OS_PACKAGE_TYPES | APP_PACKAGE_TYPES, frozenset()),
    "pypi": frozenset({"python"}),
    "npm": frozenset({"javascript", "typescript"}),
    # Some producers write the off-spec pkg:go/ purl.
    "go": frozenset({"go"}),
    "golang": frozenset({"go"}),
    "maven": JVM_LANGUAGES,
}
# jdeps cannot see classes loaded through reflection or ServiceLoader, so a missing import is no evidence.
_NON_FALSIFYING_LANGUAGES = JVM_LANGUAGES

# Per component name, one (version, callgraph languages, confirmed transitive) candidate per ecosystem listing it.
ComponentLanguages = Mapping[str, list[tuple[str, frozenset[str], bool]]]


def _ecosystem_languages(ecosystem: str | None, purl: str | None) -> frozenset[str] | None:
    """Empty for an ecosystem no producer reads, None when the ecosystem is unknown."""
    for kind in ((ecosystem or "").lower(), get_purl_type(purl)):
        if kind in _ECOSYSTEM_TO_CALLGRAPH_LANGUAGES:
            return _ECOSYSTEM_TO_CALLGRAPH_LANGUAGES[kind]
    return None


def component_language_map(deps: Iterable[Mapping[str, Any]]) -> dict[str, list[tuple[str, frozenset[str], bool]]]:
    """Vulnerability findings carry no purl, so the fail-closed gate reads the ecosystem off the inventory."""
    out: dict[str, dict[tuple[str, frozenset[str]], bool]] = {}
    for dep in deps:
        name = dep.get("name")
        if not name:
            continue
        langs = _ecosystem_languages(dep.get("type"), dep.get("purl"))
        if langs is not None:
            key = (str(dep.get("version") or ""), langs)
            transitive = dep.get("direct") is False and dep.get("direct_inferred") is False
            candidates = out.setdefault(name, {})
            candidates[key] = candidates.get(key, False) or transitive
    # Findings carry the qualified component while the inventory keeps the bare name.
    return build_component_index(
        {name: [(*key, transitive) for key, transitive in candidates.items()] for name, candidates in out.items()}
    )


async def build_component_language_map(
    db: AsyncIOMotorDatabase, scan_id: str
) -> dict[str, list[tuple[str, frozenset[str], bool]]]:
    projection = {"name": 1, "version": 1, "type": 1, "purl": 1, "direct": 1, "direct_inferred": 1}
    deps = await db.dependencies.find({"scan_id": scan_id}, projection).to_list(None)
    return component_language_map(deps)


def _candidate_languages(
    component_languages: ComponentLanguages, component: str, version: str | None
) -> tuple[list[frozenset[str]], bool]:
    candidates = lookup_component(component_languages, component) or []
    matching = [candidate for candidate in candidates if candidate[0] == version] or candidates
    return list(dict.fromkeys(langs for _, langs, _ in matching)), any(transitive for *_, transitive in matching)


@dataclass(frozen=True)
class _PreparedCallgraph:
    language: str
    usage_index: dict[str, Any]
    analyzed_index: dict[str, bool]


def _with_enclosing_packages(module_usage: dict[str, Any]) -> dict[str, Any]:
    """Unresolved from-imports name the module path, so each submodule counts for every enclosing package."""
    locations: dict[str, dict[str, None]] = {}
    symbols: dict[str, dict[str, None]] = {}
    calls: dict[str, int] = {}
    for key, usage in module_usage.items():
        parts = key.split(".")
        for depth in range(1, len(parts) + 1):
            target = ".".join(parts[:depth])
            locations.setdefault(target, {}).update(dict.fromkeys(usage.get("import_locations") or []))
            symbols.setdefault(target, {}).update(dict.fromkeys(usage.get("used_symbols") or []))
            calls[target] = calls.get(target, 0) + (usage.get("call_count") or 0)
    return {
        key: {
            **module_usage.get(key, {}),
            "import_locations": list(found),
            "used_symbols": list(symbols[key]),
            "call_count": calls[key],
        }
        for key, found in locations.items()
    }


def _prepare_callgraph(callgraph: CallgraphMinimal) -> _PreparedCallgraph:
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
    normalized = _normalize_component(component, prepared.language)
    return lookup_component(prepared.usage_index, component) or lookup_component(prepared.usage_index, normalized)


def _lists_package(prepared: _PreparedCallgraph, component: str) -> bool:
    normalized = _normalize_component(component, prepared.language)
    return bool(
        lookup_component(prepared.analyzed_index, component) or lookup_component(prepared.analyzed_index, normalized)
    )


def _falsifying_languages(
    component: str, prepared_graphs: list[_PreparedCallgraph], language_sets: list[frozenset[str]]
) -> list[str]:
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
    """bool is no confidence: True would pass as a perfect 1.0."""
    return (
        is_reachable is True
        and isinstance(confidence, (int, float))
        and not isinstance(confidence, bool)
        and confidence >= REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
    )


async def fetch_callgraphs(
    project_id: str,
    scan_id: str,
    db: AsyncIOMotorDatabase,
) -> list[CallgraphMinimal]:
    callgraph_repo = CallgraphRepository(db)
    scan_repo = ScanRepository(db)
    # Bounded, so a cyclic rescan pointer cannot hang the analysis.
    for _hop in range(MAX_RESCAN_HOPS + 1):
        if callgraphs := await callgraph_repo.find_all_minimal_by_scan(project_id, scan_id):
            return callgraphs
        scan = await scan_repo.get_minimal_by_id(scan_id)
        if not scan or not scan.original_scan_id:
            break
        scan_id = scan.original_scan_id
    else:
        return []
    if scan and scan.pipeline_id:
        return await callgraph_repo.find_all_minimal_by_pipeline(project_id, scan.pipeline_id)
    return []


def store_reachability(finding: dict[str, Any], verdict: ReachabilityInfo) -> None:
    """Mirrored to the top level, which the stats fold and the chat tools read."""
    reachability = verdict.model_dump(exclude_unset=True)
    finding.setdefault("details", {})["reachability"] = reachability
    finding["reachable"] = verdict.is_reachable
    finding["reachability_level"] = verdict.analysis_level
    finding["reachable_functions"] = verdict.matched_symbols
    _apply_adjusted_risk_score(finding, reachability)


def reachability_set_fields(finding: dict[str, Any]) -> dict[str, Any]:
    details = finding["details"]
    fields = {key: finding[key] for key in ("reachable", "reachability_level", "reachable_functions")}
    fields.update({f"details.{key}": details[key] for key in ("reachability", "adjusted_risk_score") if key in details})
    return fields


def _unknown_verdict(
    component: str,
    prepared_graphs: list[_PreparedCallgraph],
    language_sets: list[frozenset[str]],
    transitive: bool,
) -> str:
    if not any(language_sets):
        return f"Package '{component}' is in an ecosystem no callgraph tool supports; reachability unknown."

    uncovered = next(
        (langs for langs in language_sets if langs and not any(p.language in langs for p in prepared_graphs)), None
    )
    if uncovered is not None:
        analyzed = ", ".join(p.language for p in prepared_graphs) or "none"
        return (
            f"No {'/'.join(sorted(uncovered))} callgraph was uploaded for this scan "
            f"(analyzed: {analyzed}); reachability unknown."
        )

    covering = [p for p in prepared_graphs if any(p.language in langs for langs in language_sets)]
    covering_langs = ", ".join(p.language for p in covering)
    if all(not p.analyzed_index for p in covering):
        return (
            f"Package '{component}' is absent from the {covering_langs} callgraph(s), "
            "which published no coverage universe; reachability unknown."
        )
    if any(p.language in _NON_FALSIFYING_LANGUAGES and _lists_package(p, component) for p in covering):
        return (
            f"Package '{component}' was analyzed but is not imported ({covering_langs}); this callgraph "
            "cannot see reflective loading, so its absence is no evidence; reachability unknown."
        )
    if transitive:
        return (
            f"Package '{component}' is a transitive dependency, which first-party code need not import; "
            "reachability unknown."
        )
    return (
        f"Package '{component}' is outside the coverage universe resolved by the "
        f"{covering_langs} callgraph(s); reachability unknown."
    )


def _enrich_finding_from_callgraphs(
    finding: dict[str, Any],
    prepared_graphs: list[_PreparedCallgraph],
    component_languages: ComponentLanguages,
) -> None:
    component = finding["component"]
    language_sets, transitive = _candidate_languages(component_languages, component, finding.get("version"))
    graphs = [p for p in prepared_graphs if not language_sets or any(p.language in langs for langs in language_sets)]
    usages = [usage for prepared in graphs if (usage := _find_usage(prepared, component)) is not None]
    if usages:
        store_reachability(finding, _analyze_reachability(finding, usages))
        return

    falsifying = [] if transitive else _falsifying_languages(component, prepared_graphs, language_sets)
    if falsifying:
        verdict = ReachabilityInfo(
            is_reachable=False,
            confidence_score=REACHABILITY_CONFIDENCE_NOT_USED,
            analysis_level=REACHABILITY_LEVEL_IMPORT,
            matched_symbols=[],
            import_locations=[],
            message=(
                f"Package '{component}' was analyzed but is not imported in any source file ({', '.join(falsifying)})."
            ),
        )
    else:
        verdict = ReachabilityInfo(
            is_reachable=None,
            confidence_score=0.0,
            analysis_level=REACHABILITY_LEVEL_NONE,
            matched_symbols=[],
            import_locations=[],
            message=_unknown_verdict(component, prepared_graphs, language_sets, transitive),
        )
    store_reachability(finding, verdict)


def enrich_findings_with_reachability(
    findings: list[dict[str, Any]],
    callgraphs: Sequence[CallgraphMinimal],
    component_languages: ComponentLanguages,
) -> int:
    """Mutates the findings in place."""
    prepared_graphs = [_prepare_callgraph(cg) for cg in callgraphs]
    logger.debug(f"Found {len(callgraphs)} callgraph(s): {[p.language for p in prepared_graphs]}")
    targets = [f for f in findings if f.get("type") == "vulnerability" and f.get("component")]
    for finding in targets:
        _enrich_finding_from_callgraphs(finding, prepared_graphs, component_languages)
    return len(targets)


# Evidence samples kept on the finding document; the sibling *_count fields carry the totals.
_IMPORT_LOCATION_SAMPLE = 10
_VULNERABLE_SYMBOL_SAMPLE = 10
_MESSAGE_SYMBOL_SAMPLE = 5


def _analyze_reachability(finding: dict[str, Any], usages: list[Mapping[str, Any]]) -> ReachabilityInfo:
    locations = sorted({location for usage in usages for location in usage.get("import_locations") or []})
    used_symbols = list(dict.fromkeys(symbol for usage in usages for symbol in usage.get("used_symbols") or []))
    call_count = sum(usage.get("call_count") or 0 for usage in usages)
    import_count = len(locations)
    evidence = (
        f"imported in {import_count} file(s)"
        if import_count or not call_count
        else f"called through {call_count} call edge(s)"
    )

    vulnerable_symbols = get_symbols_for_finding(finding)
    matched_symbols = _match_symbols(vulnerable_symbols, used_symbols)
    if not vulnerable_symbols:
        confidence = REACHABILITY_CONFIDENCE_IMPORTED_NO_SYMBOLS
        message = f"Package is {evidence}. Could not determine specific vulnerable functions."
    elif matched_symbols:
        confidence = REACHABILITY_CONFIDENCE_SYMBOL_MATCHED
        message = (
            f"Vulnerable function(s) {name_some(matched_symbols, _MESSAGE_SYMBOL_SAMPLE)} are used in the codebase."
        )
    elif used_symbols:
        confidence = REACHABILITY_CONFIDENCE_SYMBOLS_NOT_USED
        message = (
            f"Package is {evidence} but extracted vulnerable functions "
            f"({name_some(vulnerable_symbols, _MESSAGE_SYMBOL_SAMPLE)}) were not found in direct usage. "
            "May still be reachable through indirect calls."
        )
    else:
        confidence = REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO
        message = f"Package is {evidence}. Symbol-level analysis not available."

    return ReachabilityInfo(
        is_reachable=True,
        confidence_score=confidence,
        analysis_level=REACHABILITY_LEVEL_SYMBOL if matched_symbols else REACHABILITY_LEVEL_IMPORT,
        matched_symbols=matched_symbols,
        import_locations=locations[:_IMPORT_LOCATION_SAMPLE],
        import_location_count=import_count,
        vulnerable_symbols=vulnerable_symbols[:_VULNERABLE_SYMBOL_SAMPLE],
        vulnerable_symbol_count=len(vulnerable_symbols),
        message=message,
    )


def _normalize_component(component: str, language: str) -> str:
    """Only the version suffix is stripped here: findings carry it (pkg@1.0.0), callgraph module names never do."""
    if not component:
        return component

    if "@" in component and not component.startswith("@"):
        component = component.rsplit("@", 1)[0]

    return canonical_module_key(component, language)


def _match_symbols(vulnerable_symbols: list[str], used_symbols: list[str]) -> list[str]:
    if not vulnerable_symbols or not used_symbols:
        return []

    matched = []
    vuln_lower = {s.lower() for s in vulnerable_symbols}

    for used in used_symbols:
        used_lower = used.lower()

        if used_lower in vuln_lower:
            matched.append(used)
            continue

        # A real symbol boundary, not any substring, so "get" in "getUser" cannot promote a finding.
        for vuln in vulnerable_symbols:
            vuln_l = vuln.lower()
            if used_lower.endswith("." + vuln_l) or vuln_l.endswith("." + used_lower):
                matched.append(used)
                break

    return matched


# The vulnerability lists are UI samples; reachable_total / unreachable_total carry the real counts.
_VULNERABILITY_SAMPLE_CAP = 30


def build_reachability_summary(
    findings: list[dict[str, Any]],
    callgraphs: Sequence[CallgraphMinimal],
) -> ReachabilitySummary:
    reachability_levels: ReachabilityLevelCounts = {
        "confirmed": 0,
        "likely": 0,
        "unknown": 0,
        "unreachable": 0,
    }

    callgraph_info: list[CallgraphInfo] = [
        {
            "language": cg.language or "unknown",
            "total_modules": len(cg.module_usage or {}),
            "total_imports": cg.total_imports,
            "coverage_modules": len(cg.analyzed_modules),
            "generated_at": cg.created_at.isoformat() if cg.created_at else None,
        }
        for cg in callgraphs
    ]

    summary: ReachabilitySummary = {
        "total_vulnerabilities": len(findings),
        "analyzed": 0,
        "reachability_levels": reachability_levels,
        "callgraph_info": callgraph_info,
        "languages": [info["language"] for info in callgraph_info],
        "reachable_total": 0,
        "unreachable_total": 0,
        "reachable_vulnerabilities": [],
        "unreachable_vulnerabilities": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    for finding in findings:
        reachability_data = finding.get("details", {}).get("reachability", {})
        reachable = reachability_data.get("is_reachable")
        tier = reachability_display_tier(reachable, reachability_data.get("analysis_level"))

        vuln_info: VulnerabilityInfo = {
            "cve": display_vulnerability_id(finding.get("details")) or "",
            "component": finding.get("component", ""),
            "version": finding.get("version") or "",
            "severity": finding.get("severity", "unknown"),
            "reachability_level": tier,
            "reachable_functions": reachability_data.get("matched_symbols", [])[:5],
            "is_high_confidence": is_high_confidence_reachable(reachable, reachability_data.get("confidence_score")),
        }

        reachability_counts = cast(dict[str, int], summary["reachability_levels"])
        if tier in reachability_counts:
            reachability_counts[tier] += 1

        if reachable is True:
            summary["reachable_vulnerabilities"].append(vuln_info)
        elif reachable is False:
            summary["unreachable_vulnerabilities"].append(vuln_info)

    summary["reachable_total"] = len(summary["reachable_vulnerabilities"])
    summary["unreachable_total"] = len(summary["unreachable_vulnerabilities"])
    summary["analyzed"] = summary["reachable_total"] + summary["unreachable_total"]

    for sample in ("reachable_vulnerabilities", "unreachable_vulnerabilities"):
        summary[sample] = sort_by_severity(summary[sample])[:_VULNERABILITY_SAMPLE_CAP]

    return summary


async def apply_reachability(
    db: AsyncIOMotorDatabase,
    scan_id: str,
    findings: list[dict[str, Any]],
    callgraphs: Sequence[CallgraphMinimal],
) -> tuple[ComponentLanguages, int]:
    component_languages = await build_component_language_map(db, scan_id)
    enriched = enrich_findings_with_reachability(findings, callgraphs, component_languages)
    summary = build_reachability_summary(findings, callgraphs)
    await AnalysisResultRepository(db).save_result(scan_id, "reachability", summary)
    analysis_enrichment_total.labels(type="reachability").inc(enriched)
    for finding in findings:
        reachability = finding.get("details", {}).get("reachability") or {}
        if reachability.get("is_reachable") is True:
            level = reachability.get("analysis_level") or "unknown"
            analysis_reachable_vulnerabilities_total.labels(reachability_level=level).inc()
    logger.info(f"[reachability] Enriched {enriched} findings for scan {scan_id}")
    return component_languages, enriched
