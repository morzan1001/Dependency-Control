"""Stateless ad-hoc analysis: the analysis pipeline without a scan, a project or a write."""

import logging
from dataclasses import dataclass
from typing import Any

from app.core.cache import suppress_cache_writes
from app.core.constants import get_severity_value
from app.models.match_signature import MatchSignature
from app.models.system import SystemSettings
from app.models.waiver import Waiver
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse, AnalyzerReport
from app.schemas.projections import CallgraphMinimal
from app.schemas.sbom import ParsedSBOM
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _build_settings_resolver
from app.services.analysis.registry import CRYPTO_ANALYZERS, analyzers, post_processors
from app.services.analysis.stats import build_epss_kev_summary, build_reachability_summary
from app.services.analysis.types import Database
from app.services.analyzers import Analyzer
from app.services.enrichment.service import VulnerabilityEnrichmentService
from app.services.reachability_enrichment import (
    _PreparedCallgraph,
    _prepare_callgraph,
    component_language_map,
    enrich_findings_from_callgraphs,
)
from app.services.sbom_parser import parse_sbom

logger = logging.getLogger(__name__)

_UNKNOWN_ANALYZER = "unknown analyzer"
_EMPTY_PAYLOAD = "empty payload"
_ENRICHMENT = "epss_kev"
_REACHABILITY = "reachability"
_VULNERABILITY = "vulnerability"
_NO_COMPONENTS = "no components could be parsed (detected format: {sbom_format})"
_DROPPED_COMPONENTS = "{count} component(s) dropped by the parser ({reasons})"

# Counted as skipped from the dependency graph by design: a crypto asset is routed into
# ``crypto_assets`` and the rest are not dependencies. Nothing the caller posted was lost.
_DELIBERATE_SKIP_REASONS = frozenset({"cryptographic-asset", "file", "non-dependency", "root-component"})
_UNRECOGNISED_PAYLOAD = "unrecognised payload shape: expected {keys}"

# The top-level key each normalizer reads. A payload carrying none of them is a shape the
# pipeline cannot read, which must not be reported as coverage over zero findings.
_SCANNER_RESULT_KEYS: dict[str, tuple[str, ...]] = {
    "trufflehog": ("findings",),
    "opengrep": ("findings", "results"),
    "bearer": ("findings",),
    "kics": ("queries",),
}

# What a caller gets without naming an analyzer: an SBOM in, vulnerabilities and licence
# verdicts out, with no CLI process and one batched upstream call.
ADHOC_DEFAULT_ANALYZERS: tuple[str, ...] = ("osv", "license_compliance")

_NOT_REQUESTED = "not requested"
_UNCACHED_FANOUT = (
    "off by default: this path publishes nothing to the shared cache, so every run re-queries "
    "the upstream registry for each package it recognises"
)

ADHOC_SKIP_REASONS: dict[str, str] = {
    "trivy": "off by default: CLI scanner, may run up to 300 s",
    "grype": "off by default: CLI scanner, may run up to 600 s",
    "deps_dev": _UNCACHED_FANOUT,
    "outdated_packages": _UNCACHED_FANOUT,
    "hash_verification": _UNCACHED_FANOUT,
    "end_of_life": _UNCACHED_FANOUT,
    "maintainer_risk": _UNCACHED_FANOUT,
    "os_malware": _UNCACHED_FANOUT,
    "typosquatting": "off by default: downloads the PyPI top-packages list, which this path does not cache",
}

_CRYPTO_ANALYZER_REPLACED = (
    "replaced ad-hoc by the 'crypto_rules' stage: the registered analyzer reads stored crypto "
    "assets from the database, the stage evaluates the same rules against the posted CBOM"
)

_NO_CALLGRAPH = "no callgraph supplied"
_AUTO_FORMAT = "auto"
_UNDETECTABLE_FORMAT = "could not auto-detect the callgraph format"
_LANGUAGE_REQUIRED = "'language' is required for '{callgraph_format}' callgraph payloads"
_UNSUPPORTED_FORMAT = "unsupported callgraph format: {callgraph_format}"
# The one format that names its own language: madge only ever runs over a JS/TS tree.
_MADGE_FORMAT = "madge"
_MADGE_LANGUAGE = "javascript"
# Identifies the graph within this request only; nothing here is stored or looked up by it.
_POSTED_CALLGRAPH_ID = "posted"

_WAIVERS_GLOBAL = "global"
_WAIVERS_NONE = "none"
# Only instance-precise waivers are honoured: file and rule scope expand through a Mongo
# regex over ``finding_id`` that has no in-memory counterpart.
_SCOPE_FINDING = "finding"
# The waiver UI stores this in place of a field the user left unset.
_UNCONSTRAINED_WAIVER_VALUE = "Unknown"

# Waiver field -> record field, mirroring the query the scan-backed path builds.
_WAIVER_FIELD_MAP: tuple[tuple[str, str], ...] = (
    ("finding_id", "finding_id"),
    ("package_name", "component"),
    ("package_version", "version"),
    ("finding_type", "type"),
)
# A vulnerability waiver narrows documents but never by type: the advisory it names only
# ever lives in a vulnerability document, whatever ``finding_type`` the waiver carries.
_VULNERABILITY_SCOPE_FIELDS = tuple(pair for pair in _WAIVER_FIELD_MAP if pair[0] != "finding_type")


@dataclass(frozen=True)
class _ParsedInput:
    """One posted SBOM alongside the pre-parsed components the analyzers consume."""

    # 1-based position in the request, so a finding's source names the SBOM the caller sent
    # even when an earlier one was skipped.
    position: int
    sbom: dict[str, Any]
    parsed: ParsedSBOM
    components: list[dict[str, Any]]


def _sbom_source(sbom: dict[str, Any], fallback: str) -> str:
    metadata = sbom.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        # An explicit ``"name": null`` is a present key, so a dict default would never fire.
        name = metadata["component"].get("name")
        if name:
            return str(name)
    if sbom.get("serialNumber"):
        return str(sbom["serialNumber"])
    return fallback


def _record_ran(report: AnalyzerReport, name: str) -> None:
    if name not in report.ran and name not in report.errored:
        report.ran.append(name)


def _record_errored(report: AnalyzerReport, name: str, reason: str) -> None:
    """A failure on one input shadows a success on another: partial coverage must not read as complete."""
    report.errored.setdefault(name, []).append(reason)
    if name in report.ran:
        report.ran.remove(name)


async def _run_one_analyzer(
    name: str,
    analyzer: Analyzer,
    sbom: dict[str, Any],
    settings: dict[str, Any],
    parsed_components: list[dict[str, Any]] | None,
    aggregator: ResultAggregator,
    report: AnalyzerReport,
    fallback_source: str,
) -> None:
    """Run one analyzer and record its outcome.

    A failure lands in ``report.errored`` and is never aggregated: the aggregator turns
    every ``{"error": ...}`` into a HIGH SYSTEM_WARNING finding, which would read as a
    real defect instead of as missing coverage.
    """
    try:
        result = await analyzer.analyze(sbom, settings=settings, parsed_components=parsed_components)
        # The aggregator guards on membership, not truthiness, so ``{"error": ""}`` would reach it.
        if "error" in result:
            _record_errored(report, name, f"{fallback_source}: {result['error']}")
            return
        aggregator.aggregate(name, result, source=_sbom_source(sbom, fallback_source))
    except Exception as exc:
        logger.warning("adhoc: analyzer %s failed: %s", name, exc)
        # Attributed to the input, so "failed on one of ten" is distinguishable from "failed on ten".
        _record_errored(report, name, f"{fallback_source}: {exc}")
        return

    _record_ran(report, name)


def _aggregate_posted_scanners(
    request: AdhocAnalyzeRequest,
    aggregator: ResultAggregator,
    report: AnalyzerReport,
) -> None:
    """Normalise caller-posted scanner output.

    The normalizers were written for trusted first-party output and dereference list elements
    without type checks, so a scanner version that reshapes its report must land in
    ``report.errored`` rather than abort the request.
    """
    if request.scanners is None:
        return
    for name, payload in request.scanners.model_dump(exclude_none=True).items():
        if not payload:
            report.skipped[name] = _EMPTY_PAYLOAD
            continue
        if "error" in payload:
            _record_errored(report, name, str(payload["error"]))
            continue
        expected_keys = _SCANNER_RESULT_KEYS[name]
        if not any(key in payload for key in expected_keys):
            quoted = " or ".join(f"'{key}'" for key in expected_keys)
            _record_errored(report, name, _UNRECOGNISED_PAYLOAD.format(keys=quoted))
            continue
        try:
            aggregator.aggregate(name, payload, source=f"posted:{name}")
        except Exception as exc:
            logger.warning("adhoc: posted %s output could not be normalised: %s", name, exc)
            _record_errored(report, name, str(exc))
            continue
        _record_ran(report, name)


def _yielded_nothing(parsed: ParsedSBOM) -> bool:
    return not parsed.dependencies and not parsed.crypto_assets


def _input_defects(parsed: ParsedSBOM) -> list[str]:
    """What the caller needs to know about an input the parser only partly understood."""
    defects: list[str] = []
    if _yielded_nothing(parsed):
        defects.append(_NO_COMPONENTS.format(sbom_format=parsed.format.value))
    lost = {
        reason: count
        for reason, count in parsed.skipped_reasons.items()
        if reason not in _DELIBERATE_SKIP_REASONS and count
    }
    if lost:
        reasons = ", ".join(f"{reason}={count}" for reason, count in sorted(lost.items()))
        defects.append(_DROPPED_COMPONENTS.format(count=sum(lost.values()), reasons=reasons))
    return defects


def _parse_sboms(request: AdhocAnalyzeRequest, report: AnalyzerReport) -> list[_ParsedInput]:
    """Parse every SBOM, reporting each defect the parser found.

    A document-level failure rejects that whole input rather than analysing what survived: the
    parser is shared with the scan pipeline, where a half-built dependency graph is worse than
    none. The caller gets the parser's own message and can fix the document and retry.
    """
    parsed_inputs: list[_ParsedInput] = []
    for index, sbom in enumerate(request.sboms):
        position = index + 1
        label = f"sbom#{position}"
        try:
            parsed = parse_sbom(sbom)
        except Exception as exc:
            logger.warning("adhoc: %s could not be parsed: %s", label, exc)
            report.skipped_inputs[label] = f"could not be parsed: {exc}"
            continue
        defects = _input_defects(parsed)
        if defects:
            report.skipped_inputs[label] = "; ".join(defects)
        # An input nothing could be read from must not be analysed into a clean bill of health.
        if _yielded_nothing(parsed):
            continue
        parsed_inputs.append(
            _ParsedInput(
                position=position,
                sbom=sbom,
                parsed=parsed,
                components=[dep.to_dict() for dep in parsed.dependencies],
            )
        )
    return parsed_inputs


def resolve_adhoc_analyzers(requested: list[str] | None, report: AnalyzerReport) -> list[str]:
    """Pick the analyzers to run and record a reason for every registered one left out."""
    selected = list(ADHOC_DEFAULT_ANALYZERS) if requested is None else list(requested)

    resolved: list[str] = []
    for name in selected:
        if name in post_processors:
            # Stages rather than selectable analyzers: they report their own outcome, so a
            # skip note here would contradict the same report.
            continue
        if name in CRYPTO_ANALYZERS:
            report.skipped[name] = _CRYPTO_ANALYZER_REPLACED
        elif name not in analyzers:
            report.skipped[name] = _UNKNOWN_ANALYZER
        else:
            resolved.append(name)

    for name in analyzers:
        if name in resolved or name in report.skipped:
            continue
        if name in CRYPTO_ANALYZERS:
            report.skipped[name] = _CRYPTO_ANALYZER_REPLACED
        else:
            report.skipped[name] = ADHOC_SKIP_REASONS.get(name, _NOT_REQUESTED)

    return resolved


async def _enrich_vulnerabilities(records: list[dict[str, Any]], report: AnalyzerReport) -> dict[str, Any]:
    """Add EPSS/KEV to the vulnerability records through a service private to this request.

    The module singleton carries a mutable GitHub token shared with background scans.
    """
    vulnerabilities = [record for record in records if record.get("type") == _VULNERABILITY]
    service = VulnerabilityEnrichmentService()
    try:
        await service.enrich_findings(vulnerabilities)
        _record_ran(report, _ENRICHMENT)
    except Exception as exc:
        logger.warning("adhoc: EPSS/KEV enrichment failed: %s", exc)
        _record_errored(report, _ENRICHMENT, str(exc))
    finally:
        await service.close()
    return dict(build_epss_kev_summary(vulnerabilities))


def _prepare_posted_callgraph(payload: dict[str, Any]) -> tuple[dict[str, Any], _PreparedCallgraph]:
    """Turn a posted callgraph into the same in-memory shape the stored one resolves to."""
    from app.api.v1.helpers.callgraph import detect_format, parse_generic_format, parse_madge_format

    raw_format = str(payload.get("format") or _AUTO_FORMAT)
    data = {key: value for key, value in payload.items() if key not in ("format", "language")}
    resolved_format = detect_format(data) if raw_format == _AUTO_FORMAT else raw_format
    if resolved_format == "unknown":
        raise ValueError(_UNDETECTABLE_FORMAT)

    language = payload.get("language") or (_MADGE_LANGUAGE if resolved_format == _MADGE_FORMAT else None)
    if not language:
        raise ValueError(_LANGUAGE_REQUIRED.format(callgraph_format=resolved_format))

    parser = {_MADGE_FORMAT: parse_madge_format, "generic": parse_generic_format}.get(resolved_format)
    if parser is None:
        raise ValueError(_UNSUPPORTED_FORMAT.format(callgraph_format=resolved_format))

    imports, _calls, module_usage, analyzed_modules = parser(data, str(language))
    # The model derives ``import_map`` from ``module_usage``, which is what the enrichment reads.
    minimal = CallgraphMinimal(
        id=_POSTED_CALLGRAPH_ID,
        module_usage={key: usage.model_dump() for key, usage in module_usage.items()},
        analyzed_modules=analyzed_modules,
        language=str(language),
    )
    as_dict = {
        "language": minimal.language,
        "module_usage": minimal.module_usage,
        "analyzed_modules": minimal.analyzed_modules,
        "total_imports": len(imports),
        "created_at": None,
    }
    return as_dict, _prepare_callgraph(minimal)


def _run_reachability(
    records: list[dict[str, Any]],
    callgraph_payload: dict[str, Any] | None,
    languages: dict[str, frozenset[str]],
    report: AnalyzerReport,
) -> dict[str, Any] | None:
    if callgraph_payload is None:
        report.skipped[_REACHABILITY] = _NO_CALLGRAPH
        return None

    try:
        callgraph_dict, prepared = _prepare_posted_callgraph(callgraph_payload)
    except Exception as exc:
        logger.warning("adhoc: callgraph could not be prepared: %s", exc)
        _record_errored(report, _REACHABILITY, str(exc))
        return None

    # The list holds the same dict objects as ``records``, so the mirroring store_reachability
    # does in place stays visible to every later stage.
    vulnerabilities = [record for record in records if record.get("type") == _VULNERABILITY]
    enriched = enrich_findings_from_callgraphs(vulnerabilities, [prepared], languages)
    _record_ran(report, _REACHABILITY)
    return dict(build_reachability_summary(vulnerabilities, [callgraph_dict], enriched))


def _waiver_criteria(waiver: Waiver, fields: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    """The record fields a waiver actually constrains, keyed as they appear on a record."""
    criteria: dict[str, Any] = {}
    for waiver_field, record_field in fields:
        value = getattr(waiver, waiver_field, None)
        if value and value != _UNCONSTRAINED_WAIVER_VALUE:
            criteria[record_field] = value
    return criteria


def _matches(record: dict[str, Any], criteria: dict[str, Any]) -> bool:
    return all(record.get(field) == value for field, value in criteria.items())


def _waive_matching_advisories(record: dict[str, Any], waiver: Waiver) -> None:
    """Waive the matching nested advisories, then roll the document level up from them."""
    entries = (record.get("details") or {}).get("vulnerabilities") or []
    hit = False
    for entry in entries:
        known_as = {entry.get("id"), entry.get("resolved_cve")} | set(entry.get("aliases") or [])
        if waiver.vulnerability_id in known_as:
            entry["waived"] = True
            entry["waiver_reason"] = waiver.reason
            hit = True
    if not hit:
        return
    # A fully waived document keeps the severity of its entries, so dropping the waiver
    # restores it; a partly waived one drops to the highest entry still live.
    live = [entry for entry in entries if not entry.get("waived")] or entries
    severity = max((entry.get("severity") for entry in live), key=get_severity_value)
    if severity:
        record["severity"] = severity
    if all(entry.get("waived") for entry in entries):
        record["waived"] = True
        record["waiver_reason"] = waiver.reason


def _apply_vulnerability_waiver(records: list[dict[str, Any]], waiver: Waiver) -> None:
    scope = _waiver_criteria(waiver, _VULNERABILITY_SCOPE_FIELDS)
    for record in records:
        if record.get("type") == _VULNERABILITY and _matches(record, scope):
            _waive_matching_advisories(record, waiver)


def _apply_field_waiver(records: list[dict[str, Any]], waiver: Waiver) -> None:
    criteria = _waiver_criteria(waiver, _WAIVER_FIELD_MAP)
    # A waiver that constrains nothing would blanket every finding the caller posted.
    if not criteria:
        return
    for record in records:
        if _matches(record, criteria):
            record["waived"] = True
            record["waiver_reason"] = waiver.reason


def _apply_signature_waivers(records: list[dict[str, Any]], waivers: list[Waiver]) -> None:
    """Bind location waivers to the findings they were taken from, re-anchoring across line drift."""
    from app.services.waivers.matching import MatchFinding, apply_waivers_to_findings

    # Keyed by position: a record's own id is not guaranteed unique across posted inputs.
    by_key = {str(index): record for index, record in enumerate(records)}
    located = [
        MatchFinding(id=key, sig=MatchSignature(**record["match"]))
        for key, record in by_key.items()
        if record.get("match")
    ]
    if not located:
        return

    reasons = {waiver.id: waiver.reason for waiver in waivers}
    application = apply_waivers_to_findings(located, waivers)
    for key, waiver_id in application.waived.items():
        by_key[key]["waived"] = True
        by_key[key]["waiver_reason"] = reasons.get(waiver_id)
    for key, waiver_id in application.lapsed.items():
        by_key[key]["waiver_lapsed"] = True
        by_key[key]["lapsed_waiver_id"] = waiver_id


def apply_global_waivers_in_memory(records: list[dict[str, Any]], waivers: list[Waiver]) -> int:
    """Apply global waivers to in-memory records; returns how many records end up waived."""
    signature_waivers: list[Waiver] = []
    for waiver in waivers:
        if (waiver.scope or _SCOPE_FINDING) != _SCOPE_FINDING:
            continue
        if waiver.match is not None:
            signature_waivers.append(waiver)
        elif waiver.vulnerability_id:
            _apply_vulnerability_waiver(records, waiver)
        else:
            _apply_field_waiver(records, waiver)

    _apply_signature_waivers(records, signature_waivers)
    return sum(1 for record in records if record.get("waived") is True)


async def run_adhoc_analysis(request: AdhocAnalyzeRequest, db: Database) -> AdhocAnalyzeResponse:
    """Analyze the posted SBOMs and scanner results in memory. Writes nothing.

    The analyzers cache through a Redis shared with the scan pipeline under keys built from the
    package names they are given, so this path reads that cache but publishes nothing into it.
    """
    with suppress_cache_writes():
        return await _analyze(request, db)


async def _analyze(request: AdhocAnalyzeRequest, db: Database) -> AdhocAnalyzeResponse:
    report = AnalyzerReport()
    aggregator = ResultAggregator()

    parsed_inputs = _parse_sboms(request, report)

    # Defaults, not the stored document: the settings dependency exposes an ``auto_init`` query
    # parameter that writes a ``system_settings`` document.
    license_policy = request.license_policy.model_dump() if request.license_policy else None
    settings_for = _build_settings_resolver(SystemSettings(), license_policy, None)

    requested = resolve_adhoc_analyzers(request.analyzers, report)

    for parsed_input in parsed_inputs:
        for name in requested:
            await _run_one_analyzer(
                name,
                analyzers[name],
                parsed_input.sbom,
                settings_for(name),
                parsed_input.components or None,
                aggregator,
                report,
                f"SBOM #{parsed_input.position}",
            )

    _aggregate_posted_scanners(request, aggregator, report)

    records = [finding.model_dump() for finding in aggregator.get_findings()]
    for record in records:
        # Findings are addressed by ``finding_id`` everywhere the scan-backed API exposes them.
        record["finding_id"] = record["id"]

    epss_kev_summary = await _enrich_vulnerabilities(records, report)

    languages = component_language_map([component for pi in parsed_inputs for component in pi.components])
    reachability_summary = _run_reachability(records, request.callgraph, languages, report)

    waived_count = 0
    waivers_applied = _WAIVERS_NONE
    if request.apply_global_waivers:
        from app.repositories import WaiverRepository

        waived_count = apply_global_waivers_in_memory(records, await WaiverRepository(db).find_active_global())
        waivers_applied = _WAIVERS_GLOBAL

    return AdhocAnalyzeResponse(
        findings=records,
        epss_kev_summary=epss_kev_summary,
        reachability_summary=reachability_summary,
        analyzers=report,
        waivers_applied=waivers_applied,
        waived_count=waived_count,
    )
