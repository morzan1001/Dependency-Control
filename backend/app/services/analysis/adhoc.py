"""Ad-hoc analysis: the analysis pipeline without a scan, a project or a write."""

import asyncio
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError

from app.core.cache import suppress_cache_writes
from app.core.constants import (
    DEPS_DEV_API_URL,
    EOL_API_URL,
    GITHUB_API_URL,
    MALWARE_API_URL,
    NPM_REGISTRY_URL,
    OSV_BATCH_API_URL,
    OSV_VULN_API_URL,
    PYPI_API_URL,
    TOP_PYPI_PACKAGES_URL,
)
from app.models.crypto_asset import CryptoAsset
from app.models.match_signature import MatchSignature
from app.models.system import SystemSettings
from app.models.waiver import Waiver
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse, AnalyzerReport
from app.schemas.bearer import BearerFinding
from app.schemas.crypto_policy import RULE_DRIVEN_FINDING_TYPES
from app.schemas.enrichment import VulnerabilityEnrichment
from app.schemas.kics import KicsQuery
from app.schemas.opengrep import OpenGrepFinding
from app.schemas.projections import CallgraphMinimal
from app.schemas.sbom import ParsedSBOM
from app.schemas.trufflehog import TruffleHogFinding
from app.services.aggregation import ResultAggregator, is_error_result
from app.services.aggregation.cross_link import refresh_vulnerability_info
from app.services.analysis.engine import _build_settings_resolver, _partial_result_reason, _sbom_source
from app.services.analysis.registry import CRYPTO_ANALYZERS, POST_PROCESSOR_ANALYZERS, analyzer_factories
from app.services.analysis.stats import build_epss_kev_summary, build_reachability_summary, compute_stats
from app.services.analysis.types import Database
from app.services.analyzers.base import Analyzer
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.analyzers.malware import MISSING_API_KEY
from app.services.component_identity import canonical_callgraph_language
from app.services.crypto_policy.seeder import load_seed_rules
from app.services.enrichment.service import sends_ids, vulnerability_enrichment_service
from app.services.reachability_enrichment import (
    ComponentLanguages,
    component_language_map,
    enrich_findings_with_reachability,
)
from app.services.recommendations import recommendation_engine
from app.services.sbom_parser import merge_duplicate_dependencies, parse_sbom
from app.services.waivers.matching import (
    MatchFinding,
    apply_waivers_to_findings,
    bind_legacy_signatures,
    record_matches,
    roll_up_advisories,
    route_waiver,
    waive_advisories,
    waiver_criteria,
)

logger = logging.getLogger(__name__)

_UNKNOWN_ANALYZER = "unknown analyzer"
_EMPTY_PAYLOAD = "empty payload"
_PARTIAL_COVERAGE = "partial coverage: {reason}"
_ENRICHMENT = "epss_kev"
_NO_ENRICHABLE_IDS = "no CVE or GHSA id to look up"
_REACHABILITY = "reachability"
_VULNERABILITY = "vulnerability"
_NO_COMPONENTS = "no components could be parsed (detected format: {sbom_format})"
_DROPPED_COMPONENTS = "{count} component(s) dropped by the parser ({reasons})"

# Counted as skipped from the dependency graph by design: a crypto asset is routed into
# ``crypto_assets`` once it parses, and the rest are not dependencies.
_CRYPTO_ASSET = "cryptographic-asset"
_DELIBERATE_SKIP_REASONS = frozenset({_CRYPTO_ASSET, "file", "non-dependency", "root-component"})
_UNRECOGNISED_PAYLOAD = "unrecognised payload shape: expected {keys}"

_BEARER = "bearer"

# The top-level keys each normalizer reads and the typed entry it reads under them. A payload
# missing every key, or carrying entries the model rejects, normalises to no finding or a
# placeholder one, and neither may be reported as coverage.
_POSTED_SCANNERS: dict[str, tuple[tuple[str, ...], type[BaseModel]]] = {
    "trufflehog": (("findings",), TruffleHogFinding),
    "opengrep": (("findings", "results"), OpenGrepFinding),
    _BEARER: (("findings",), BearerFinding),
    "kics": (("queries",), KicsQuery),
}
_UNREADABLE_ENTRIES = "{unreadable} of {total} '{key}' entries could not be read ({reason})"
_WHOLE_ENTRY = "entry"

_OSV = "osv"

# What a caller gets without naming an analyzer: an SBOM in, vulnerabilities and licence
# verdicts out, with no CLI process and one batched upstream call.
ADHOC_DEFAULT_ANALYZERS: tuple[str, ...] = (_OSV, "license_compliance")

_NOT_REQUESTED = "not requested"
_NO_PACKAGE_COMPONENTS = "no package components to analyse"
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

_SBOM_POSITION = "SBOM #{position}"

_CRYPTO_RULES = "crypto_rules"
_NO_CRYPTO_ASSETS = "no readable cryptographic-asset components in the SBOM"
# ``normalize_crypto`` rebuilds each dict into a Finding carrying its own type, so one dispatch
# key covers every crypto finding type the rules emit.
_CRYPTO_DISPATCH_KEY = "crypto_weak_algorithm"
# Names the assets within this request only; nothing here is stored or looked up by it.
_ADHOC_SCOPE = "adhoc"

_CRYPTO_ANALYZER_REPLACED = (
    "replaced ad-hoc by the 'crypto_rules' stage: the registered analyzer reads stored crypto "
    "assets from the database, the stage evaluates the seeded rules against the posted CBOM"
)
# The two crypto analyzers that grade against an external reference rather than a policy rule.
# Their coverage is genuinely absent here, so claiming the stage replaces them would be false.
_CRYPTO_ANALYZER_NO_EQUIVALENT: dict[str, str] = {
    "crypto_certificate_lifecycle": (
        "no ad-hoc equivalent: certificate lifecycle is graded against the wall clock by an "
        "analyzer reading stored assets, not by the rules the 'crypto_rules' stage evaluates"
    ),
    "crypto_protocol_cipher": (
        "no ad-hoc equivalent: cipher suites are graded against the IANA catalog by an "
        "analyzer reading stored assets, not by the rules the 'crypto_rules' stage evaluates"
    ),
}


def _hosts(*urls: str) -> str:
    """The distinct hosts behind the given endpoints, read off the constants the analyzers use
    so a note can never name somewhere the code no longer calls."""
    return ", ".join(dict.fromkeys(urlsplit(url).netloc for url in urls))


_COORDINATES_SENT = "package coordinates from the posted SBOMs are sent to {hosts}"

# What a stage that ran does not otherwise reveal. Keeping a result is not sending it, so
# every stage that puts something the caller posted on the wire is named here, and the crypto
# stage says it grades against the shipped seeds because it never reads this installation's policy.
_STAGE_NOTES: dict[str, str] = {
    _OSV: _COORDINATES_SENT.format(hosts=_hosts(OSV_BATCH_API_URL, OSV_VULN_API_URL)),
    "deps_dev": _COORDINATES_SENT.format(hosts=_hosts(DEPS_DEV_API_URL)),
    "outdated_packages": _COORDINATES_SENT.format(hosts=_hosts(DEPS_DEV_API_URL)),
    "end_of_life": _COORDINATES_SENT.format(hosts=_hosts(EOL_API_URL)),
    "hash_verification": _COORDINATES_SENT.format(hosts=_hosts(PYPI_API_URL, NPM_REGISTRY_URL)),
    "maintainer_risk": _COORDINATES_SENT.format(
        hosts=_hosts(PYPI_API_URL, NPM_REGISTRY_URL, DEPS_DEV_API_URL, GITHUB_API_URL)
    ),
    "os_malware": _COORDINATES_SENT.format(hosts=_hosts(MALWARE_API_URL)),
    # The odd one out: it downloads a list and matches against it here, so nothing posted leaves.
    "typosquatting": (
        f"the package list at {_hosts(TOP_PYPI_PACKAGES_URL)} is downloaded and matched in this "
        "process; no posted coordinate is sent"
    ),
    _ENRICHMENT: (
        f"vulnerability ids are sent to {_hosts(*vulnerability_enrichment_service.SENDS_IDS_TO)}; the CISA KEV "
        f"catalog is downloaded from {_hosts(*vulnerability_enrichment_service.DOWNLOADS_FROM)} and matched in "
        "this process"
    ),
    _CRYPTO_RULES: "graded against the shipped seed rules, not against this installation's crypto policy",
}

# Analyzers that put nothing the caller posted on the wire: the licence database ships with the
# image, and the two CLI scanners match the SBOM against a vulnerability database they fetch for
# themselves. Named rather than inferred so a new analyzer has to be placed on one side of the
# contract before it can quietly break it.
_SENDS_NOTHING: frozenset[str] = frozenset({"license_compliance", "trivy", "grype"})

_ADHOC_CRYPTO_RULES = tuple(r for r in load_seed_rules() if r.enabled and r.finding_type in RULE_DRIVEN_FINDING_TYPES)

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


def _posted_entries(name: str, payload: dict[str, Any], key: str) -> list[Any] | None:
    """The entry list under `key`, or None when the payload carries no readable list there.

    Bearer groups its findings under a severity key, so the normalizer's own flattening has to
    be mirrored here or its entries would be neither counted nor validated."""
    container = payload.get(key)
    if isinstance(container, list):
        return container
    if name == _BEARER and isinstance(container, dict):
        return [entry for items in container.values() if isinstance(items, list) for entry in items]
    return None


@dataclass(frozen=True)
class _ParsedInput:
    """One posted SBOM alongside the pre-parsed components the analyzers consume."""

    # 1-based position in the request, so a finding's source names the SBOM the caller sent
    # even when an earlier one was skipped.
    position: int
    sbom: dict[str, Any]
    parsed: ParsedSBOM
    components: list[dict[str, Any]]


def _input_label(parsed_input: _ParsedInput) -> str:
    return _SBOM_POSITION.format(position=parsed_input.position)


def _record_ran(report: AnalyzerReport, name: str) -> None:
    report.skipped.pop(name, None)
    if name not in report.ran and name not in report.errored:
        report.ran.append(name)


def _record_errored(report: AnalyzerReport, name: str, reason: str) -> None:
    """A failure on one input shadows a success on another: partial coverage must not read as complete."""
    report.skipped.pop(name, None)
    report.errored.setdefault(name, []).append(reason)
    if name in report.ran:
        report.ran.remove(name)


async def _run_one_analyzer(
    name: str,
    analyzer: Analyzer,
    sbom: dict[str, Any],
    settings: dict[str, Any],
    parsed_components: list[dict[str, Any]],
    aggregator: ResultAggregator,
    report: AnalyzerReport,
    fallback_source: str,
) -> None:
    """Run one analyzer and record its outcome.

    A failure and a coverage gap both land in ``report.errored`` and neither is ever aggregated:
    the aggregator turns every ``{"error": ...}`` into a HIGH SYSTEM_WARNING finding, which would
    read as a real defect instead of as missing coverage.
    """
    try:
        result = await analyzer.analyze(sbom, settings=settings, parsed_components=parsed_components)
        if is_error_result(result):
            _record_errored(report, name, f"{fallback_source}: {result['error']}")
            return
        aggregator.aggregate(name, result, source=_sbom_source(sbom) or fallback_source)
    except Exception as exc:
        logger.warning("adhoc: analyzer %s failed: %s", name, exc)
        # Attributed to the input, so "failed on one of ten" is distinguishable from "failed on ten".
        _record_errored(report, name, f"{fallback_source}: {exc}")
        return

    # What the analyzer did find is kept; what it could not reach is a gap, and an unreachable
    # CVE source must not answer a Log4Shell SBOM with an empty finding list and no reason.
    partial = _partial_result_reason(result)
    if partial:
        logger.warning("adhoc: analyzer %s returned partial coverage: %s", name, partial)
        _record_errored(report, name, f"{fallback_source}: {_PARTIAL_COVERAGE.format(reason=partial)}")
        return

    _record_ran(report, name)


def _aggregate_atomically(aggregator: ResultAggregator, name: str, payload: dict[str, Any], source: str) -> None:
    """Dry-run on a scratch aggregator: normalizers add item by item, so a half-read payload adds nothing."""
    ResultAggregator().aggregate(name, payload, source=source)
    aggregator.aggregate(name, payload, source=source)


def _first_reason(exc: ValidationError) -> str:
    error = exc.errors()[0]
    field = ".".join(str(part) for part in error["loc"])
    return f"{field or _WHOLE_ENTRY}: {error['msg']}"


def _entry_shortfall(name: str, payload: dict[str, Any]) -> str | None:
    """Why the normalizer cannot read the posted entries, or None when it can read them all.

    The container being the right shape says nothing about the entries in it: 200 kics queries
    carrying no ``files`` normalise to zero findings, which is an all-clear the run never earned.
    """
    keys, model = _POSTED_SCANNERS[name]
    for key in keys:
        entries = _posted_entries(name, payload, key)
        if not entries:
            continue
        unreadable = 0
        first_reason = ""
        for entry in entries:
            try:
                model.model_validate(entry)
            except ValidationError as exc:
                unreadable += 1
                first_reason = first_reason or _first_reason(exc)
        if not unreadable:
            return None
        return _UNREADABLE_ENTRIES.format(unreadable=unreadable, total=len(entries), key=key, reason=first_reason)
    return None


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
        if is_error_result(payload):
            _record_errored(report, name, str(payload["error"]))
            continue
        expected_keys = _POSTED_SCANNERS[name][0]
        if all(_posted_entries(name, payload, key) is None for key in expected_keys):
            quoted = " or ".join(f"'{key}'" for key in expected_keys)
            _record_errored(report, name, _UNRECOGNISED_PAYLOAD.format(keys=quoted))
            continue
        shortfall = _entry_shortfall(name, payload)
        if shortfall:
            logger.warning("adhoc: posted %s output: %s", name, shortfall)
            _record_errored(report, name, shortfall)
            continue
        try:
            _aggregate_atomically(aggregator, name, payload, f"posted:{name}")
        except Exception as exc:
            logger.warning("adhoc: posted %s output could not be normalised: %s", name, exc)
            _record_errored(report, name, str(exc))
            continue
        _record_ran(report, name)


def _input_defects(parsed: ParsedSBOM) -> list[str]:
    """What the caller needs to know about an input the parser only partly understood."""
    defects: list[str] = []
    if not parsed.dependencies and not parsed.crypto_assets:
        defects.append(_NO_COMPONENTS.format(sbom_format=parsed.format.value))
    lost = {
        reason: count
        for reason, count in parsed.skipped_reasons.items()
        if reason not in _DELIBERATE_SKIP_REASONS and count
    }
    unread_crypto = parsed.skipped_reasons.get(_CRYPTO_ASSET, 0) - len(parsed.crypto_assets)
    if unread_crypto > 0:
        lost[_CRYPTO_ASSET] = unread_crypto
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
        label = _SBOM_POSITION.format(position=position)
        try:
            parsed = parse_sbom(sbom)
        except Exception as exc:
            logger.warning("adhoc: %s could not be parsed: %s", label, exc)
            report.skipped_inputs[label] = f"could not be parsed: {exc}"
            continue
        defects = _input_defects(parsed)
        if defects:
            report.skipped_inputs[label] = "; ".join(defects)
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
    selected = list(ADHOC_DEFAULT_ANALYZERS) if requested is None else list(dict.fromkeys(requested))

    resolved: list[str] = []
    for name in selected:
        if name in POST_PROCESSOR_ANALYZERS or name in CRYPTO_ANALYZERS:
            # Post-processors are stages that report their own outcome; every crypto name gets its note below.
            continue
        if name not in analyzer_factories:
            report.skipped[name] = _UNKNOWN_ANALYZER
        else:
            resolved.append(name)

    for name in analyzer_factories:
        if name not in resolved and name not in report.skipped:
            report.skipped[name] = ADHOC_SKIP_REASONS.get(name, _NOT_REQUESTED)
    for name in sorted(CRYPTO_ANALYZERS):
        report.skipped.setdefault(name, _CRYPTO_ANALYZER_NO_EQUIVALENT.get(name, _CRYPTO_ANALYZER_REPLACED))

    return resolved


def _aggregate_crypto_rules(
    parsed_inputs: list[_ParsedInput], aggregator: ResultAggregator, report: AnalyzerReport
) -> None:
    """Evaluate the rule-driven crypto policy against each SBOM's embedded CBOM components.

    The registered crypto analyzers read their assets back from ``crypto_assets``, which does not
    exist here; the rules themselves are pure. The rules are the shipped defaults, for the same
    reason the analyzers get a default ``SystemSettings``.
    """
    if not any(parsed_input.parsed.crypto_assets for parsed_input in parsed_inputs):
        report.skipped[_CRYPTO_RULES] = _NO_CRYPTO_ASSETS
        return

    for parsed_input in parsed_inputs:
        assets = [
            CryptoAsset(project_id=_ADHOC_SCOPE, scan_id=_ADHOC_SCOPE, **asset.model_dump())
            for asset in parsed_input.parsed.crypto_assets
        ]
        findings = crypto_findings_for_assets(assets, _ADHOC_CRYPTO_RULES, scanner=_CRYPTO_RULES)
        if findings:
            aggregator.aggregate(
                _CRYPTO_DISPATCH_KEY,
                {"findings": findings},
                source=_sbom_source(parsed_input.sbom) or _input_label(parsed_input),
            )
    _record_ran(report, _CRYPTO_RULES)


async def _enrich_vulnerabilities(
    records: list[dict[str, Any]], report: AnalyzerReport
) -> tuple[dict[str, Any], dict[str, VulnerabilityEnrichment]]:
    """Add EPSS/KEV to the vulnerability records; returns the EPSS/KEV summary and the per-CVE enrichment."""
    vulnerabilities = [record for record in records if record.get("type") == _VULNERABILITY]
    threat_intel: dict[str, VulnerabilityEnrichment] = {}
    sends = sends_ids(vulnerabilities)
    try:
        threat_intel, unavailable = await vulnerability_enrichment_service.enrich_findings(vulnerabilities)
    except Exception as exc:
        logger.warning("adhoc: EPSS/KEV enrichment failed: %s", exc)
        _record_errored(report, _ENRICHMENT, str(exc))
    else:
        if unavailable:
            _record_errored(report, _ENRICHMENT, f"{' and '.join(unavailable)} unavailable")
        elif sends:
            _record_ran(report, _ENRICHMENT)
        else:
            report.skipped[_ENRICHMENT] = _NO_ENRICHABLE_IDS
    refresh_vulnerability_info(records)
    return dict(build_epss_kev_summary(vulnerabilities)), threat_intel


def _prepare_posted_callgraph(payload: dict[str, Any]) -> CallgraphMinimal:
    """Turn a posted callgraph into the same in-memory shape the stored one resolves to."""
    from app.api.v1.helpers.callgraph import detect_format, parse_generic_format, parse_madge_format

    raw_format = str(payload.get("format") or _AUTO_FORMAT)
    data = {key: value for key, value in payload.items() if key not in ("format", "language")}
    resolved_format = detect_format(data) if raw_format == _AUTO_FORMAT else raw_format
    if resolved_format == "unknown":
        raise ValueError(_UNDETECTABLE_FORMAT)

    raw_language = payload.get("language") or (_MADGE_LANGUAGE if resolved_format == _MADGE_FORMAT else None)
    if not raw_language:
        raise ValueError(_LANGUAGE_REQUIRED.format(callgraph_format=resolved_format))
    language = canonical_callgraph_language(str(raw_language))

    parser = {_MADGE_FORMAT: parse_madge_format, "generic": parse_generic_format}.get(resolved_format)
    if parser is None:
        raise ValueError(_UNSUPPORTED_FORMAT.format(callgraph_format=resolved_format))

    parsed = parser(data, language)
    return CallgraphMinimal(
        id=_POSTED_CALLGRAPH_ID,
        module_usage={key: usage.model_dump() for key, usage in parsed.module_usage.items()},
        analyzed_modules=parsed.analyzed_modules,
        language=language,
        total_imports=parsed.total_imports,
    )


def _run_reachability(
    records: list[dict[str, Any]],
    callgraph_payload: dict[str, Any] | None,
    languages: ComponentLanguages,
    report: AnalyzerReport,
) -> dict[str, Any] | None:
    if callgraph_payload is None:
        report.skipped[_REACHABILITY] = _NO_CALLGRAPH
        return None

    try:
        callgraph = _prepare_posted_callgraph(callgraph_payload)
    except Exception as exc:
        logger.warning("adhoc: callgraph could not be prepared: %s", exc)
        _record_errored(report, _REACHABILITY, str(exc))
        return None

    # The list holds the same dict objects as ``records``, so the mirroring store_reachability
    # does in place stays visible to every later stage.
    vulnerabilities = [record for record in records if record.get("type") == _VULNERABILITY]
    enrich_findings_with_reachability(vulnerabilities, [callgraph], languages)
    _record_ran(report, _REACHABILITY)
    return dict(build_reachability_summary(vulnerabilities, [callgraph]))


def _apply_vulnerability_waiver(records: list[dict[str, Any]], waiver: Waiver) -> None:
    scope = waiver_criteria(waiver)
    for record in records:
        if record.get("type") == _VULNERABILITY and record_matches(record, scope) and waive_advisories(record, waiver):
            roll_up_advisories(record)


def _apply_field_waiver(records: list[dict[str, Any]], waiver: Waiver) -> None:
    criteria = waiver_criteria(waiver)
    # A waiver that constrains nothing would blanket every finding the caller posted.
    if not criteria:
        return
    for record in records:
        if record_matches(record, criteria):
            record["waived"] = True
            record["waiver_reason"] = waiver.reason


def _apply_signature_waivers(records: list[dict[str, Any]], waivers: list[Waiver]) -> None:
    """Bind location waivers to the findings they were taken from, re-anchoring across line drift."""
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
    signed = {record["finding_id"]: MatchSignature(**record["match"]) for record in records if record.get("match")}
    bind_legacy_signatures(waivers, signed)
    signature_waivers: list[Waiver] = []
    for waiver in waivers:
        route = route_waiver(waiver)
        if route == "signature":
            signature_waivers.append(waiver)
        elif route == "vulnerability":
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

    parsed_inputs = await asyncio.to_thread(_parse_sboms, request, report)

    license_settings = {"license_compliance": request.license_policy.model_dump()} if request.license_policy else None
    settings_for = _build_settings_resolver(SystemSettings(), license_settings)

    requested = resolve_adhoc_analyzers(request.analyzers, report)
    # An input without package components must not be analysed into a clean bill of health.
    package_inputs = [parsed_input for parsed_input in parsed_inputs if parsed_input.components]
    if not package_inputs:
        report.skipped.update(dict.fromkeys(requested, _NO_PACKAGE_COMPONENTS))

    for parsed_input in package_inputs:
        for name in requested:
            await _run_one_analyzer(
                name,
                analyzer_factories[name](),
                parsed_input.sbom,
                settings_for(name),
                parsed_input.components,
                aggregator,
                report,
                _input_label(parsed_input),
            )

    _aggregate_crypto_rules(parsed_inputs, aggregator, report)
    _aggregate_posted_scanners(request, aggregator, report)

    records = [finding.model_dump() for finding in aggregator.get_findings()]
    for record in records:
        # Findings are addressed by ``finding_id`` everywhere the scan-backed API exposes them.
        record["finding_id"] = record["id"]

    epss_kev_summary, threat_intel = await _enrich_vulnerabilities(records, report)

    # One row per package across every posted SBOM, the invariant a stored scan's inventory holds.
    merged, _ = merge_duplicate_dependencies([dep for pi in parsed_inputs for dep in pi.parsed.dependencies])
    components = [dep.to_dict() for dep in merged]
    languages = component_language_map(components)
    reachability_summary = await asyncio.to_thread(_run_reachability, records, request.callgraph, languages, report)

    waived_count = 0
    waivers_applied = _WAIVERS_NONE
    if request.apply_global_waivers:
        from app.repositories.waivers import WaiverRepository

        waived_count = apply_global_waivers_in_memory(records, await WaiverRepository(db).find_active_global())
        waivers_applied = _WAIVERS_GLOBAL

    # After the waivers, so an accepted risk neither scores nor generates work to do.
    stats = compute_stats(records, languages)
    recommendations = await asyncio.to_thread(
        recommendation_engine.generate_recommendations,
        findings=[record for record in records if not record.get("waived")],
        dependencies=components,
        join_dependencies=components,
        threat_intel=threat_intel,
    )

    # A stage that errored still reached upstream, unless it stopped for want of an API key before any request.
    report.notes = {
        name: note
        for name, note in _STAGE_NOTES.items()
        if name in report.ran or any(MISSING_API_KEY not in reason for reason in report.errored.get(name, ()))
    }

    return AdhocAnalyzeResponse(
        findings=records,
        stats=stats,
        dependencies=aggregator.get_dependency_enrichments(),
        epss_kev_summary=epss_kev_summary,
        reachability_summary=reachability_summary,
        recommendations=[recommendation.to_dict() for recommendation in recommendations],
        analyzers=report,
        waivers_applied=waivers_applied,
        waived_count=waived_count,
    )
