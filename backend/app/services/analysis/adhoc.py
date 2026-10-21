import asyncio
import logging
from dataclasses import dataclass
from functools import partial
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
from app.models.finding import FindingType
from app.models.waiver import Waiver
from app.repositories.system_settings import SystemSettingsRepository
from app.repositories.waivers import WaiverRepository
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse, AnalyzerReport, WaiversApplied
from app.schemas.analytics import RecommendationResponse
from app.schemas.bearer import BearerFinding, bearer_entries
from app.schemas.crypto_policy import RULE_DRIVEN_FINDING_TYPES
from app.schemas.enrichment import VulnerabilityEnrichment
from app.schemas.kics import KicsQuery
from app.schemas.opengrep import OpenGrepFinding
from app.schemas.projections import CallgraphMinimal
from app.schemas.sbom import ParsedSBOM
from app.schemas.trufflehog import TruffleHogFinding
from app.services.aggregation import ResultAggregator, is_error_result
from app.services.aggregation.cross_link import refresh_vulnerability_info
from app.services.analysis.registry import CRYPTO_ANALYZERS, POST_PROCESSOR_ANALYZERS, analyzer_factories
from app.services.analysis.runner import (
    AnalyzerInput,
    AnalyzerOutcome,
    OutcomeStatus,
    build_settings_resolver,
    run_analyzer,
    sbom_label,
    sbom_name,
)
from app.services.analysis.stats import build_epss_kev_summary, build_reachability_summary, compute_stats
from app.services.analysis.types import Database
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.analyzers.malware import MISSING_API_KEY
from app.services.crypto_policy.seeder import load_seed_rules
from app.services.enrichment.service import sends_ids, vulnerability_enrichment_service
from app.services.github import installation_github_token
from app.services.reachability_enrichment import (
    ComponentLanguages,
    component_language_map,
    enrich_findings_with_reachability,
)
from app.services.recommendations import generate_recommendations
from app.services.sbom_parser import (
    DELIBERATE_SKIP_REASONS,
    SKIP_CRYPTO_ASSET,
    merge_duplicate_dependencies,
    parse_sbom,
)
from app.services.waivers.matching import (
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
_NO_COMPONENTS = "no components could be parsed (detected format: {sbom_format})"
_DROPPED_COMPONENTS = "{count} component(s) dropped by the parser ({reasons})"

_UNRECOGNISED_PAYLOAD = "unrecognised payload shape: expected {keys}"

_BEARER = "bearer"

# A payload missing every key, or with entries the model rejects, must not be reported as coverage.
_POSTED_SCANNERS: dict[str, tuple[tuple[str, ...], type[BaseModel]]] = {
    "trufflehog": (("findings",), TruffleHogFinding),
    "opengrep": (("findings", "results"), OpenGrepFinding),
    _BEARER: (("findings",), BearerFinding),
    "kics": (("queries",), KicsQuery),
}
_UNREADABLE_ENTRIES = "{unreadable} of {total} '{key}' entries could not be read ({reason})"
_WHOLE_ENTRY = "entry"

_OSV = "osv"

# The defaults run no CLI process and make one batched upstream call.
ADHOC_DEFAULT_ANALYZERS: tuple[str, ...] = (_OSV, "license_compliance")

_NOT_REQUESTED = "not requested"
_NO_PACKAGE_COMPONENTS = "no package components to analyse"
_UNCACHED_FANOUT = (
    "off by default: this path caches nothing keyed on the posted packages, so every run re-queries "
    "the upstream registry for each package it recognises"
)
_CLI_SCANNER = "off by default: runs a CLI scanner process, which takes minutes on large SBOMs"

ADHOC_SKIP_REASONS: dict[str, str] = {
    "trivy": _CLI_SCANNER,
    "grype": _CLI_SCANNER,
    "deps_dev": _UNCACHED_FANOUT,
    "outdated_packages": _UNCACHED_FANOUT,
    "hash_verification": _UNCACHED_FANOUT,
    "end_of_life": _UNCACHED_FANOUT,
    "maintainer_risk": _UNCACHED_FANOUT,
    "os_malware": _UNCACHED_FANOUT,
    "typosquatting": "off by default: downloads the PyPI top-packages list, which this path does not cache",
}

_CRYPTO_RULES = "crypto_rules"
_NO_CRYPTO_ASSETS = "no readable cryptographic-asset components in the SBOM"
# normalize_crypto keeps each finding's own type, so one dispatch key covers every crypto finding type.
_CRYPTO_DISPATCH_KEY = "crypto_weak_algorithm"

_CRYPTO_ANALYZER_REPLACED = (
    "replaced ad-hoc by the 'crypto_rules' stage: the registered analyzer reads stored crypto "
    "assets from the database, the stage evaluates the seeded rules against the posted CBOM"
)
# These grade against an external reference, not a policy rule, so the rule stage does not replace them.
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
    """Read off the analyzers' own URL constants so a note never names a host the code no longer calls."""
    return ", ".join(dict.fromkeys(urlsplit(url).netloc for url in urls))


_COORDINATES_SENT = "package coordinates from the posted SBOMs are sent to {hosts}"

# Every stage that puts posted data on the wire must be named here.
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

_ADHOC_CRYPTO_RULES = tuple(r for r in load_seed_rules() if r.enabled and r.finding_type in RULE_DRIVEN_FINDING_TYPES)

_NO_CALLGRAPH = "no callgraph supplied"
# Identifies the graph within this request only; nothing here is stored or looked up by it.
_POSTED_CALLGRAPH_ID = "posted"


def _posted_entries(name: str, payload: dict[str, Any], key: str) -> list[Any] | None:
    container = payload.get(key)
    if name == _BEARER:
        return bearer_entries(container)
    return container if isinstance(container, list) else None


@dataclass(frozen=True)
class _ParsedInput:
    parsed: ParsedSBOM
    sbom: AnalyzerInput


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


async def _aggregate_unless_errored(aggregator: ResultAggregator, name: str, source: str, result: Any) -> None:
    # The aggregator would turn the error into a HIGH SYSTEM_WARNING finding that reads as a real defect.
    if not is_error_result(result):
        aggregator.aggregate(name, result, source=source)


def _record_outcome(report: AnalyzerReport, outcome: AnalyzerOutcome, label: str) -> None:
    """Attributed to the input, so "failed on one of ten" is distinguishable from "failed on ten"."""
    if outcome.status is OutcomeStatus.SUCCESS:
        _record_ran(report, outcome.name)
        return
    reason = outcome.reason
    if outcome.status is OutcomeStatus.PARTIAL:
        # An unreachable CVE source must not answer with an empty finding list and no reason.
        reason = _PARTIAL_COVERAGE.format(reason=reason)
    logger.warning("adhoc: analyzer %s on %s: %s", outcome.name, label, reason)
    _record_errored(report, outcome.name, f"{label}: {reason}")


def _aggregate_atomically(aggregator: ResultAggregator, name: str, payload: dict[str, Any], source: str) -> None:
    """Dry-run on a scratch aggregator: normalizers add item by item, so a half-read payload adds nothing."""
    ResultAggregator().aggregate(name, payload, source=source)
    aggregator.aggregate(name, payload, source=source)


def _first_reason(exc: ValidationError) -> str:
    error = exc.errors()[0]
    field = ".".join(str(part) for part in error["loc"])
    return f"{field or _WHOLE_ENTRY}: {error['msg']}"


def _entry_shortfall(name: str, payload: dict[str, Any]) -> str | None:
    """A well-shaped container says nothing about its entries: kics queries without files would read as an all-clear."""
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
    """Normalizers trust first-party shapes, so a reshaped report must land in report.errored, not abort the request."""
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
    defects: list[str] = []
    if not parsed.dependencies and not parsed.crypto_assets:
        defects.append(_NO_COMPONENTS.format(sbom_format=parsed.format.value))
    lost = {
        reason: count
        for reason, count in parsed.skipped_reasons.items()
        if reason not in DELIBERATE_SKIP_REASONS and count
    }
    # A skipped crypto asset is lost unless it reached crypto_assets.
    unread_crypto = parsed.skipped_reasons.get(SKIP_CRYPTO_ASSET, 0) - len(parsed.crypto_assets)
    if unread_crypto > 0:
        lost[SKIP_CRYPTO_ASSET] = unread_crypto
    if lost:
        reasons = ", ".join(f"{reason}={count}" for reason, count in sorted(lost.items()))
        defects.append(_DROPPED_COMPONENTS.format(count=sum(lost.values()), reasons=reasons))
    return defects


def _parse_sboms(request: AdhocAnalyzeRequest, report: AnalyzerReport) -> list[_ParsedInput]:
    """A document-level failure rejects the whole input: a half-built graph is worse than none."""
    parsed_inputs: list[_ParsedInput] = []
    for position, sbom in enumerate(request.sboms, start=1):
        label = sbom_label(position)
        try:
            parsed = parse_sbom(sbom)
        except Exception as exc:
            logger.warning("adhoc: %s could not be parsed: %s", label, exc)
            report.skipped_inputs[label] = f"could not be parsed: {exc}"
            continue
        defects = _input_defects(parsed)
        if defects:
            report.skipped_inputs[label] = "; ".join(defects)
        components = [dep.model_dump() for dep in parsed.dependencies]
        parsed_inputs.append(
            _ParsedInput(parsed, AnalyzerInput(position, components, name=sbom_name(sbom), document=sbom))
        )
    return parsed_inputs


def resolve_adhoc_analyzers(requested: list[str] | None, report: AnalyzerReport) -> list[str]:
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
    """Registered crypto analyzers read crypto_assets, absent here; the pure rules run on the shipped defaults."""
    if not any(parsed_input.parsed.crypto_assets for parsed_input in parsed_inputs):
        report.skipped[_CRYPTO_RULES] = _NO_CRYPTO_ASSETS
        return

    for parsed_input in parsed_inputs:
        findings = crypto_findings_for_assets(
            parsed_input.parsed.crypto_assets, _ADHOC_CRYPTO_RULES, scanner=_CRYPTO_RULES
        )
        if findings:
            aggregator.aggregate(
                _CRYPTO_DISPATCH_KEY,
                {"findings": findings},
                source=parsed_input.sbom.source,
            )
    _record_ran(report, _CRYPTO_RULES)


async def _enrich_vulnerabilities(
    records: list[dict[str, Any]], vulnerabilities: list[dict[str, Any]], report: AnalyzerReport, db: Database
) -> dict[str, VulnerabilityEnrichment]:
    threat_intel: dict[str, VulnerabilityEnrichment] = {}
    sends = sends_ids(vulnerabilities)
    try:
        github_token = await installation_github_token(db, (await SystemSettingsRepository(db).get()).github_token)
        threat_intel, unavailable = await vulnerability_enrichment_service.enrich_findings(
            vulnerabilities, github_token=github_token
        )
    except Exception as exc:
        logger.warning("adhoc: EPSS/KEV enrichment failed: %s", exc)
        _record_errored(report, _ENRICHMENT, str(exc))
    else:
        if unavailable:
            _record_errored(report, _ENRICHMENT, unavailable)
        elif sends:
            _record_ran(report, _ENRICHMENT)
        else:
            report.skipped[_ENRICHMENT] = _NO_ENRICHABLE_IDS
    refresh_vulnerability_info(records)
    return threat_intel


def _prepare_posted_callgraph(payload: dict[str, Any]) -> CallgraphMinimal:
    from app.api.v1.helpers.callgraph import resolve_callgraph_payload

    data = {key: value for key, value in payload.items() if key not in ("format", "language")}
    posted_language = payload.get("language")
    _, language, parser = resolve_callgraph_payload(
        str(payload.get("format") or "auto"), str(posted_language) if posted_language else None, data
    )
    parsed = parser(data, language)
    return CallgraphMinimal(
        id=_POSTED_CALLGRAPH_ID,
        module_usage={key: usage.model_dump() for key, usage in parsed.module_usage.items()},
        analyzed_modules=parsed.analyzed_modules,
        language=language,
        total_imports=parsed.total_imports,
    )


def _run_reachability(
    vulnerabilities: list[dict[str, Any]],
    callgraph_payload: dict[str, Any] | None,
    languages: ComponentLanguages,
    report: AnalyzerReport,
) -> CallgraphMinimal | None:
    if callgraph_payload is None:
        report.skipped[_REACHABILITY] = _NO_CALLGRAPH
        return None

    try:
        callgraph = _prepare_posted_callgraph(callgraph_payload)
    except Exception as exc:
        logger.warning("adhoc: callgraph could not be prepared: %s", exc)
        _record_errored(report, _REACHABILITY, str(exc))
        return None

    enrich_findings_with_reachability(vulnerabilities, [callgraph], languages)
    _record_ran(report, _REACHABILITY)
    return callgraph


def _apply_vulnerability_waiver(records: list[dict[str, Any]], waiver: Waiver) -> None:
    scope = waiver_criteria(waiver)
    for record in records:
        if (
            record.get("type") == FindingType.VULNERABILITY
            and record_matches(record, scope)
            and waive_advisories(record, waiver)
        ):
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


def apply_global_waivers_in_memory(records: list[dict[str, Any]], waivers: list[Waiver]) -> int:
    for waiver in waivers:
        if route_waiver(waiver) == "vulnerability":
            _apply_vulnerability_waiver(records, waiver)
        else:
            _apply_field_waiver(records, waiver)
    return sum(1 for record in records if record.get("waived") is True)


async def run_adhoc_analysis(request: AdhocAnalyzeRequest, db: Database) -> AdhocAnalyzeResponse:
    """Writes nothing; of the Redis cache it shares with the scans, only advisory data named by its upstream id."""
    with suppress_cache_writes():
        return await _analyze(request, db)


async def _analyze(request: AdhocAnalyzeRequest, db: Database) -> AdhocAnalyzeResponse:
    report = AnalyzerReport()
    aggregator = ResultAggregator()

    parsed_inputs = await asyncio.to_thread(_parse_sboms, request, report)

    license_settings = {"license_compliance": request.license_policy.model_dump()} if request.license_policy else None
    # Analyzers get none of the installation's settings or credentials; its GitHub token serves the GHSA lookups only.
    settings_for = build_settings_resolver(None, license_settings)

    requested = resolve_adhoc_analyzers(request.analyzers, report)
    # An input without package components must not be analysed into a clean bill of health.
    package_inputs = [parsed_input.sbom for parsed_input in parsed_inputs if parsed_input.sbom.components]
    if not package_inputs:
        report.skipped.update(dict.fromkeys(requested, _NO_PACKAGE_COMPONENTS))

    for sbom in package_inputs:
        outcomes = await asyncio.gather(
            *(
                run_analyzer(
                    name, sbom, settings_for(name), partial(_aggregate_unless_errored, aggregator, name, sbom.source)
                )
                for name in requested
            )
        )
        for outcome in outcomes:
            _record_outcome(report, outcome, sbom.label)

    _aggregate_crypto_rules(parsed_inputs, aggregator, report)
    _aggregate_posted_scanners(request, aggregator, report)

    records = [finding.model_dump() for finding in aggregator.get_findings()]
    for record in records:
        # Findings are addressed by ``finding_id`` everywhere the scan-backed API exposes them.
        record["finding_id"] = record["id"]
    # Same dict objects as records, so every stage's in-place enrichment reaches the response.
    vulnerabilities = [record for record in records if record["type"] == FindingType.VULNERABILITY]

    threat_intel = await _enrich_vulnerabilities(records, vulnerabilities, report, db)

    # One row per package across every posted SBOM, the invariant a stored scan's inventory holds.
    merged, _ = merge_duplicate_dependencies([dep for pi in parsed_inputs for dep in pi.parsed.dependencies])
    components = [dep.model_dump() for dep in merged]
    languages = component_language_map(components)
    callgraph = await asyncio.to_thread(_run_reachability, vulnerabilities, request.callgraph, languages, report)

    waived_count = 0
    waivers_applied: WaiversApplied = "none"
    if request.apply_global_waivers:
        waived_count = apply_global_waivers_in_memory(records, await WaiverRepository(db).find_active_global())
        waivers_applied = "global"

    # After the waivers, so an accepted risk neither scores, counts in a summary nor generates work to do.
    stats = compute_stats(records, languages)
    live_vulnerabilities = [record for record in vulnerabilities if not record.get("waived")]
    recommendations = await asyncio.to_thread(
        generate_recommendations,
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
        epss_kev_summary=dict(build_epss_kev_summary(live_vulnerabilities, threat_intel)),
        reachability_summary=dict(build_reachability_summary(live_vulnerabilities, [callgraph])) if callgraph else None,
        recommendations=[RecommendationResponse.model_validate(recommendation) for recommendation in recommendations],
        analyzers=report,
        waivers_applied=waivers_applied,
        waived_count=waived_count,
    )
