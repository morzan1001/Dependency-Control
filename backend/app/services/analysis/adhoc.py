"""Stateless ad-hoc analysis: the analysis pipeline without a scan, a project or a write."""

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any

from app.core.cache import suppress_cache_writes
from app.core.constants import (
    ADHOC_MAX_FINDINGS,
    ADHOC_MAX_SBOM_COMPONENTS,
    ADHOC_MAX_SBOM_EVIDENCE_ENTRIES,
    ADHOC_MAX_SCANNER_FINDINGS,
    get_severity_value,
    sort_by_severity,
)
from app.models.crypto_asset import CryptoAsset
from app.models.match_signature import MatchSignature
from app.models.system import SystemSettings
from app.models.waiver import Waiver
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse, AnalyzerReport
from app.schemas.projections import CallgraphMinimal
from app.schemas.sbom import ParsedSBOM
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _build_settings_resolver, _partial_result_reason
from app.services.analysis.registry import CRYPTO_ANALYZERS, analyzers, post_processors
from app.services.analysis.stats import build_epss_kev_summary, build_reachability_summary, compute_stats
from app.services.analysis.types import Database
from app.services.analyzers import Analyzer
from app.services.analyzers.crypto.base import CryptoRuleAnalyzer, crypto_findings_for_assets
from app.services.crypto_policy.seeder import load_seed_rules
from app.services.enrichment.service import VulnerabilityEnrichmentService
from app.services.reachability_enrichment import (
    _PreparedCallgraph,
    _prepare_callgraph,
    component_language_map,
    enrich_findings_from_callgraphs,
)
from app.services.recommendations import recommendation_engine
from app.services.sbom_parser import MAX_COMPONENT_NESTING_DEPTH, parse_sbom
from app.services.stats import _resolve_finding_id_query

logger = logging.getLogger(__name__)

# One ad-hoc analysis per pod: the two in-process analysis workers must not be starved.
ADHOC_SLOTS = asyncio.Semaphore(1)

_UNKNOWN_ANALYZER = "unknown analyzer"
_EMPTY_PAYLOAD = "empty payload"
_PARTIAL_COVERAGE = "partial coverage: {reason}"
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

_OSV = "osv"

# What a caller gets without naming an analyzer: an SBOM in, vulnerabilities and licence
# verdicts out, with no CLI process and one batched upstream call.
ADHOC_DEFAULT_ANALYZERS: tuple[str, ...] = (_OSV, "license_compliance")

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

_SBOM_POSITION = "SBOM #{position}"

_CRYPTO_RULES = "crypto_rules"
_NO_CRYPTO_ASSETS = "no cryptographic-asset components in the SBOM"
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

# The finding types the registered rule-driven analyzers own. A seeded rule outside them belongs
# to an analyzer with its own grading logic: the certificate-lifecycle rule constrains nothing,
# so the matcher alone would fire it on every asset in the CBOM.
_RULE_DRIVEN_FINDING_TYPES: frozenset[str] = frozenset(
    finding_type.value
    for analyzer in analyzers.values()
    if isinstance(analyzer, CryptoRuleAnalyzer)
    for finding_type in analyzer.finding_types
)

# What a stage that ran does not otherwise reveal. ``osv`` is in the defaults, so a caller who
# named no analyzer still has to be told their package list left the process, and the crypto
# stage grades against the shipped seeds because it never reads this installation's policy.
_STAGE_NOTES: dict[str, str] = {
    _OSV: "package coordinates from the posted SBOMs are sent to api.osv.dev",
    _ENRICHMENT: "vulnerability ids are sent to the EPSS API and matched against the CISA KEV catalog",
    _CRYPTO_RULES: "graded against the shipped seed rules, not against this installation's crypto policy",
}

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
_SCOPE_FINDING = "finding"
# A rule-scope waiver spans every file, so the component it was taken from is not a criterion.
_SCOPE_RULE = "rule"
# The waiver UI stores this in place of a field the user left unset.
_UNCONSTRAINED_WAIVER_VALUE = "Unknown"

_WAIVER_FINDING_ID = "finding_id"
_WAIVER_PACKAGE_NAME = "package_name"
_WAIVER_PACKAGE_VERSION = "package_version"
_WAIVER_FINDING_TYPE = "finding_type"

# Waiver field -> record field, mirroring the query the scan-backed path builds.
_WAIVER_FIELD_MAP: tuple[tuple[str, str], ...] = (
    (_WAIVER_FINDING_ID, "finding_id"),
    (_WAIVER_PACKAGE_NAME, "component"),
    (_WAIVER_PACKAGE_VERSION, "version"),
    (_WAIVER_FINDING_TYPE, "type"),
)
# A vulnerability waiver narrows documents but never by type: the advisory it names only
# ever lives in a vulnerability document, whatever ``finding_type`` the waiver carries.
_VULNERABILITY_SCOPE_FIELDS = tuple(pair for pair in _WAIVER_FIELD_MAP if pair[0] != _WAIVER_FINDING_TYPE)


class AdhocInputTooLarge(Exception):
    """The request is shaped so that a synchronous stage would run superlinearly over it."""


# Where each SBOM dialect keeps its component list.
_COMPONENT_KEYS: tuple[str, ...] = ("components", "packages", "artifacts")
# Per-component lists the parser folds into a deduped list with a linear membership test,
# which makes the parse quadratic in whatever one component carries.
_EVIDENCE_LIST_KEYS: tuple[str, ...] = ("properties", "cpes", "locations")

_TOO_MANY_COMPONENTS = "{count} components exceeds the ad-hoc limit of {limit}"
_TOO_MANY_EVIDENCE = "{count} component evidence entries exceeds the ad-hoc limit of {limit}"
_TOO_MANY_SCANNER_FINDINGS = "{count} posted scanner findings exceeds the ad-hoc limit of {limit}"


def _components_of(sbom: dict[str, Any], depth: int = 0) -> list[dict[str, Any]]:
    """Every component the parser will flatten, nested ones included.

    Bounded at the parser's own depth, because everything below it the parser counts and drops
    without ever reaching the stage this ceiling protects. One wrapper component is otherwise
    enough to walk a document of any size past both counts.
    """
    entries: list[dict[str, Any]] = []
    if depth >= MAX_COMPONENT_NESTING_DEPTH:
        return entries
    for key in _COMPONENT_KEYS:
        value = sbom.get(key)
        if not isinstance(value, list):
            continue
        for entry in value:
            if not isinstance(entry, dict):
                continue
            entries.append(entry)
            entries.extend(_components_of(entry, depth + 1))
    return entries


def _evidence_entries(component: dict[str, Any]) -> int:
    total = sum(len(component[key]) for key in _EVIDENCE_LIST_KEYS if isinstance(component.get(key), list))
    evidence = component.get("evidence")
    occurrences = evidence.get("occurrences") if isinstance(evidence, dict) else None
    return total + (len(occurrences) if isinstance(occurrences, list) else 0)


def _posted_finding_count(name: str, payload: dict[str, Any]) -> int:
    total = 0
    for key in _SCANNER_RESULT_KEYS[name]:
        items = payload.get(key)
        if not isinstance(items, list):
            continue
        total += len(items)
        # KICS nests one entry per hit inside the query that produced it.
        total += sum(
            len(item["files"]) for item in items if isinstance(item, dict) and isinstance(item.get("files"), list)
        )
    return total


def _reject_unaffordable_input(request: AdhocAnalyzeRequest) -> None:
    """Refuse a request whose shape drives a superlinear synchronous stage.

    The parse and the cross-linking run to completion without an await, so no deadline can
    interrupt them and the 25 MB body ceiling sits far above where they become expensive.
    Counting the three shapes that drive them is linear, and it happens before any of them run.
    """
    components = [component for sbom in request.sboms for component in _components_of(sbom)]
    if len(components) > ADHOC_MAX_SBOM_COMPONENTS:
        raise AdhocInputTooLarge(_TOO_MANY_COMPONENTS.format(count=len(components), limit=ADHOC_MAX_SBOM_COMPONENTS))

    evidence = sum(_evidence_entries(component) for component in components)
    if evidence > ADHOC_MAX_SBOM_EVIDENCE_ENTRIES:
        raise AdhocInputTooLarge(_TOO_MANY_EVIDENCE.format(count=evidence, limit=ADHOC_MAX_SBOM_EVIDENCE_ENTRIES))

    if request.scanners is None:
        return
    posted = sum(
        _posted_finding_count(name, payload)
        for name, payload in request.scanners.model_dump(exclude_none=True).items()
        if payload
    )
    if posted > ADHOC_MAX_SCANNER_FINDINGS:
        raise AdhocInputTooLarge(_TOO_MANY_SCANNER_FINDINGS.format(count=posted, limit=ADHOC_MAX_SCANNER_FINDINGS))


def _cap_findings(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    """Keep the most severe findings when the set has to be cut.

    The aggregator orders by type name, where ``vulnerability`` sorts last, so a head slice
    would drop every CVE before the first secret.
    """
    if len(records) <= ADHOC_MAX_FINDINGS:
        return records, False
    logger.warning("adhoc: capping %d findings at %d", len(records), ADHOC_MAX_FINDINGS)
    return sort_by_severity(records)[:ADHOC_MAX_FINDINGS], True


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

    A failure and a coverage gap both land in ``report.errored`` and neither is ever aggregated:
    the aggregator turns every ``{"error": ...}`` into a HIGH SYSTEM_WARNING finding, which would
    read as a real defect instead of as missing coverage.
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

    # What the analyzer did find is kept; what it could not reach is a gap, and an unreachable
    # CVE source must not answer a Log4Shell SBOM with an empty finding list and no reason.
    partial = _partial_result_reason(result)
    if partial:
        logger.warning("adhoc: analyzer %s returned partial coverage: %s", name, partial)
        _record_errored(report, name, f"{fallback_source}: {_PARTIAL_COVERAGE.format(reason=partial)}")
        return

    _record_ran(report, name)


def _aggregate_atomically(aggregator: ResultAggregator, name: str, payload: dict[str, Any], source: str) -> None:
    """Normalise into a scratch aggregator, then hand over only a complete result.

    The normalizers add each item as they read it, so a payload that dies half-way would
    otherwise contribute whatever preceded the unreadable item — the same items in a different
    order yielding a different set of findings alongside the same error.
    """
    staged = ResultAggregator()
    staged.aggregate(name, payload, source=source)
    for finding in staged.findings.values():
        aggregator.add_finding(finding, source=source)


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
            _aggregate_atomically(aggregator, name, payload, f"posted:{name}")
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
            report.skipped[name] = _CRYPTO_ANALYZER_NO_EQUIVALENT.get(name, _CRYPTO_ANALYZER_REPLACED)
        elif name not in analyzers:
            report.skipped[name] = _UNKNOWN_ANALYZER
        else:
            resolved.append(name)

    for name in analyzers:
        if name in resolved or name in report.skipped:
            continue
        if name in CRYPTO_ANALYZERS:
            report.skipped[name] = _CRYPTO_ANALYZER_NO_EQUIVALENT.get(name, _CRYPTO_ANALYZER_REPLACED)
        else:
            report.skipped[name] = ADHOC_SKIP_REASONS.get(name, _NOT_REQUESTED)

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

    rules = [rule for rule in load_seed_rules() if rule.enabled and rule.finding_type in _RULE_DRIVEN_FINDING_TYPES]
    for parsed_input in parsed_inputs:
        assets = [
            CryptoAsset(project_id=_ADHOC_SCOPE, scan_id=_ADHOC_SCOPE, **asset.model_dump())
            for asset in parsed_input.parsed.crypto_assets
        ]
        findings = crypto_findings_for_assets(assets, rules)
        if findings:
            aggregator.aggregate(
                _CRYPTO_DISPATCH_KEY,
                {"findings": findings},
                source=_sbom_source(parsed_input.sbom, _input_label(parsed_input)),
            )
    _record_ran(report, _CRYPTO_RULES)


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


def _scoped_finding_id(finding_id: str, scope: str, package_name: str) -> str | re.Pattern[str]:
    """The finding ids a waiver reaches, as the same resolver the scan-backed query is built from."""
    resolved = _resolve_finding_id_query(finding_id, scope, package_name)
    return re.compile(resolved["$regex"]) if isinstance(resolved, dict) else resolved


def _waiver_criteria(waiver: Waiver, fields: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    """The record fields a waiver actually constrains, keyed as they appear on a record."""
    scope = waiver.scope or _SCOPE_FINDING
    criteria: dict[str, Any] = {}
    for waiver_field, record_field in fields:
        if waiver_field == _WAIVER_PACKAGE_NAME and scope == _SCOPE_RULE:
            continue
        value = getattr(waiver, waiver_field, None)
        if not value or value == _UNCONSTRAINED_WAIVER_VALUE:
            continue
        if waiver_field == _WAIVER_FINDING_ID:
            criteria[record_field] = _scoped_finding_id(str(value), scope, waiver.package_name or "")
        else:
            criteria[record_field] = value
    return criteria


def _matches(record: dict[str, Any], criteria: dict[str, Any]) -> bool:
    for field, expected in criteria.items():
        value = record.get(field)
        if isinstance(expected, re.Pattern):
            if not isinstance(value, str) or not expected.search(value):
                return False
        elif value != expected:
            return False
    return True


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
        # A widened scope keeps its query semantics: re-anchoring one signature would narrow it
        # back to the single location the waiver was taken from.
        if waiver.match is not None and (waiver.scope or _SCOPE_FINDING) == _SCOPE_FINDING:
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
    _reject_unaffordable_input(request)

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
                _input_label(parsed_input),
            )

    _aggregate_crypto_rules(parsed_inputs, aggregator, report)
    _aggregate_posted_scanners(request, aggregator, report)

    records = [finding.model_dump() for finding in aggregator.get_findings()]
    for record in records:
        # Findings are addressed by ``finding_id`` everywhere the scan-backed API exposes them.
        record["finding_id"] = record["id"]

    # Before enrichment, so waivers, stats and recommendations all describe the returned set.
    records, truncated = _cap_findings(records)

    epss_kev_summary = await _enrich_vulnerabilities(records, report)

    components = [component for pi in parsed_inputs for component in pi.components]
    languages = component_language_map(components)
    reachability_summary = _run_reachability(records, request.callgraph, languages, report)

    waived_count = 0
    waivers_applied = _WAIVERS_NONE
    if request.apply_global_waivers:
        from app.repositories import WaiverRepository

        waived_count = apply_global_waivers_in_memory(records, await WaiverRepository(db).find_active_global())
        waivers_applied = _WAIVERS_GLOBAL

    # After the waivers, so an accepted risk neither scores nor generates work to do.
    stats = compute_stats(records, languages)
    source_target = next((pi.parsed.source_target for pi in parsed_inputs if pi.parsed.source_target), None)
    recommendations = await recommendation_engine.generate_recommendations(
        findings=[record for record in records if not record.get("waived")],
        dependencies=components,
        source_target=source_target,
    )

    # A stage that errored still reached upstream, so attempted is the condition, not success.
    report.notes = {name: note for name, note in _STAGE_NOTES.items() if name in report.ran or name in report.errored}

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
        truncated=truncated,
    )
