"""Stateless ad-hoc analysis: the analysis pipeline without a scan, a project or a write."""

import logging
from dataclasses import dataclass
from typing import Any

from app.core.cache import suppress_cache_writes
from app.models.system import SystemSettings
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse, AnalyzerReport
from app.schemas.sbom import ParsedSBOM
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _build_settings_resolver
from app.services.analysis.registry import CRYPTO_ANALYZERS, analyzers
from app.services.analysis.types import Database
from app.services.analyzers import Analyzer
from app.services.sbom_parser import parse_sbom

logger = logging.getLogger(__name__)

_UNKNOWN_ANALYZER = "unknown analyzer"
_EMPTY_PAYLOAD = "empty payload"
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


@dataclass(frozen=True)
class _ParsedInput:
    """One posted SBOM alongside the pre-parsed components the analyzers consume."""

    # 1-based position in the request, so a finding's source names the SBOM the caller sent
    # even when an earlier one was skipped.
    position: int
    sbom: dict[str, Any]
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
            _ParsedInput(position=position, sbom=sbom, components=[dep.to_dict() for dep in parsed.dependencies])
        )
    return parsed_inputs


def resolve_adhoc_analyzers(requested: list[str] | None, report: AnalyzerReport) -> list[str]:
    """Pick the analyzers to run and record a reason for every registered one left out."""
    selected = list(ADHOC_DEFAULT_ANALYZERS) if requested is None else list(requested)

    resolved: list[str] = []
    for name in selected:
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

    return AdhocAnalyzeResponse(findings=records, analyzers=report)
