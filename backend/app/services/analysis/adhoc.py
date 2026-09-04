"""Stateless ad-hoc analysis: the analysis pipeline without a scan, a project or a write."""

import logging
from dataclasses import dataclass
from typing import Any

from app.models.system import SystemSettings
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse, AnalyzerReport
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _build_settings_resolver
from app.services.analysis.registry import analyzers
from app.services.analysis.types import Database
from app.services.analyzers import Analyzer
from app.services.sbom_parser import parse_sbom

logger = logging.getLogger(__name__)

_UNKNOWN_ANALYZER = "unknown analyzer"


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
        return str(metadata["component"].get("name", fallback))
    if sbom.get("serialNumber"):
        return str(sbom["serialNumber"])
    return fallback


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
    except Exception as exc:
        logger.warning("adhoc: analyzer %s failed: %s", name, exc)
        report.errored[name] = str(exc)
        return

    if result.get("error"):
        report.errored[name] = str(result["error"])
        return

    aggregator.aggregate(name, result, source=_sbom_source(sbom, fallback_source))
    if name not in report.ran:
        report.ran.append(name)


def _aggregate_posted_scanners(
    request: AdhocAnalyzeRequest,
    aggregator: ResultAggregator,
    report: AnalyzerReport,
) -> None:
    if request.scanners is None:
        return
    for name, payload in request.scanners.model_dump(exclude_none=True).items():
        aggregator.aggregate(name, payload, source=f"posted:{name}")
        if name not in report.ran:
            report.ran.append(name)


def _parse_sboms(request: AdhocAnalyzeRequest, report: AnalyzerReport) -> list[_ParsedInput]:
    """Parse every SBOM; an unparseable one is reported and skipped, never fatal."""
    parsed_inputs: list[_ParsedInput] = []
    for index, sbom in enumerate(request.sboms):
        position = index + 1
        try:
            parsed = parse_sbom(sbom)
        except Exception as exc:
            logger.warning("adhoc: sbom#%d could not be parsed: %s", position, exc)
            report.skipped_inputs[f"sbom#{position}"] = f"could not be parsed: {exc}"
            continue
        parsed_inputs.append(
            _ParsedInput(position=position, sbom=sbom, components=[dep.to_dict() for dep in parsed.dependencies])
        )
    return parsed_inputs


async def run_adhoc_analysis(request: AdhocAnalyzeRequest, db: Database) -> AdhocAnalyzeResponse:
    """Analyze the posted SBOMs and scanner results in memory. Writes nothing."""
    report = AnalyzerReport()
    aggregator = ResultAggregator()

    parsed_inputs = _parse_sboms(request, report)

    # Defaults, not the stored document: the settings dependency exposes an ``auto_init`` query
    # parameter that writes a ``system_settings`` document.
    license_policy = request.license_policy.model_dump() if request.license_policy else None
    settings_for = _build_settings_resolver(SystemSettings(), license_policy, None)

    requested: list[str] = []
    for name in request.analyzers or []:
        if name in analyzers:
            requested.append(name)
        else:
            report.skipped[name] = _UNKNOWN_ANALYZER

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
