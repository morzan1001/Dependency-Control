import asyncio
import contextlib
import logging
import re
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Optional

import bson
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo import UpdateMany
from pymongo.errors import DocumentTooLarge

from app.core.constants import (
    ANALYSIS_MAX_RETRIES,
    DETAILS_KEY_IN_KEV,
    MAX_CRYPTO_ASSETS_PER_SCAN,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
    ScanStatus,
    SCAN_USABLE_STATUSES,
)
from app.core.cve import display_vulnerability_id
from app.core.metrics import (
    analysis_aggregation_duration_seconds,
    analysis_components_parsed_total,
    analysis_duration_seconds,
    analysis_enrichment_total,
    analysis_epss_scores,
    analysis_errors_total,
    analysis_findings_by_type_total,
    analysis_findings_total,
    analysis_gridfs_operations_total,
    analysis_kev_vulnerabilities_total,
    analysis_race_conditions_total,
    analysis_rescan_operations_total,
    analysis_sbom_parse_errors_total,
    analysis_sbom_processed_total,
    analysis_scans_total,
    analysis_waivers_applied_total,
)
from app.models.crypto_asset import CryptoAsset
from app.models.project import Scan
from app.models.stats import Stats
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.crypto_asset import CryptoAssetRepository, scan_query
from app.repositories.dependencies import DependencyRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.repositories.findings import FindingRepository, finding_identity
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.waivers import WaiverRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.cbom import CryptoAssetType
from app.schemas.finding_details import VulnerabilitySummaryDetails
from app.schemas.sbom import ParsedSBOM
from app.services.aggregation import ResultAggregator, is_error_result
from app.services.aggregation.cross_link import refresh_vulnerability_info
from app.services.analysis.integrations import decorate_github_pr, decorate_gitlab_mr
from app.services.analysis.notifications import notify_analysis_failed, send_scan_notifications
from app.services.analysis.registry import (
    CRYPTO_ANALYZERS,
    RAW_SBOM_ANALYZERS,
    VULNERABILITY_ANALYZERS,
    analyzer_factories,
    crypto_evaluators,
)
from app.services.analysis.stats import build_epss_kev_summary, calculate_comprehensive_stats
from app.services.analysis.types import Database
from app.services.analyzers import Analyzer
from app.services.analyzers.crypto.catalogs.loader import CipherSuiteEntry, load_iana_catalog
from app.services.crypto_policy.resolver import CryptoPolicyResolver, EffectivePolicy
from app.services.dependency_store import store_scan_dependencies
from app.services.enrichment.service import vulnerability_enrichment_service
from app.services.github import is_public_github
from app.services.gridfs_maintenance import extract_gridfs_ids_from_refs, gridfs_ref_id, load_gridfs_json
from app.services.reachability_enrichment import (
    ComponentLanguages,
    apply_reachability,
    fetch_callgraphs,
    run_pending_reachability_for_scan,
)
from app.services.sbom_parser import parse_sbom
from app.services.update_frequency_rollup import record_scan_update_delta
from app.services.waivers.apply import restamp_waivers, waiver_fingerprint
from app.services.waivers.matching import route_waiver

logger = logging.getLogger(__name__)

_BULK_CHUNK_SIZE = 500
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_SLIMMED_ADVISORY_FIELDS = frozenset({"description", "references", "details"})

# Run inside the engine (not registered in ``analyzers``); regenerated per run, never carried over.
_POST_PROCESSOR_ANALYZERS = frozenset({"epss_kev", "reachability"})

# Result rows the engine writes itself on every run, as opposed to rows posted by external scanners.
_ENGINE_RESULT_NAMES = frozenset(analyzer_factories) | _POST_PROCESSOR_ANALYZERS | CRYPTO_ANALYZERS

# Crypto findings span the whole scan, so none is credited to one SBOM.
_CRYPTO_SOURCE = "CBOM"


async def _get_github_instance_token(db: Database) -> str | None:
    """The token of the oldest active github.com instance, since GHSA lookups send it to api.github.com."""
    cursor = db.github_instances.find(
        {"is_active": True, "access_token": {"$nin": [None, ""]}},
        {"access_token": 1, "github_url": 1, "url": 1},
    ).sort([("created_at", 1), ("_id", 1)])
    async for doc in cursor:
        if is_public_github(doc.get("github_url"), doc["url"]):
            return str(doc["access_token"])
    return None


async def _carry_over_external_results(scan_id: str, scan_doc: Optional["Scan"], db: Database) -> None:
    """Copy non-SBOM analyzer results (e.g. Secret Scanning, SAST) from the original scan to a rescan."""
    if not (scan_doc and scan_doc.is_rescan and scan_doc.original_scan_id):
        return

    original_scan_id = scan_doc.original_scan_id
    logger.info(f"Rescan detected. Carrying over external results from {original_scan_id} to {scan_id}")

    try:
        await AnalysisResultRepository(db).carry_over(original_scan_id, scan_id, list(_ENGINE_RESULT_NAMES))
    except Exception as e:
        logger.exception("Failed to carry over external results: %s", e)


async def _carry_over_crypto_assets(scan_id: str, scan_doc: Optional["Scan"], db: Database) -> None:
    """Re-key the original scan's crypto assets onto a rescan.

    A CBOM posted to /ingest/cbom is not stored in GridFS, so a rescan cannot re-derive the assets
    it described and every crypto surface would read the rescan as having no cryptography at all.
    """
    if not (scan_doc and scan_doc.is_rescan and scan_doc.original_scan_id and scan_doc.project_id):
        return

    try:
        carried = await CryptoAssetRepository(db).carry_over_to_scan(
            scan_doc.project_id, scan_doc.original_scan_id, scan_id
        )
    except Exception as e:
        logger.exception("Failed to carry over crypto assets to rescan %s: %s", scan_id, e)
        return
    if carried:
        logger.info("Carried over %d crypto assets from %s to rescan %s", carried, scan_doc.original_scan_id, scan_id)


# Analyzer result keys reporting incomplete coverage, with how to phrase each.
_PARTIAL_RESULT_KEYS: tuple[tuple[str, str], ...] = (
    ("partial_components_skipped", "{count} component(s) were not scanned"),
    ("partial_vulnerabilities_unhydrated", "{count} vulnerability record(s) could not be fetched"),
)


def _partial_result_reason(result: Any) -> str | None:
    """Why an analyzer's coverage is incomplete, or None when it is complete."""
    if not isinstance(result, dict):
        return None
    reasons = [template.format(count=result[key]) for key, template in _PARTIAL_RESULT_KEYS if result.get(key)]
    return "; ".join(reasons) if reasons else None


async def _record_result(
    analyzer_name: str,
    result: Any,
    scan_id: str,
    db: Database,
    aggregator: ResultAggregator,
    source: str,
    row_source: str | None = None,
) -> str:
    aggregator.aggregate(analyzer_name, result, source=source)

    # The findings are already aggregated, so a refused raw row costs only the raw-results view.
    try:
        await AnalysisResultRepository(db).save_result(scan_id, analyzer_name, result, source=row_source)
    except Exception as e:
        logger.exception("Storing the raw %s result of %s failed: %s", analyzer_name, scan_id, e)

    # CLI analyzers report timeouts/exit-codes/bad JSON as error dicts instead of raising.
    if is_error_result(result):
        if analysis_errors_total:
            analysis_errors_total.labels(analyzer=analyzer_name).inc()
        logger.warning(f"Analysis {analyzer_name} returned an error result for {scan_id}: {result.get('error')}")
        return f"{analyzer_name}: Failed"

    partial_reason = _partial_result_reason(result)
    if partial_reason:
        # Surface the coverage gap as a finding and flag the analyzer as partial.
        aggregator.add_scan_error(analyzer_name, partial_reason, partial=True, source=f"System: {analyzer_name}")
        logger.warning(f"Analysis {analyzer_name} returned a partial result for {scan_id}: {partial_reason}")
        return f"{analyzer_name}: Partial ({partial_reason})"

    logger.info(f"Analysis {analyzer_name} completed for {scan_id}")
    return f"{analyzer_name}: Success"


def _analyzer_failed(analyzer_name: str, error: Exception, aggregator: ResultAggregator) -> str:
    logger.error("Analysis %s failed: %s", analyzer_name, error, exc_info=error)
    if analysis_errors_total:
        analysis_errors_total.labels(analyzer=analyzer_name).inc()
    # Surface the failure as a finding.
    aggregator.add_scan_error(analyzer_name, str(error), source=f"System: {analyzer_name}")
    return f"{analyzer_name}: Failed"


async def process_analyzer(
    analyzer_name: str,
    analyzer: Analyzer,
    sbom: dict[str, Any],
    scan_id: str,
    db: Database,
    aggregator: ResultAggregator,
    settings: dict[str, Any] | None = None,
    fallback_source: str = "unknown-sbom",
    parsed_components: list[dict[str, Any]] | None = None,
) -> str:
    analyzer_start_time = time.time()
    try:
        if analysis_scans_total:
            analysis_scans_total.labels(analyzer=analyzer_name).inc()

        result = await analyzer.analyze(sbom, settings=settings, parsed_components=parsed_components)

        if analysis_duration_seconds:
            duration = time.time() - analyzer_start_time
            analysis_duration_seconds.labels(analyzer=analyzer_name).observe(duration)

        source: str = fallback_source
        if sbom.get("metadata") and sbom["metadata"].get("component"):
            source = str(sbom["metadata"]["component"].get("name", fallback_source))
        elif sbom.get("serialNumber"):
            source = str(sbom.get("serialNumber"))

        # Keyed on the SBOM's position: root names repeat within a scan (multi-arch images).
        return await _record_result(analyzer_name, result, scan_id, db, aggregator, source, row_source=fallback_source)
    except Exception as e:
        return _analyzer_failed(analyzer_name, e, aggregator)


def _evaluate_crypto(
    assets: list[CryptoAsset], policy: EffectivePolicy, catalog: dict[str, CipherSuiteEntry]
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for name, evaluate in crypto_evaluators(catalog).items():
        started = time.time()
        if analysis_scans_total:
            analysis_scans_total.labels(analyzer=name).inc()
        try:
            results[name] = evaluate(assets, policy)
        except Exception as e:
            logger.exception("Analysis %s failed: %s", name, e)
            results[name] = {"error": str(e), "findings": []}
        if analysis_duration_seconds:
            analysis_duration_seconds.labels(analyzer=name).observe(time.time() - started)
    return results


async def _run_crypto_analyzers(project_id: str, scan_id: str, db: Database, aggregator: ResultAggregator) -> list[str]:
    """Evaluate the scan's stored crypto assets once, after every SBOM's embedded assets are persisted."""
    repo = CryptoAssetRepository(db)
    try:
        assets = await repo.find_many(scan_query(project_id, scan_id), limit=MAX_CRYPTO_ASSETS_PER_SCAN)
        policy = await CryptoPolicyResolver(db).resolve(project_id)
        has_protocols = any(a.asset_type == CryptoAssetType.PROTOCOL for a in assets)
        catalog = await load_iana_catalog() if has_protocols else {}
        # CPU-bound matching over up to MAX_CRYPTO_ASSETS_PER_SCAN assets; keeps the shared event loop free.
        results = await asyncio.to_thread(_evaluate_crypto, assets, policy, catalog)
        skipped = (
            await repo.count_by_scan(project_id, scan_id) - len(assets)
            if len(assets) == MAX_CRYPTO_ASSETS_PER_SCAN
            else 0
        )
    except Exception as e:
        return [_analyzer_failed(name, e, aggregator) for name in sorted(CRYPTO_ANALYZERS)]
    if skipped:
        logger.warning("Scan %s: %d crypto assets beyond the per-scan budget were not evaluated", scan_id, skipped)
        for result in results.values():
            result["partial_components_skipped"] = skipped

    summary: list[str] = []
    for name, result in results.items():
        try:
            summary.append(await _record_result(name, result, scan_id, db, aggregator, _CRYPTO_SOURCE))
        except Exception as e:
            summary.append(_analyzer_failed(name, e, aggregator))
    return summary


# Marker substring of the system-error raised when a GridFS SBOM cannot be read.
_SBOM_GRIDFS_LOAD_ERROR = "Failed to load SBOM from GridFS"


def _count_gridfs_refs(sboms_to_process: list[Any]) -> int:
    return len(extract_gridfs_ids_from_refs(sboms_to_process))


def _outcome_rank(status: str) -> int:
    return 2 if status.startswith("Failed") else int(status.startswith("Partial"))


def _analyzer_outcomes(results_summary: list[str]) -> dict[str, str]:
    """Worst reported status per analyzer; run_analysis repeats each analyzer's entry once per SBOM."""
    outcomes: dict[str, str] = {}
    for entry in results_summary:
        name, _, status = entry.partition(": ")
        if name not in outcomes or _outcome_rank(status) > _outcome_rank(outcomes[name]):
            outcomes[name] = status
    return outcomes


def _failed_analyzer_names(outcomes: dict[str, str]) -> tuple[list[str], list[str]]:
    """(analyzers, enrichments) that failed or ran partially; a failed enrichment loses metadata, not findings."""
    failed = sorted(name for name, status in outcomes.items() if _outcome_rank(status))
    return (
        [name for name in failed if name not in _POST_PROCESSOR_ANALYZERS],
        [name for name in failed if name in _POST_PROCESSOR_ANALYZERS],
    )


async def _resolve_sbom(item: Any, fs: AsyncIOMotorGridFSBucket, aggregator: ResultAggregator) -> dict[str, Any] | None:
    """Resolve a single SBOM item from inline dict or GridFS reference."""
    gridfs_id = gridfs_ref_id(item)
    if gridfs_id:
        try:
            if analysis_gridfs_operations_total:
                analysis_gridfs_operations_total.labels(operation="download", status="attempt").inc()
            sbom: dict[str, Any] = await load_gridfs_json(fs, gridfs_id)
            if analysis_gridfs_operations_total:
                analysis_gridfs_operations_total.labels(operation="download", status="success").inc()
            return sbom
        except Exception as gridfs_err:
            logger.exception("Failed to fetch SBOM from GridFS %s: %s", gridfs_id, gridfs_err)
            if analysis_gridfs_operations_total:
                analysis_gridfs_operations_total.labels(operation="download", status="error").inc()
            aggregator.add_scan_error("system", f"{_SBOM_GRIDFS_LOAD_ERROR}: {gridfs_err}")
            return None
    result: dict[str, Any] | None = item
    return result


def _parse_and_track_sbom(current_sbom: Any) -> tuple[Any, list[dict[str, Any]]]:
    """Try to pre-parse the SBOM and track metrics. Returns (parsed_sbom, parsed_components)."""
    parsed_components: list[dict[str, Any]] = []
    parsed_sbom = None
    try:
        parsed_sbom = parse_sbom(current_sbom)
        parsed_components = [dep.to_dict() for dep in parsed_sbom.dependencies]
        logger.info(f"Parsed SBOM: format={parsed_sbom.format.value}, components={len(parsed_components)}")
        if analysis_sbom_processed_total:
            analysis_sbom_processed_total.labels(format=parsed_sbom.format.value).inc()
        if analysis_components_parsed_total:
            analysis_components_parsed_total.inc(len(parsed_components))
    except Exception as parse_err:
        logger.warning(f"Failed to pre-parse SBOM: {parse_err} - only the raw-document scanners will run")
        if analysis_sbom_parse_errors_total:
            analysis_sbom_parse_errors_total.inc()
    return parsed_sbom, parsed_components


async def _persist_embedded_crypto_assets(parsed_sbom: Any, project_id: str, scan_id: str, db: Database) -> None:
    """Persist crypto assets that were embedded in a parsed SBOM."""
    try:
        crypto_assets = [
            CryptoAsset(project_id=project_id, scan_id=scan_id, **a.model_dump()) for a in parsed_sbom.crypto_assets
        ]
        persisted = await CryptoAssetRepository(db).bulk_upsert(project_id, scan_id, crypto_assets)
        logger.info(
            "engine: persisted %d crypto assets from embedded CBOM (scan=%s)",
            persisted,
            scan_id,
        )
    except Exception as cbom_err:
        logger.warning(
            "engine: failed to persist embedded CBOM crypto assets for scan %s: %s",
            scan_id,
            cbom_err,
        )


def _resolve_effective_analyzers(
    active_analyzers: list[str], parsed_sbom: Any, parsed_components: list[dict[str, Any]], scan_type: str | None
) -> list[str]:
    if parsed_sbom is None:
        active_analyzers = [n for n in active_analyzers if n in RAW_SBOM_ANALYZERS]
    # CBOM-only scans with no real SBOM content: drop SBOM-format scanners
    if not parsed_components and scan_type == "cbom":
        return sorted(n for n in active_analyzers if n not in VULNERABILITY_ANALYZERS)
    return sorted(active_analyzers)


def _build_settings_resolver(
    system_settings: Any,
    project_analyzer_settings: dict[str, dict[str, Any]] | None,
    github_token: str | None = None,
) -> Callable[[str], dict[str, Any]]:
    """Return a function that yields per-analyzer settings dicts."""
    base_settings = system_settings.model_dump() if system_settings else {}
    base_settings["github_token"] = github_token

    def _settings_for(analyzer_name: str) -> dict[str, Any]:
        merged = dict(base_settings)
        if project_analyzer_settings:
            overrides = project_analyzer_settings.get(analyzer_name)
            if overrides:
                merged.update(overrides)
        return merged

    return _settings_for


async def _process_sbom(
    index: int,
    current_sbom: dict[str, Any],
    scan_id: str,
    db: Database,
    aggregator: ResultAggregator,
    active_analyzers: list[str],
    system_settings: Any,
    project_analyzer_settings: dict[str, dict[str, Any]] | None = None,
    project_id: str | None = None,
    scan_type: str | None = None,
    payload: list[ParsedSBOM | None] | None = None,
    github_token: str | None = None,
) -> list[str]:
    """Process a single resolved SBOM: parse, collect deps, run analyzers; returns the results summary."""
    fallback_source = f"SBOM #{index + 1}"

    parsed_sbom, parsed_components = await asyncio.to_thread(_parse_and_track_sbom, current_sbom)

    # Collected rather than stored here: the inventory is replaced once per payload (see store_scan_dependencies).
    if payload is not None and current_sbom:
        payload.append(parsed_sbom)

    if parsed_sbom is not None and parsed_sbom.crypto_assets and project_id:
        await _persist_embedded_crypto_assets(parsed_sbom, project_id, scan_id, db)

    effective_analyzers = _resolve_effective_analyzers(active_analyzers, parsed_sbom, parsed_components, scan_type)

    settings_for = _build_settings_resolver(system_settings, project_analyzer_settings, github_token)

    tasks = [
        process_analyzer(
            analyzer_name,
            analyzer_factories[analyzer_name](),
            current_sbom,
            scan_id,
            db,
            aggregator,
            settings=settings_for(analyzer_name),
            fallback_source=fallback_source,
            parsed_components=parsed_components,
        )
        for analyzer_name in effective_analyzers
        if analyzer_name in analyzer_factories
    ]

    batch_results = await asyncio.gather(*tasks)
    del current_sbom, parsed_components
    return list(batch_results)


def _track_findings_metrics(aggregated_findings: list[Any]) -> None:
    """Track Prometheus metrics for aggregated findings."""
    for finding in aggregated_findings:
        finding_type = finding.type if hasattr(finding, "type") else "unknown"
        severity = finding.severity if hasattr(finding, "severity") else "unknown"
        if analysis_findings_by_type_total:
            analysis_findings_by_type_total.labels(type=finding_type, severity=severity).inc()
        if analysis_findings_total:
            scanners = finding.scanners if hasattr(finding, "scanners") else []
            for scanner_name in scanners:
                analysis_findings_total.labels(analyzer=scanner_name, severity=severity).inc()


_DEP_ENRICHMENT_COPY_KEYS = ("license", "license_expression", "license_category", "license_risks")
_LICENSE_MISSING = {"$in": [None, ""]}
_LICENSE_PRESENT = {"$nin": [None, ""]}


def _dependency_update_ops(scan_id: str, entry: dict[str, Any]) -> list[UpdateMany]:
    """Per-scan dependency updates for one enrichment entry, covering every duplicate doc."""
    slim = {key: entry["data"][key] for key in _DEP_ENRICHMENT_COPY_KEYS if key in entry["data"]}
    if not slim:
        return []

    if entry["purl"]:
        # The canonical purl names package and version whatever each SBOM called it; the prefix
        # match keeps qualifier variants together. A lookahead, unlike an alternation, leaves the
        # server a tight index range on the literal prefix.
        dep_filter: dict[str, Any] = {"scan_id": scan_id, "purl": {"$regex": f"^{re.escape(entry['purl'])}(?![^?#])"}}
    else:
        # Without a purl the enrichment describes an unidentified package; restrict it to
        # the equally purl-less docs so it cannot stamp a same-named package of another
        # ecosystem with its licence.
        dep_filter = {
            "scan_id": scan_id,
            "name": entry["name"],
            "version": entry["version"],
            "purl": {"$in": [None, ""]},
        }

    if "license" not in slim:
        return [UpdateMany(dep_filter, {"$set": slim})]

    # The SBOM-declared license is authoritative; enrichment only fills docs that lack one.
    ops = [UpdateMany({**dep_filter, "license": _LICENSE_MISSING}, {"$set": slim})]
    without_license = {key: value for key, value in slim.items() if key != "license"}
    if without_license:
        ops.append(UpdateMany({**dep_filter, "license": _LICENSE_PRESENT}, {"$set": without_license}))
    return ops


async def _enrich_dependencies(enrichment_entries: list[dict[str, Any]], scan_id: str, db: Database) -> None:
    """Persist aggregated enrichment: purl-keyed upserts plus a slim per-scan dependency copy."""
    if not enrichment_entries:
        return

    logger.info(f"Enriching {len(enrichment_entries)} dependencies with aggregated metadata")

    bulk_ops: list[UpdateMany] = []
    total_updated = 0

    for entry in enrichment_entries:
        if not entry["data"]:
            continue

        bulk_ops.extend(_dependency_update_ops(scan_id, entry))

        if len(bulk_ops) >= _BULK_CHUNK_SIZE:
            try:
                await db.dependencies.bulk_write(bulk_ops, ordered=False)
                total_updated += len(bulk_ops)
            except Exception as e:
                logger.exception("Failed to bulk update dependencies: %s", e)
            bulk_ops.clear()

    if bulk_ops:
        try:
            await db.dependencies.bulk_write(bulk_ops, ordered=False)
            total_updated += len(bulk_ops)
        except Exception as e:
            logger.exception("Failed to bulk update dependencies: %s", e)

    persisted = await DependencyEnrichmentRepository(db).upsert_many(enrichment_entries)
    logger.info(f"Bulk updated {total_updated} dependencies.")
    logger.info(f"Upserted {persisted} dependency enrichments.")


async def _run_epss_kev_enrichment(
    vulnerability_findings: list[dict[str, Any]],
    scan_id: str,
    result_repo: AnalysisResultRepository,
    github_token: str | None,
    results_summary: list[str],
) -> None:
    """Run EPSS/KEV enrichment on vulnerability findings."""
    try:
        _, unavailable = await vulnerability_enrichment_service.enrich_findings(
            vulnerability_findings, github_token=github_token
        )
        epss_kev_summary = build_epss_kev_summary(vulnerability_findings)
        await result_repo.save_result(scan_id, "epss_kev", epss_kev_summary)
        outcome = f"Partial ({' and '.join(unavailable)} unavailable)" if unavailable else "Success"
        results_summary.append(f"epss_kev: {outcome} ({len(vulnerability_findings)} enriched)")
        logger.info(f"[epss_kev] Enriched {len(vulnerability_findings)} vulnerability findings with EPSS/KEV data")

        if analysis_enrichment_total:
            analysis_enrichment_total.labels(type="epss_kev").inc(len(vulnerability_findings))

        for vf in vulnerability_findings:
            details = vf.get("details", {})
            epss_score = details.get("epss_score")
            if epss_score is not None and analysis_epss_scores:
                with contextlib.suppress(ValueError, TypeError):
                    analysis_epss_scores.observe(float(epss_score))
            if details.get(DETAILS_KEY_IN_KEV) and analysis_kev_vulnerabilities_total:
                analysis_kev_vulnerabilities_total.inc()

    except Exception as e:
        results_summary.append("epss_kev: Failed")
        logger.warning(f"[epss_kev] Failed to enrich findings: {e}")


async def _run_reachability_enrichment(
    vulnerability_findings: list[dict[str, Any]],
    scan_id: str,
    project_id: str,
    db: Database,
    scan_repo: ScanRepository,
    results_summary: list[str],
) -> ComponentLanguages | None:
    """Run reachability analysis on vulnerability findings; returns the inventory language map it built."""
    callgraphs = await fetch_callgraphs(project_id, scan_id, db)
    if not callgraphs:
        await scan_repo.update_raw(scan_id, {"$set": {"reachability_pending": True}})
        logger.info(f"[reachability] No callgraph available for scan {scan_id}. Marked as pending.")
        return None

    try:
        component_languages, enriched_count = await apply_reachability(db, scan_id, vulnerability_findings, callgraphs)
    except Exception as e:
        results_summary.append("reachability: Failed")
        logger.warning(f"[reachability] Failed to enrich findings: {e}")
        return None
    results_summary.append(f"reachability: Success ({enriched_count} enriched)")
    return component_languages


async def _load_project_settings_overrides(
    project_id: str | None, project_repo: ProjectRepository
) -> dict[str, dict[str, Any]] | None:
    if not project_id:
        return None
    project_doc = await project_repo.get_by_id(project_id)
    return project_doc.analyzer_settings if project_doc else None


async def _aggregate_external_results(
    aggregator: ResultAggregator,
    result_repo: AnalysisResultRepository,
    scan_id: str,
    results_summary: list[str],
) -> None:
    """Fetch external analyzer results and aggregate them; failures land in results_summary."""
    query = {"scan_id": scan_id, "analyzer_name": {"$nin": list(_ENGINE_RESULT_NAMES)}}
    async for row in result_repo.iterate_raw(query, {"analyzer_name": 1, "result": 1}):
        analyzer_name = row["analyzer_name"]
        try:
            result = row["result"]
            aggregator.aggregate(analyzer_name, result)
            if is_error_result(result):
                # Error-shaped rows aggregate into a SCAN-ERROR finding without raising.
                results_summary.append(f"{analyzer_name}: Failed")
            else:
                results_summary.append(f"{analyzer_name}: Success")
        except Exception as exc:
            logger.warning(
                "_aggregate_external_results: skipping malformed result for analyzer=%s scan=%s: %s",
                analyzer_name,
                scan_id,
                exc,
            )
            aggregator.add_scan_error(
                analyzer_name, f"external result could not be aggregated: {exc}", error_details=str(exc)
            )
            results_summary.append(f"{analyzer_name}: Failed")


def _cleanup_analyzer_names(active_analyzers: list[str]) -> list[str]:
    """Analyzer result-row names to purge before a (re)run: internal, post-processor, and crypto.

    Crypto/post-processor rows are regenerated per run whatever active_analyzers says, so they are purged explicitly.
    """
    internal_analyzers = [name for name in active_analyzers if name in analyzer_factories]
    return sorted(set(internal_analyzers) | set(_POST_PROCESSOR_ANALYZERS) | set(CRYPTO_ANALYZERS))


def _prepare_finding_records(
    aggregated_findings: list[Any],
    scan_id: str,
    project_id: str | None,
    scan_created_at: datetime | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Convert aggregated findings to insertion records, splitting out vulnerabilities.

    ``_id`` is deterministic per (scan, finding identity) so a re-analysis or a raced double-persist
    writes over the stored copy instead of storing the whole finding set twice.
    """
    findings_to_insert: list[dict[str, Any]] = []
    vulnerability_findings: list[dict[str, Any]] = []
    seen_identities: dict[str, int] = {}
    for f in aggregated_findings:
        record: dict[str, Any] = f.model_dump()
        record["scan_id"] = scan_id
        record["project_id"] = project_id
        record["finding_id"] = f.id
        identity = f"{scan_id}:{record.get('type')}:{record.get('component')}:{record.get('version')}:{f.id}"
        occurrence = seen_identities.get(identity, 0)
        seen_identities[identity] = occurrence + 1
        if occurrence:
            identity = f"{identity}:{occurrence}"
        record["_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, identity))
        record.setdefault("scan_created_at", scan_created_at)
        findings_to_insert.append(record)
        if record.get("type") == "vulnerability":
            vulnerability_findings.append(record)
    return findings_to_insert, vulnerability_findings


# Bounds persisted findings_summary so the scan doc stays under Mongo's 16MB limit.
_FINDINGS_SUMMARY_LIMIT = 500


def _build_findings_summary(
    vulnerability_findings: list[dict[str, Any]],
    limit: int = _FINDINGS_SUMMARY_LIMIT,
) -> list[dict[str, Any]]:
    """Compact, bounded, vulnerability-only summary; details trimmed to the CVE id to bound size."""
    summary: list[dict[str, Any]] = []
    for record in vulnerability_findings[:limit]:
        cve_id = display_vulnerability_id(record.get("details"))
        summary.append(
            {
                "id": record.get("id"),
                "type": "vulnerability",
                "severity": record.get("severity"),
                "component": record.get("component"),
                "version": record.get("version"),
                "description": (record.get("description") or "")[:200],
                "scanners": record.get("scanners") or [],
                "details": VulnerabilitySummaryDetails(cve_id=cve_id).model_dump(exclude_none=True),
            }
        )
    return summary


async def _run_vuln_enrichments(
    active_analyzers: list[str],
    vulnerability_findings: list[dict[str, Any]],
    scan_id: str,
    project_id: str | None,
    db: Database,
    result_repo: AnalysisResultRepository,
    scan_repo: ScanRepository,
    github_token: str | None,
    results_summary: list[str],
) -> ComponentLanguages | None:
    """Run the vulnerability enrichments; returns the inventory language map reachability built."""
    if "epss_kev" in active_analyzers and vulnerability_findings:
        await _run_epss_kev_enrichment(vulnerability_findings, scan_id, result_repo, github_token, results_summary)

    if "reachability" in active_analyzers and vulnerability_findings and project_id:
        return await _run_reachability_enrichment(
            vulnerability_findings, scan_id, project_id, db, scan_repo, results_summary
        )
    return None


async def _stamp_first_seen(
    records: list[dict[str, Any]], project_id: str | None, finding_repo: FindingRepository
) -> None:
    """Carry each finding's earliest detection in the project forward, since retention deletes the
    scans that first saw it and the SLA age has to survive them."""
    earliest = await finding_repo.earliest_detections(project_id, records) if project_id else {}
    for record in records:
        detections = (earliest.get(finding_identity(record)), record["scan_created_at"])
        record["first_seen_at"] = min(d for d in detections if d is not None)


def _fit_finding(record: dict[str, Any]) -> dict[str, Any]:
    """The record, with its advisories slimmed when a vulnerability finding outgrows a Mongo document."""
    size = len(bson.encode(record))
    if size <= _MAX_DOCUMENT_BYTES:
        return record
    if record["type"] == "vulnerability":
        details = record["details"]
        advisories = [
            {k: v for k, v in e.items() if k not in _SLIMMED_ADVISORY_FIELDS} for e in details["vulnerabilities"]
        ]
        slim = {**record, "details": {**details, "vulnerabilities": advisories}}
        if len(bson.encode(slim)) <= _MAX_DOCUMENT_BYTES:
            logger.warning(
                "Finding %s exceeds 16 MiB (%d bytes); stored with slim advisories", record["finding_id"], size
            )
            return slim
    raise DocumentTooLarge(f"Finding {record['finding_id']} is {size} bytes, over the 16 MiB document limit")


async def _persist_findings_and_waivers(
    findings_to_insert: list[dict[str, Any]],
    scan_id: str,
    project_id: str | None,
    finding_repo: FindingRepository,
    db: Database,
) -> int:
    """Write findings over the scan's stored ones and stamp the waiver set on them and the scan; returns the count."""
    # Before the write, so re-analysing a scan still sees the dates its own copies inherited.
    await _stamp_first_seen(findings_to_insert, project_id, finding_repo)
    written_at = datetime.now(timezone.utc)
    for record in findings_to_insert:
        record["created_at"] = written_at
    # Fitted before the first write: the server drops a document just over 16 MiB from the batch without failing it.
    fitted = [_fit_finding(record) for record in findings_to_insert]
    persisted_count = 0
    for i in range(0, len(fitted), _BULK_CHUNK_SIZE):
        persisted_count += await finding_repo.replace_many_raw(fitted[i : i + _BULK_CHUNK_SIZE])
    # Only after every chunk is written, so a persist that raises leaves the previous findings in place.
    await finding_repo.delete_older_writes({"scan_id": scan_id}, written_at)

    waivers = await WaiverRepository(db).find_active_for_project(project_id) if project_id else []
    matches = await restamp_waivers(finding_repo, None, scan_id, waivers)
    await ScanRepository(db).update_raw(scan_id, {"$set": {"waiver_fingerprint": waiver_fingerprint(waivers)}})
    for waiver in waivers:
        if matches[waiver.id]:
            analysis_waivers_applied_total.labels(type=route_waiver(waiver)).inc()
    return persisted_count


async def _apply_handed_over_callgraphs(scan_id: str, project_id: str | None, db: Database) -> None:
    # A callgraph uploaded during the run only flagged the scan, since the findings it would enrich were being replaced.
    try:
        state = await ScanRepository(db).get_minimal_by_id(scan_id)
        if project_id and state and state.reachability_pending:
            await run_pending_reachability_for_scan(scan_id, project_id, db)
    except Exception:
        # A failed pass stays flagged for the next upload; the final scan is still announced.
        logger.exception("Scan %s: applying the callgraphs uploaded during the analysis failed", scan_id)


async def _write_final_state(
    scan_repo: ScanRepository,
    scan_id: str,
    status: ScanStatus,
    update: dict[str, Any],
    *,
    worker_id: str,
    sbom_generation: int | None,
    external_load_start: datetime,
) -> ScanStatus | None:
    """Apply ``update`` while this run holds the scan and saw all its input.

    Returns ``status`` once written, PENDING when new input arrived during the run (rescheduled),
    and None when the claim moved to another run, which then owns the scan.
    """
    # A replaced SBOM, or a scanner result that arrived after loading began, would otherwise be
    # finalized over and never analysed.
    guard: dict[str, Any] = {
        "_id": scan_id,
        "status": SCAN_STATUS_PROCESSING,
        "worker_id": worker_id,
        "sbom_generation": sbom_generation,
        "$or": [
            {"last_result_at": {"$exists": False}},
            {"last_result_at": None},
            {"last_result_at": {"$lt": external_load_start}},
        ],
    }
    if await scan_repo.collection.find_one_and_update(guard, update) is not None:
        return status
    if not await scan_repo.requeue(scan_id, worker_id, counter="retry_count"):
        logger.warning("Scan %s: the claim moved to another run; leaving the scan to it.", scan_id)
        return None
    logger.warning("Scan %s: new input arrived during analysis; rescheduled instead of finalizing.", scan_id)
    if analysis_race_conditions_total:
        analysis_race_conditions_total.inc()
    return SCAN_STATUS_PENDING


async def _finalize_scan_and_project(
    scan_id: str,
    scan_doc: Any,
    project_id: str | None,
    total_findings_count: int,
    ignored_count: int,
    stats: Any,
    latest_run_summary: dict,
    scan_repo: ScanRepository,
    *,
    worker_id: str,
    external_load_start: datetime,
    status: ScanStatus = SCAN_STATUS_COMPLETED,
    error: str | None = None,
    findings_summary: list[dict[str, Any]] | None = None,
    failed_analyzers: list[str] | None = None,
    enrichment_failures: list[str] | None = None,
    sbom_generation: int | None = None,
) -> ScanStatus | None:
    """Persist the final scan status, ignored count, and (on success) project stats; returns what
    ``_write_final_state`` returns."""
    set_fields: dict[str, Any] = {
        "status": status,
        "findings_count": total_findings_count,
        "ignored_count": ignored_count,
        "stats": stats.model_dump(),
        "completed_at": datetime.now(timezone.utc),
        "latest_run": latest_run_summary,
        "findings_summary": findings_summary or [],
        "failed_analyzers": failed_analyzers or None,
        "enrichment_failures": enrichment_failures or None,
    }
    if error:
        set_fields["error"] = error
    unset_fields = {
        "received_results": "",
        "last_result_at": "",
    }
    if status in SCAN_USABLE_STATUSES and not scan_doc.is_rescan:
        # This analysis post-dates every rescan of the build, which may still hold a replaced SBOM.
        unset_fields["latest_rescan_id"] = ""

    outcome = await _write_final_state(
        scan_repo,
        scan_id,
        status,
        {"$set": set_fields, "$unset": unset_fields},
        worker_id=worker_id,
        sbom_generation=sbom_generation,
        external_load_start=external_load_start,
    )
    if outcome != status:
        return outcome

    if scan_doc.is_rescan and scan_doc.original_scan_id:
        # latest_run reports every run, while the lineage moves only onto an analysis head may report.
        root_fields: dict[str, Any] = {"latest_run": latest_run_summary}
        if status in SCAN_USABLE_STATUSES:
            root_fields["latest_rescan_id"] = scan_id
        await scan_repo.report_rescan_run(scan_doc.original_scan_id, scan_doc.sbom_generation, root_fields)

    if project_id and status != SCAN_STATUS_FAILED and await scan_repo.sync_project_head(project_id) == scan_id:
        # Only head records waiver outcomes, and head is known once sync_project_head derived it.
        try:
            waiver_repo = WaiverRepository(scan_repo.db)
            waivers = await waiver_repo.find_active_for_project(project_id)
            await restamp_waivers(FindingRepository(scan_repo.db), waiver_repo, scan_id, waivers)
        except Exception:
            # Best effort like the announcement: the scan is already final.
            logger.exception("Scan %s: recording the waiver outcomes on head failed", scan_id)
    return status


async def _filter_out_waived_findings(
    findings: list[dict[str, Any]], scan_id: str, db: Database
) -> list[dict[str, Any]]:
    """Drop the records waived in this scan, re-read from the DB because waivers are applied only there."""
    finding_repo = FindingRepository(db)
    waived = {doc["_id"] async for doc in finding_repo.iterate_raw({"scan_id": scan_id, "waived": True}, {"_id": 1})}
    return [record for record in findings if record["_id"] not in waived]


async def _send_integrations_and_notifications(
    project_id: str | None,
    scan_id: str,
    scan_doc: Any,
    stats: Stats,
    status: ScanStatus,
    error: str | None,
    failed_analyzers: list[str],
    findings: list[dict[str, Any]],
    analyzer_outcomes: dict[str, str],
    db: Database,
) -> None:
    if not project_id:
        return
    project = await ProjectRepository(db).get_by_id(project_id)
    if not project:
        return
    await decorate_gitlab_mr(scan_id, stats, status, error, scan_doc, project, db)
    await decorate_github_pr(scan_id, stats, status, error, scan_doc, project, db)
    await send_scan_notifications(
        scan_id,
        project,
        findings,
        stats,
        status,
        failed_analyzers,
        analyzer_outcomes,
        analyzer_count=sum(1 for name in analyzer_outcomes if name not in _POST_PROCESSOR_ANALYZERS),
        db=db,
    )


def _release_memory_to_os() -> None:
    """Force gc and release glibc heap pages back to OS (Linux-only)."""
    import gc

    gc.collect()
    try:
        import ctypes

        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except (OSError, AttributeError):
        pass


def _partial_run_reasons(
    failed_analyzers: list[str],
    sbom_load_failures: int,
    sbom_parse_failures: int,
    sboms_expected: int,
    persisted_findings_count: int,
    total_findings_count: int,
) -> list[str]:
    reasons: list[str] = []
    if failed_analyzers:
        reasons.append(f"analyzers failed or returned partial results: {', '.join(failed_analyzers)}")
    if sbom_load_failures:
        reasons.append(f"{sbom_load_failures} of {sboms_expected} SBOMs failed to load")
    if sbom_parse_failures:
        reasons.append(
            f"{sbom_parse_failures} of {sboms_expected} SBOMs failed to parse; dependency inventory left unchanged"
        )
    if persisted_findings_count < total_findings_count:
        reasons.append(f"only {persisted_findings_count} of {total_findings_count} findings were persisted")
    return reasons


def _final_scan_status(scan_id: str, sboms_unusable: bool, partial_reasons: list[str]) -> tuple[ScanStatus, str | None]:
    if sboms_unusable:
        return SCAN_STATUS_FAILED, "SBOM could not be loaded or parsed for analysis"
    if partial_reasons:
        error = "; ".join(partial_reasons)
        logger.warning("Scan %s completed with errors: %s", scan_id, error)
        return SCAN_STATUS_COMPLETED_WITH_ERRORS, error
    return SCAN_STATUS_COMPLETED, None


async def _announce_outcome(
    status: ScanStatus,
    error: str | None,
    failed_analyzers: list[str],
    project_id: str | None,
    scan_id: str,
    scan_doc: Scan,
    stats: Stats,
    findings: list[dict[str, Any]],
    analyzer_outcomes: dict[str, str],
    db: Database,
) -> None:
    """Best effort: the scan is already final, so a failure here is logged and never changes it."""
    try:
        await _apply_handed_over_callgraphs(scan_id, project_id, db)
        if status == SCAN_STATUS_FAILED:
            await notify_analysis_failed(db, scan_id, project_id, error or status)
            return
        notify_findings = await _filter_out_waived_findings(findings, scan_id, db)
        await _send_integrations_and_notifications(
            project_id,
            scan_id,
            scan_doc,
            stats,
            status,
            error,
            failed_analyzers,
            notify_findings,
            analyzer_outcomes,
            db,
        )
    except Exception:
        logger.exception("Scan %s: announcing the finished analysis failed", scan_id)


async def run_analysis(
    scan_id: str,
    sboms: list[dict[str, Any]],
    active_analyzers: list[str],
    db: Database,
    *,
    worker_id: str,
    sbom_generation: int | None = None,
) -> ScanStatus | None:
    """Analyse a scan claimed by ``worker_id``; returns what ``_finalize_scan_and_project`` returns,
    or None when the scan is gone or the claim was lost before the results were written.

    ``sboms`` and ``sbom_generation`` come from the same claimed scan document.
    """
    logger.info(f"Starting analysis for scan {scan_id}")
    aggregation_start_time = time.time()
    aggregator = ResultAggregator()
    results_summary: list[str] = []

    scan_repo = ScanRepository(db)
    result_repo = AnalysisResultRepository(db)
    finding_repo = FindingRepository(db)
    project_repo = ProjectRepository(db)

    scan_doc = await scan_repo.get_by_id(scan_id)
    if not scan_doc:
        logger.error(f"Scan {scan_id} not found")
        return None

    project_id: str | None = scan_doc.project_id
    scan_type: str | None = getattr(scan_doc, "scan_type", None)

    fs = AsyncIOMotorGridFSBucket(db)

    load_start = datetime.now(timezone.utc)
    # Resolved before the first delete, so an SBOM that fails to load leaves the stored analysis intact.
    resolved_sboms: list[dict[str, Any] | None] = [await _resolve_sbom(item, fs, aggregator) for item in sboms]
    sbom_load_failures = sum(1 for resolved in resolved_sboms if resolved is None)
    sboms_expected = len(resolved_sboms)
    gridfs_expected = _count_gridfs_refs(sboms)
    if sbom_load_failures and scan_doc.completed_at is not None:
        # Retried while the worker still re-queues, so the input that reopened the scan gets analysed.
        if scan_doc.retry_count + 1 < ANALYSIS_MAX_RETRIES:
            logger.warning("Scan %s: an SBOM failed to load; retrying the re-analysis", scan_id)
            return SCAN_STATUS_PENDING if await scan_repo.requeue(scan_id, worker_id, counter="retry_count") else None
        logger.warning("Scan %s: an SBOM failed to load on the last attempt; keeping the previous analysis", scan_id)
        error = "SBOM could not be loaded for re-analysis; findings are from the previous analysis"
        outcome = await _write_final_state(
            scan_repo,
            scan_id,
            SCAN_STATUS_COMPLETED_WITH_ERRORS,
            {"$set": {"status": SCAN_STATUS_COMPLETED_WITH_ERRORS, "error": error}},
            worker_id=worker_id,
            sbom_generation=sbom_generation,
            external_load_start=load_start,
        )
        if outcome == SCAN_STATUS_COMPLETED_WITH_ERRORS and project_id:
            await scan_repo.sync_project_head(project_id)
            await _apply_handed_over_callgraphs(scan_id, project_id, db)
        return outcome

    await result_repo.delete_many(
        {"scan_id": scan_id, "analyzer_name": {"$in": _cleanup_analyzer_names(active_analyzers)}}
    )

    if scan_doc.is_rescan and analysis_rescan_operations_total:
        analysis_rescan_operations_total.inc()

    # Before the SBOM loop: an embedded CBOM re-persists over the carried copy of the same asset.
    await _carry_over_external_results(scan_id, scan_doc, db)
    await _carry_over_crypto_assets(scan_id, scan_doc, db)

    settings_repo = SystemSettingsRepository(db)
    system_settings = await settings_repo.get()
    github_token = system_settings.github_token or await _get_github_instance_token(db)

    project_analyzer_settings = await _load_project_settings_overrides(project_id, project_repo)

    if sbom_load_failures:
        logger.warning(
            "Scan %s: %d/%d SBOMs failed to resolve; skipping dependency persistence to keep stored dependencies",
            scan_id,
            sbom_load_failures,
            sboms_expected,
        )

    payload: list[ParsedSBOM | None] = []
    for index, current_sbom in enumerate(resolved_sboms):
        if current_sbom is None:
            payload.append(None)
            continue
        sbom_results = await _process_sbom(
            index,
            current_sbom,
            scan_id,
            db,
            aggregator,
            active_analyzers,
            system_settings,
            project_analyzer_settings=project_analyzer_settings,
            project_id=project_id,
            scan_type=scan_type,
            payload=payload,
            github_token=github_token,
        )
        resolved_sboms[index] = None
        results_summary.extend(sbom_results)

    if project_id and (scan_type == "cbom" or any(p is not None and p.crypto_assets for p in payload)):
        results_summary.extend(await _run_crypto_analyzers(project_id, scan_id, db, aggregator))

    if not await scan_repo.renew_claim(scan_id, worker_id):
        logger.warning("Scan %s: the claim moved to another run; stopping before writing results.", scan_id)
        return None

    sbom_parse_failures = payload.count(None) - sbom_load_failures
    if project_id:
        stored = await store_scan_dependencies(payload, project_id, scan_id, DependencyRepository(db))
        if stored is not None:
            logger.info(f"Stored {stored} dependencies for scan {scan_id}")
    del payload

    external_load_start = datetime.now(timezone.utc)
    await _aggregate_external_results(aggregator, result_repo, scan_id, results_summary)

    aggregated_findings = aggregator.get_findings()
    _track_findings_metrics(aggregated_findings)
    dependency_enrichments = aggregator.get_dependency_enrichments()
    del aggregator

    await _enrich_dependencies(dependency_enrichments, scan_id, db)
    del dependency_enrichments

    scan_created_at: datetime | None = getattr(scan_doc, "created_at", None)
    findings_to_insert, vulnerability_findings = _prepare_finding_records(
        aggregated_findings, scan_id, project_id, scan_created_at
    )
    del aggregated_findings
    total_findings_count = len(findings_to_insert)

    component_languages = await _run_vuln_enrichments(
        active_analyzers,
        vulnerability_findings,
        scan_id,
        project_id,
        db,
        result_repo,
        scan_repo,
        github_token,
        results_summary,
    )
    refresh_vulnerability_info(findings_to_insert)

    if not await scan_repo.renew_claim(scan_id, worker_id):
        logger.warning("Scan %s: the claim moved to another run; stopping before writing results.", scan_id)
        return None

    persisted_findings_count = await _persist_findings_and_waivers(
        findings_to_insert, scan_id, project_id, finding_repo, db
    )
    stats, ignored_count = await calculate_comprehensive_stats(db, scan_id, component_languages)

    # A rescan has no stored inventory to fall back on, so a partial payload would leave it without one.
    sboms_unusable = (scan_doc.is_rescan and sbom_load_failures + sbom_parse_failures > 0) or (
        sbom_load_failures > 0 and sbom_load_failures == gridfs_expected
    )
    if sboms_unusable:
        logger.error(
            "Scan %s: %d/%d SBOMs failed to load and %d failed to parse; marking failed",
            scan_id,
            sbom_load_failures,
            sboms_expected,
            sbom_parse_failures,
        )

    analyzer_outcomes = _analyzer_outcomes(results_summary)
    failed_analyzers, enrichment_failures = _failed_analyzer_names(analyzer_outcomes)
    partial_reasons = _partial_run_reasons(
        failed_analyzers,
        sbom_load_failures,
        sbom_parse_failures,
        sboms_expected,
        persisted_findings_count,
        total_findings_count,
    )
    total_findings_count = persisted_findings_count
    final_status, final_error = _final_scan_status(scan_id, sboms_unusable, partial_reasons)

    latest_run_summary = {
        "scan_id": scan_id,
        "status": final_status,
        "findings_count": total_findings_count,
        "stats": stats.model_dump(),
        "completed_at": datetime.now(timezone.utc),
    }

    if analysis_aggregation_duration_seconds:
        analysis_aggregation_duration_seconds.observe(time.time() - aggregation_start_time)

    outcome = await _finalize_scan_and_project(
        scan_id,
        scan_doc,
        project_id,
        total_findings_count,
        ignored_count,
        stats,
        latest_run_summary,
        scan_repo,
        worker_id=worker_id,
        external_load_start=external_load_start,
        status=final_status,
        error=final_error,
        findings_summary=_build_findings_summary(vulnerability_findings),
        failed_analyzers=failed_analyzers,
        enrichment_failures=enrichment_failures,
        sbom_generation=sbom_generation,
    )
    if outcome != final_status:
        del findings_to_insert, vulnerability_findings
        _release_memory_to_os()
        return outcome

    await _announce_outcome(
        final_status,
        final_error,
        failed_analyzers,
        project_id,
        scan_id,
        scan_doc,
        stats,
        findings_to_insert,
        analyzer_outcomes,
        db,
    )
    del findings_to_insert, vulnerability_findings

    # Runs on the released findings: the rollup holds two dependency maps of its own.
    await record_scan_update_delta(db, scan_id)

    _release_memory_to_os()

    return outcome
