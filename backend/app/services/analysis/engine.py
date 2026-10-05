import asyncio
import contextlib
import json
import logging
import os
import re
import tempfile
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import bson
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo import UpdateMany
from pymongo.errors import DocumentTooLarge

from app.core.constants import (
    ANALYSIS_MAX_RETRIES,
    DETAILS_KEY_IN_KEV,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
    ScanStatus,
    SCAN_USABLE_STATUSES,
)
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
from app.db.mongodb import open_gridfs_download_with_retry
from app.models.crypto_asset import CryptoAsset
from app.models.finding import Finding
from app.models.project import Scan
from app.models.stats import Stats
from app.repositories.analysis_results import RESULT_PROJECTION, AnalysisResultRepository
from app.repositories.crypto_asset import CryptoAssetRepository, scan_query
from app.repositories.dependencies import DependencyRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.repositories.findings import FindingRepository, finding_identity
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.waivers import WaiverRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.cbom import CryptoAssetType
from app.schemas.sbom import ParsedSBOM, SBOMFormat
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
from app.services.analyzers import Analyzer, CLIAnalyzer
from app.services.analyzers.cli_base import TEMP_SBOM_PREFIX
from app.services.analyzers.crypto.catalogs.loader import CipherSuiteEntry, load_iana_catalog
from app.services.crypto_policy.resolver import CryptoPolicyResolver, EffectivePolicy
from app.services.dependency_store import store_scan_dependencies
from app.services.enrichment.service import vulnerability_enrichment_service
from app.services.github import is_public_github
from app.services.gridfs_maintenance import gridfs_ref_id
from app.services.reachability_enrichment import (
    ComponentLanguages,
    apply_reachability,
    fetch_callgraphs,
    run_pending_reachability_for_scan,
)
from app.services.sbom_parser import parse_sbom, sbom_parser
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
        await CryptoAssetRepository(db).carry_over_to_scan(scan_doc.project_id, scan_doc.original_scan_id, scan_id)
    except Exception as e:
        logger.exception("Failed to carry over crypto assets to rescan %s: %s", scan_id, e)


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
    await AnalysisResultRepository(db).save_result(scan_id, analyzer_name, result, source=row_source)

    # CLI analyzers report timeouts/exit-codes/bad JSON as error dicts instead of raising.
    if is_error_result(result):
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
    analysis_errors_total.labels(analyzer=analyzer_name).inc()
    # Surface the failure as a finding.
    aggregator.add_scan_error(analyzer_name, str(error), source=f"System: {analyzer_name}")
    return f"{analyzer_name}: Failed"


async def process_analyzer(
    analyzer_name: str,
    analyzer: Analyzer,
    scan_id: str,
    db: Database,
    aggregator: ResultAggregator,
    *,
    settings: dict[str, Any],
    source: str,
    row_source: str,
    parsed_components: list[dict[str, Any]],
    sbom_path: str | None,
    sbom_format: SBOMFormat,
) -> str:
    analyzer_start_time = time.time()
    try:
        analysis_scans_total.labels(analyzer=analyzer_name).inc()

        if isinstance(analyzer, CLIAnalyzer):
            assert sbom_path is not None
            result = await analyzer.analyze_file(sbom_path, sbom_format)
        else:
            result = await analyzer.analyze({}, settings=settings, parsed_components=parsed_components)

        analysis_duration_seconds.labels(analyzer=analyzer_name).observe(time.time() - analyzer_start_time)

        return await _record_result(analyzer_name, result, scan_id, db, aggregator, source, row_source=row_source)
    except Exception as e:
        return _analyzer_failed(analyzer_name, e, aggregator)


def _evaluate_crypto(
    docs: list[dict[str, Any]], policy: EffectivePolicy, catalog: dict[str, CipherSuiteEntry]
) -> dict[str, dict[str, Any]]:
    assets = [CryptoAsset.model_validate(d) for d in docs]
    results: dict[str, dict[str, Any]] = {}
    for name, evaluate in crypto_evaluators(catalog).items():
        started = time.time()
        analysis_scans_total.labels(analyzer=name).inc()
        try:
            results[name] = evaluate(assets, policy)
        except Exception as e:
            logger.exception("Analysis %s failed: %s", name, e)
            results[name] = {"error": str(e), "findings": []}
        analysis_duration_seconds.labels(analyzer=name).observe(time.time() - started)
    return results


async def _run_crypto_analyzers(project_id: str, scan_id: str, db: Database, aggregator: ResultAggregator) -> list[str]:
    """Evaluate the scan's stored crypto assets once, after every SBOM's embedded assets are persisted."""
    try:
        docs = await CryptoAssetRepository(db).find_all_raw(scan_query(project_id, scan_id))
        policy = await CryptoPolicyResolver(db).resolve(project_id)
        has_protocols = any(d.get("asset_type") == CryptoAssetType.PROTOCOL for d in docs)
        catalog = await load_iana_catalog() if has_protocols else {}
        results = await asyncio.to_thread(_evaluate_crypto, docs, policy, catalog)
    except Exception as e:
        return [_analyzer_failed(name, e, aggregator) for name in sorted(CRYPTO_ANALYZERS)]

    summary: list[str] = []
    for name, result in results.items():
        try:
            summary.append(await _record_result(name, result, scan_id, db, aggregator, _CRYPTO_SOURCE))
        except Exception as e:
            summary.append(_analyzer_failed(name, e, aggregator))
    return summary


# Marker substring of the system-error raised when a GridFS SBOM cannot be read.
_SBOM_GRIDFS_LOAD_ERROR = "Failed to load SBOM from GridFS"


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


def _sbom_load_failed(aggregator: ResultAggregator, reason: object) -> None:
    analysis_gridfs_operations_total.labels(operation="download", status="error").inc()
    aggregator.add_scan_error("system", f"{_SBOM_GRIDFS_LOAD_ERROR}: {reason}")


async def _stored_sbom_ids(
    fs: AsyncIOMotorGridFSBucket, sboms: list[Any], aggregator: ResultAggregator
) -> list[str | None]:
    """Each ref's GridFS id, or None with the load failure recorded when no stored file backs it."""
    gridfs_ids = [gridfs_ref_id(item) for item in sboms]
    wanted = [bson.ObjectId(gid) for gid in gridfs_ids if gid and bson.ObjectId.is_valid(gid)]
    stored = {str(file._id) async for file in fs.find({"_id": {"$in": wanted}})} if wanted else set()
    for gid in gridfs_ids:
        if gid not in stored:
            logger.error("%s: %s is not stored", _SBOM_GRIDFS_LOAD_ERROR, gid)
            _sbom_load_failed(aggregator, f"{gid} is not stored")
    return [gid if gid in stored else None for gid in gridfs_ids]


_ParsedDocument = tuple[ParsedSBOM | None, list[dict[str, Any]], str | None, SBOMFormat]


async def _load_sbom(
    fs: AsyncIOMotorGridFSBucket, gridfs_id: str, write_file: bool
) -> tuple[str | None, _ParsedDocument]:
    """Download one stored SBOM, write its bytes for the CLI scanners when asked, and parse it."""
    analysis_gridfs_operations_total.labels(operation="download", status="attempt").inc()
    data = await (await open_gridfs_download_with_retry(fs, bson.ObjectId(gridfs_id))).read()
    path = None
    try:
        if write_file:
            fd, path = tempfile.mkstemp(prefix=TEMP_SBOM_PREFIX, suffix=".json")
            os.close(fd)
            await asyncio.to_thread(Path(path).write_bytes, data)
        document = await asyncio.to_thread(json.loads, data)
        del data
        analysis_gridfs_operations_total.labels(operation="download", status="success").inc()
        return path, await asyncio.to_thread(_parse_and_track_sbom, document)
    except BaseException:
        if path:
            os.remove(path)
        raise


def _sbom_source(sbom: dict[str, Any]) -> str | None:
    """The SBOM's root component name, else its serial number."""
    metadata = sbom.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        # An explicit ``"name": null`` is a present key, so a dict default would never fire.
        name = metadata["component"].get("name")
        if name:
            return str(name)
    serial = sbom.get("serialNumber")
    return str(serial) if serial else None


def _parse_and_track_sbom(document: Any) -> _ParsedDocument:
    """Pre-parse the SBOM and track metrics; a document that fails to parse leaves only the raw-document scanners."""
    parsed_components: list[dict[str, Any]] = []
    parsed_sbom = None
    source, sbom_format = None, SBOMFormat.UNKNOWN
    try:
        source, sbom_format = _sbom_source(document), sbom_parser.detect_format(document)
        parsed_sbom = parse_sbom(document)
        parsed_components = [dep.to_dict() for dep in parsed_sbom.dependencies]
        logger.info(
            f"Parsed SBOM: format={parsed_sbom.format.value}, components={len(parsed_components)}, "
            f"skipped={parsed_sbom.skipped_components}, merged={parsed_sbom.merged_components}, "
            f"skipped_reasons={parsed_sbom.skipped_reasons}"
        )
        analysis_sbom_processed_total.labels(format=parsed_sbom.format.value).inc()
        analysis_components_parsed_total.inc(len(parsed_components))
    except Exception as parse_err:
        logger.warning(f"Failed to pre-parse SBOM: {parse_err} - only the raw-document scanners will run")
        analysis_sbom_parse_errors_total.inc()
    return parsed_sbom, parsed_components, source, sbom_format


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
    parsed_sbom: ParsedSBOM | None,
    parsed_components: list[dict[str, Any]],
    source: str | None,
    sbom_path: str | None,
    sbom_format: SBOMFormat,
    scan_id: str,
    db: Database,
    aggregator: ResultAggregator,
    active_analyzers: list[str],
    system_settings: Any,
    project_analyzer_settings: dict[str, dict[str, Any]] | None = None,
    project_id: str | None = None,
    scan_type: str | None = None,
    github_token: str | None = None,
) -> list[str]:
    """Run the analyzers over one loaded SBOM; returns the results summary."""
    # Rows are keyed on the SBOM's position: root names repeat within a scan (multi-arch images).
    row_source = f"SBOM #{index + 1}"

    if parsed_sbom is not None and parsed_sbom.crypto_assets and project_id:
        await _persist_embedded_crypto_assets(parsed_sbom, project_id, scan_id, db)

    effective_analyzers = _resolve_effective_analyzers(active_analyzers, parsed_sbom, parsed_components, scan_type)

    settings_for = _build_settings_resolver(system_settings, project_analyzer_settings, github_token)

    tasks = [
        process_analyzer(
            analyzer_name,
            analyzer_factories[analyzer_name](),
            scan_id,
            db,
            aggregator,
            settings=settings_for(analyzer_name),
            source=source or row_source,
            row_source=row_source,
            parsed_components=parsed_components,
            sbom_path=sbom_path,
            sbom_format=sbom_format,
        )
        for analyzer_name in effective_analyzers
        if analyzer_name in analyzer_factories
    ]

    return list(await asyncio.gather(*tasks))


def _track_findings_metrics(aggregated_findings: list[Finding]) -> None:
    """Track Prometheus metrics for aggregated findings."""
    for finding in aggregated_findings:
        analysis_findings_by_type_total.labels(type=finding.type, severity=finding.severity).inc()
        for scanner_name in finding.scanners:
            analysis_findings_total.labels(analyzer=scanner_name, severity=finding.severity).inc()


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

        analysis_enrichment_total.labels(type="epss_kev").inc(len(vulnerability_findings))

        for vf in vulnerability_findings:
            details = vf.get("details", {})
            epss_score = details.get("epss_score")
            if epss_score is not None:
                with contextlib.suppress(ValueError, TypeError):
                    analysis_epss_scores.observe(float(epss_score))
            if details.get(DETAILS_KEY_IN_KEV):
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
    async for row in result_repo.iterate_raw(query, RESULT_PROJECTION):
        analyzer_name = row["analyzer_name"]
        try:
            result = await result_repo.load_result(row)
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
        "failed_analyzers": failed_analyzers or None,
        "enrichment_failures": enrichment_failures or None,
    }
    unset_fields = {"received_results": "", "last_result_at": ""}
    if error:
        set_fields["error"] = error
    else:
        unset_fields["error"] = ""
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
    # Checked before the first delete, so an SBOM that is gone leaves the stored analysis intact.
    stored_ids = await _stored_sbom_ids(fs, sboms, aggregator)
    sbom_load_failures = stored_ids.count(None)
    sboms_expected = len(stored_ids)
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

    await result_repo.delete_many({"scan_id": scan_id, "analyzer_name": {"$in": list(_ENGINE_RESULT_NAMES)}})

    if scan_doc.is_rescan:
        analysis_rescan_operations_total.inc()

    # Before the SBOM loop: an embedded CBOM re-persists over the carried copy of the same asset.
    await _carry_over_external_results(scan_id, scan_doc, db)
    await _carry_over_crypto_assets(scan_id, scan_doc, db)

    settings_repo = SystemSettingsRepository(db)
    system_settings = await settings_repo.get()
    github_token = system_settings.github_token or await _get_github_instance_token(db)

    project_analyzer_settings = await _load_project_settings_overrides(project_id, project_repo)

    write_file = bool(RAW_SBOM_ANALYZERS & set(active_analyzers))
    # Collected rather than stored per SBOM: the inventory is replaced once per payload (see store_scan_dependencies).
    payload: list[ParsedSBOM | None] = []
    for index, gridfs_id in enumerate(stored_ids):
        if gridfs_id is None:
            payload.append(None)
            continue
        try:
            sbom_path, (parsed_sbom, components, source, sbom_format) = await _load_sbom(fs, gridfs_id, write_file)
        except Exception as load_err:
            logger.exception("Failed to load SBOM from GridFS %s", gridfs_id)
            _sbom_load_failed(aggregator, load_err)
            sbom_load_failures += 1
            payload.append(None)
            continue
        payload.append(parsed_sbom)
        try:
            sbom_results = await _process_sbom(
                index,
                parsed_sbom,
                components,
                source,
                sbom_path,
                sbom_format,
                scan_id,
                db,
                aggregator,
                active_analyzers,
                system_settings,
                project_analyzer_settings=project_analyzer_settings,
                project_id=project_id,
                scan_type=scan_type,
                github_token=github_token,
            )
        finally:
            if sbom_path:
                os.remove(sbom_path)
        results_summary.extend(sbom_results)
        aggregator.fold_vulnerability_entries()
        # The component dicts must not stay alive while the next SBOM loads.
        del components

    if sbom_load_failures:
        logger.warning(
            "Scan %s: %d/%d SBOMs failed to load; skipping dependency persistence to keep stored dependencies",
            scan_id,
            sbom_load_failures,
            sboms_expected,
        )

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
        sbom_load_failures > 0 and sbom_load_failures == sboms_expected
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
        failed_analyzers=failed_analyzers,
        enrichment_failures=enrichment_failures,
        sbom_generation=sbom_generation,
    )
    if outcome != final_status:
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

    return outcome
