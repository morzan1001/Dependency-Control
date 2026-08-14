import asyncio
import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo import UpdateMany, UpdateOne

from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    SCAN_STATUS_FAILED,
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
    analysis_reachable_vulnerabilities_total,
    analysis_rescan_operations_total,
    analysis_sbom_parse_errors_total,
    analysis_sbom_processed_total,
    analysis_scans_total,
    analysis_waivers_applied_total,
)
from app.db.mongodb import open_gridfs_download_with_retry, primary_gridfs_bucket
from app.models.finding import Finding, FindingType, Severity
from app.models.project import Project, Scan
from app.models.waiver import Waiver
from app.repositories import (
    AnalysisResultRepository,
    CallgraphRepository,
    DependencyRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.finding_details import SystemWarningDetails, VulnerabilitySummaryDetails
from app.services.aggregation import ResultAggregator
from app.services.analysis.integrations import decorate_gitlab_mr
from app.services.analysis.notifications import send_scan_notifications
from app.services.analysis.registry import CRYPTO_ANALYZERS, VULNERABILITY_ANALYZERS, analyzers, is_crypto_analyzer
from app.services.analysis.stats import (
    build_epss_kev_summary,
    build_reachability_summary,
    calculate_comprehensive_stats,
)
from app.services.analysis.types import Database
from app.services.analyzers import Analyzer
from app.services.dependency_store import store_sbom_dependencies
from app.services.enrichment import enrich_vulnerability_findings
from app.services.reachability_enrichment import enrich_findings_with_reachability
from app.services.sbom_parser import parse_sbom

logger = logging.getLogger(__name__)

_BULK_CHUNK_SIZE = 500

# Run inside the engine (not registered in ``analyzers``); regenerated per run, never carried over.
_POST_PROCESSOR_ANALYZERS = frozenset({"epss_kev", "reachability"})


def _get_waiver_type(waiver: Waiver) -> str:
    """Determine the type of a waiver based on its fields."""
    if waiver.finding_id:
        return "finding_id"
    if waiver.package_name:
        return "package"
    if waiver.finding_type:
        return "type"
    if waiver.vulnerability_id:
        return "vulnerability_id"
    return "other"


async def _get_github_instance_token(db: Database) -> str | None:
    """Fallback: Use access_token from first active GitHub instance."""
    doc = await db.github_instances.find_one(
        {"is_active": True, "access_token": {"$exists": True, "$ne": None}},
        {"access_token": 1},
    )
    return doc.get("access_token") if doc else None


async def _carry_over_external_results(scan_id: str, scan_doc: Optional["Scan"], db: Database) -> None:
    """Copy non-SBOM analyzer results (e.g. Secret Scanning, SAST) from the original scan to a rescan."""
    if not (scan_doc and scan_doc.is_rescan and scan_doc.original_scan_id):
        return

    original_scan_id = scan_doc.original_scan_id
    logger.info(f"Rescan detected. Carrying over external results from {original_scan_id} to {scan_id}")

    # Internal analyzers and post-processors are regenerated per run, never carried over.
    excluded_names = list(analyzers.keys()) + list(_POST_PROCESSOR_ANALYZERS)

    from app.repositories import AnalysisResultRepository

    result_repo = AnalysisResultRepository(db)
    old_results = await result_repo.find_many(
        {
            "scan_id": original_scan_id,
            "analyzer_name": {"$nin": excluded_names},
        },
        limit=10000,
    )

    if not old_results:
        return

    bulk_ops = []
    for old_result in old_results:
        new_result = old_result.model_dump(by_alias=True).copy()
        new_result["_id"] = str(uuid.uuid4())
        new_result["scan_id"] = scan_id
        new_result["created_at"] = datetime.now(timezone.utc)

        bulk_ops.append(
            UpdateOne(
                {
                    "scan_id": scan_id,
                    "analyzer_name": old_result.analyzer_name,
                    "result": old_result.result,
                },
                {"$setOnInsert": new_result},
                upsert=True,
            )
        )

    try:
        await db.analysis_results.bulk_write(bulk_ops, ordered=False)
        logger.info(f"Carried over {len(bulk_ops)} external results to rescan {scan_id}")
    except Exception as e:
        logger.exception("Failed to bulk carry over external results: %s", e)


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
    project_id: str | None = None,
) -> str:
    analyzer_start_time = time.time()
    try:
        if analysis_scans_total:
            analysis_scans_total.labels(analyzer=analyzer_name).inc()

        # Crypto analyzers read crypto assets from the DB, so they need project_id/scan_id/db.
        if is_crypto_analyzer(analyzer_name):
            # mypy only sees the base .analyze() signature; crypto subclasses add kw-only params.
            result = await analyzer.analyze(  # type: ignore[call-arg]
                sbom,
                settings=settings,
                parsed_components=parsed_components,
                project_id=project_id,
                scan_id=scan_id,
                db=db,
            )
        else:
            result = await analyzer.analyze(sbom, settings=settings, parsed_components=parsed_components)

        if analysis_duration_seconds:
            duration = time.time() - analyzer_start_time
            analysis_duration_seconds.labels(analyzer=analyzer_name).observe(duration)

        result_repo = AnalysisResultRepository(db)
        await result_repo.create_raw(
            {
                "_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "analyzer_name": analyzer_name,
                "result": result,
                "created_at": datetime.now(timezone.utc),
            }
        )

        source: str = fallback_source
        if sbom.get("metadata") and sbom["metadata"].get("component"):
            source = str(sbom["metadata"]["component"].get("name", fallback_source))
        elif sbom.get("serialNumber"):
            source = str(sbom.get("serialNumber"))

        aggregator.aggregate(analyzer_name, result, source=source)

        skipped = result.get("partial_components_skipped") if isinstance(result, dict) else None
        if skipped:
            # Surface the coverage gap as a finding and flag the analyzer as partial.
            aggregator.aggregate(
                analyzer_name,
                {"error": f"partial result: {skipped} component(s) were not scanned"},
                source=f"System: {analyzer_name}",
            )
            logger.warning(f"Analysis {analyzer_name} returned a partial result for {scan_id}: {skipped} skipped")
            return f"{analyzer_name}: Partial ({skipped} components skipped)"

        logger.info(f"Analysis {analyzer_name} completed for {scan_id}")
        return f"{analyzer_name}: Success"
    except Exception as e:
        logger.exception("Analysis %s failed: %s", analyzer_name, e)
        # Track errors
        if analysis_errors_total:
            analysis_errors_total.labels(analyzer=analyzer_name).inc()
        # Surface the failure as a finding.
        aggregator.aggregate(analyzer_name, {"error": str(e)}, source=f"System: {analyzer_name}")
        return f"{analyzer_name}: Failed"


# Marker substring of the system-error raised when a GridFS SBOM cannot be read.
_SBOM_GRIDFS_LOAD_ERROR = "Failed to load SBOM from GridFS"


def _count_gridfs_refs(sboms_to_process: list[Any]) -> int:
    return sum(1 for it in sboms_to_process if isinstance(it, dict) and it.get("type") == "gridfs_reference")


def _failed_analyzer_names(results_summary: list[str]) -> list[str]:
    """Analyzer names whose summary entry reports a failure or partial coverage."""
    names = set()
    for entry in results_summary:
        name, sep, rest = entry.partition(": ")
        if sep and rest.startswith(("Failed", "Partial")):
            names.add(name)
    return sorted(names)


async def _resolve_sbom(item: Any, fs: AsyncIOMotorGridFSBucket, aggregator: ResultAggregator) -> dict[str, Any] | None:
    """Resolve a single SBOM item from inline dict or GridFS reference."""
    if isinstance(item, dict) and item.get("type") == "gridfs_reference":
        gridfs_id = item.get("gridfs_id")
        try:
            if analysis_gridfs_operations_total:
                analysis_gridfs_operations_total.labels(operation="download", status="attempt").inc()
            stream = await open_gridfs_download_with_retry(fs, ObjectId(gridfs_id))
            content: bytes = await stream.read()
            sbom: dict[str, Any] = json.loads(content)
            del content
            if analysis_gridfs_operations_total:
                analysis_gridfs_operations_total.labels(operation="download", status="success").inc()
            return sbom
        except Exception as gridfs_err:
            logger.exception("Failed to fetch SBOM from GridFS %s: %s", gridfs_id, gridfs_err)
            if analysis_gridfs_operations_total:
                analysis_gridfs_operations_total.labels(operation="download", status="error").inc()
            aggregator.aggregate("system", {"error": f"{_SBOM_GRIDFS_LOAD_ERROR}: {gridfs_err}"})
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
        logger.warning(f"Failed to pre-parse SBOM: {parse_err} - analyzers will use fallback parsing")
        if analysis_sbom_parse_errors_total:
            analysis_sbom_parse_errors_total.inc()
    return parsed_sbom, parsed_components


async def _persist_embedded_crypto_assets(parsed_sbom: Any, project_id: str, scan_id: str, db: Database) -> None:
    """Persist crypto assets that were embedded in a parsed SBOM."""
    try:
        from app.models.crypto_asset import CryptoAsset
        from app.repositories.crypto_asset import CryptoAssetRepository

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
    active_analyzers: list[str],
    parsed_sbom: Any,
    parsed_components: list[dict[str, Any]],
    scan_type: str | None,
) -> list[str]:
    """Select analyzers based on whether crypto data and SBOM content are present."""
    has_crypto = scan_type == "cbom" or (parsed_sbom is not None and bool(getattr(parsed_sbom, "crypto_assets", None)))
    if has_crypto:
        effective_analyzers = list(set(active_analyzers) | CRYPTO_ANALYZERS)
    else:
        effective_analyzers = [n for n in active_analyzers if n not in CRYPTO_ANALYZERS]

    # CBOM-only scans with no real SBOM content: drop SBOM-format scanners
    if not parsed_components and scan_type == "cbom":
        effective_analyzers = [n for n in effective_analyzers if n not in VULNERABILITY_ANALYZERS]
    return effective_analyzers


def _build_settings_resolver(
    system_settings: Any,
    project_license_policy: dict[str, Any] | None,
    project_analyzer_settings: dict[str, dict[str, Any]] | None,
) -> Callable[[str], dict[str, Any]]:
    """Return a function that yields per-analyzer settings dicts."""
    base_settings = system_settings.model_dump() if system_settings else {}
    if project_license_policy:
        base_settings["license_policy"] = project_license_policy

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
    project_license_policy: dict[str, Any] | None = None,
    project_analyzer_settings: dict[str, dict[str, Any]] | None = None,
    project_id: str | None = None,
    scan_type: str | None = None,
    persist_deps: bool = True,
    old_deps_deleted: bool = False,
) -> tuple[list[str], bool]:
    """Process a single resolved SBOM: parse, persist deps, run analyzers; returns (results summary, old_deps_deleted)."""
    fallback_source = f"SBOM #{index + 1}"

    parsed_sbom, parsed_components = _parse_and_track_sbom(current_sbom)

    # Rescans run under a fresh scan_id with no stored deps; delete-once-then-insert keeps
    # ingest-origin re-runs idempotent. persist_deps=False (an SBOM of this run failed to
    # resolve) and the falsy CBOM-only {} placeholder skip it so stored deps are never wiped.
    if persist_deps and parsed_sbom is not None and project_id and current_sbom:
        inserted, old_deps_deleted = await store_sbom_dependencies(
            parsed_sbom, project_id, scan_id, DependencyRepository(db), old_deps_deleted
        )
        logger.info(f"Stored {inserted} dependencies for scan {scan_id} (SBOM #{index + 1})")

    if parsed_sbom is not None and parsed_sbom.crypto_assets and project_id:
        await _persist_embedded_crypto_assets(parsed_sbom, project_id, scan_id, db)

    effective_analyzers = _resolve_effective_analyzers(active_analyzers, parsed_sbom, parsed_components, scan_type)

    settings_for = _build_settings_resolver(system_settings, project_license_policy, project_analyzer_settings)

    tasks = [
        process_analyzer(
            analyzer_name,
            analyzers[analyzer_name],
            current_sbom,
            scan_id,
            db,
            aggregator,
            settings=settings_for(analyzer_name),
            fallback_source=fallback_source,
            parsed_components=(parsed_components if parsed_components else None),
            project_id=project_id,
        )
        for analyzer_name in effective_analyzers
        if analyzer_name in analyzers
    ]

    batch_results = await asyncio.gather(*tasks)
    del current_sbom, parsed_components
    return list(batch_results), old_deps_deleted


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

    dep_filter: dict[str, Any] = {"scan_id": scan_id, "name": entry["name"], "version": entry["version"]}
    if entry["purl"]:
        # Prefix match keeps qualifier variants together without touching a
        # same-named package from another ecosystem.
        dep_filter["purl"] = {"$regex": f"^{re.escape(entry['purl'])}([?#]|$)"}

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
    enrichment_ops: list[UpdateOne] = []
    total_updated = 0
    total_enrichments_persisted = 0

    for entry in enrichment_entries:
        if not entry["data"]:
            continue

        bulk_ops.extend(_dependency_update_ops(scan_id, entry))

        purl = entry["purl"]
        if purl:
            enrichment_ops.append(
                UpdateOne(
                    {"purl": purl},
                    {"$set": {**entry["data"], "purl": purl, "name": entry["name"], "version": entry["version"]}},
                    upsert=True,
                )
            )

        if len(bulk_ops) >= _BULK_CHUNK_SIZE:
            try:
                await db.dependencies.bulk_write(bulk_ops, ordered=False)
                total_updated += len(bulk_ops)
            except Exception as e:
                logger.exception("Failed to bulk update dependencies: %s", e)
            bulk_ops.clear()

        if len(enrichment_ops) >= _BULK_CHUNK_SIZE:
            try:
                await db.dependency_enrichments.bulk_write(enrichment_ops, ordered=False)
                total_enrichments_persisted += len(enrichment_ops)
            except Exception as e:
                logger.exception("Failed to bulk upsert dependency enrichments: %s", e)
            enrichment_ops.clear()

    if bulk_ops:
        try:
            await db.dependencies.bulk_write(bulk_ops, ordered=False)
            total_updated += len(bulk_ops)
        except Exception as e:
            logger.exception("Failed to bulk update dependencies: %s", e)

    if enrichment_ops:
        try:
            await db.dependency_enrichments.bulk_write(enrichment_ops, ordered=False)
            total_enrichments_persisted += len(enrichment_ops)
        except Exception as e:
            logger.exception("Failed to bulk upsert dependency enrichments: %s", e)

    logger.info(f"Bulk updated {total_updated} dependencies.")
    logger.info(f"Upserted {total_enrichments_persisted} dependency enrichments.")


async def _run_epss_kev_enrichment(
    vulnerability_findings: list[dict[str, Any]],
    scan_id: str,
    result_repo: AnalysisResultRepository,
    github_token: str | None,
    results_summary: list[str],
) -> None:
    """Run EPSS/KEV enrichment on vulnerability findings."""
    try:
        await enrich_vulnerability_findings(vulnerability_findings, github_token=github_token)
        epss_kev_summary = build_epss_kev_summary(vulnerability_findings)
        await result_repo.create_raw(
            {
                "_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "analyzer_name": "epss_kev",
                "result": epss_kev_summary,
                "created_at": datetime.now(timezone.utc),
            }
        )
        results_summary.append(f"epss_kev: Success ({len(vulnerability_findings)} enriched)")
        logger.info(f"[epss_kev] Enriched {len(vulnerability_findings)} vulnerability findings with EPSS/KEV data")

        if analysis_enrichment_total:
            analysis_enrichment_total.labels(type="epss_kev").inc(len(vulnerability_findings))

        for vf in vulnerability_findings:
            details = vf.get("details", {})
            epss_score = details.get("epss_score")
            if epss_score is not None and analysis_epss_scores:
                try:
                    analysis_epss_scores.observe(float(epss_score))
                except (ValueError, TypeError):
                    pass
            if details.get(DETAILS_KEY_IN_KEV) and analysis_kev_vulnerabilities_total:
                analysis_kev_vulnerabilities_total.inc()

    except Exception as e:
        results_summary.append("epss_kev: Failed")
        logger.warning(f"[epss_kev] Failed to enrich findings: {e}")


async def _run_reachability_enrichment(
    vulnerability_findings: list[dict[str, Any]],
    scan_id: str,
    project_id: str,
    scan_doc: Scan,
    db: Database,
    callgraph_repo: CallgraphRepository,
    result_repo: AnalysisResultRepository,
    scan_repo: ScanRepository,
    results_summary: list[str],
) -> None:
    """Run reachability analysis on vulnerability findings."""
    callgraphs = await callgraph_repo.find_all_minimal_by_scan(project_id, scan_id)

    if not callgraphs:
        pipeline_id = scan_doc.pipeline_id if scan_doc else None
        if pipeline_id:
            callgraphs = await callgraph_repo.find_all_minimal_by_pipeline(project_id, pipeline_id)

    if not callgraphs:
        await scan_repo.update_raw(
            scan_id,
            {"$set": {"reachability_pending": True, "reachability_pending_since": datetime.now(timezone.utc)}},
        )
        logger.info(f"[reachability] No callgraph available for scan {scan_id}. Marked as pending.")
        return

    try:
        enriched_count = await enrich_findings_with_reachability(
            findings=vulnerability_findings,
            project_id=str(project_id),
            db=db,
            scan_id=scan_id,
        )
        reachability_summary = build_reachability_summary(
            vulnerability_findings,
            [cg.model_dump(by_alias=True) for cg in callgraphs],
            enriched_count,
        )
        await result_repo.create_raw(
            {
                "_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "analyzer_name": "reachability",
                "result": reachability_summary,
                "created_at": datetime.now(timezone.utc),
            }
        )
        results_summary.append(f"reachability: Success ({enriched_count} enriched)")
        logger.info(f"[reachability] Enriched {enriched_count} findings for scan {scan_id}")

        if analysis_enrichment_total:
            analysis_enrichment_total.labels(type="reachability").inc(enriched_count)

        if analysis_reachable_vulnerabilities_total:
            for vf in vulnerability_findings:
                reachability = vf.get("details", {}).get("reachability", {})
                if reachability.get("is_reachable"):
                    level = reachability.get("level", "unknown")
                    analysis_reachable_vulnerabilities_total.labels(reachability_level=level).inc()
    except Exception as e:
        results_summary.append("reachability: Failed")
        logger.warning(f"[reachability] Failed to enrich findings: {e}")


def _track_waiver_metrics(active_waivers: list[Waiver]) -> None:
    """Track Prometheus metrics for applied waivers."""
    if not analysis_waivers_applied_total:
        return

    waiver_types: dict[str, int] = {}
    for waiver in active_waivers:
        waiver_type = _get_waiver_type(waiver)
        waiver_types[waiver_type] = waiver_types.get(waiver_type, 0) + 1

    for waiver_type, count in waiver_types.items():
        analysis_waivers_applied_total.labels(type=waiver_type).inc(count)


async def _check_race_condition(scan_id: str, external_load_start: datetime, scan_repo: ScanRepository) -> bool:
    """Check if new results arrived during processing. Returns True if race detected."""
    race_check = await scan_repo.get_by_id_strong(scan_id)
    last_result_at = race_check.last_result_at if race_check else None

    if last_result_at and last_result_at.tzinfo is None:
        last_result_at = last_result_at.replace(tzinfo=timezone.utc)

    if last_result_at and last_result_at >= external_load_start:
        logger.warning(
            f"Race condition detected for scan {scan_id}. "
            f"New results arrived at {last_result_at} (Analysis load start: {external_load_start}). "
            f"Rescheduling scan."
        )
        if analysis_race_conditions_total:
            analysis_race_conditions_total.inc()

        await scan_repo.update_raw(
            scan_id,
            {"$set": {"status": "pending"}, "$inc": {"retry_count": 1}},
        )
        return True

    return False


async def _load_project_settings_overrides(
    project_id: str | None, project_repo: ProjectRepository
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]] | None]:
    """Load license_policy and analyzer_settings from project doc."""
    if not project_id:
        return None, None
    project_doc = await project_repo.get_by_id_strong(project_id)
    if not project_doc:
        return None, None
    license_policy = getattr(project_doc, "license_policy", None) or None
    analyzer_settings = getattr(project_doc, "analyzer_settings", None) or None
    return license_policy, analyzer_settings


def _resolve_sboms_to_process(sboms: list[dict[str, Any]], scan_type: str | None) -> list[dict[str, Any]]:
    """Pick SBOMs to iterate, with a synthetic placeholder for CBOM-only scans."""
    if sboms:
        return sboms
    if scan_type == "cbom":
        return [{}]
    return []


async def _aggregate_external_results(
    aggregator: ResultAggregator,
    result_repo: AnalysisResultRepository,
    scan_id: str,
    results_summary: list[str],
) -> None:
    """Fetch external analyzer results and aggregate them; failures land in results_summary."""
    external_results = await result_repo.find_by_scan(scan_id, limit=10000)
    for res in external_results:
        # Skip post-processor rows: they are engine outputs, not external scanner results.
        if res.analyzer_name not in analyzers and res.analyzer_name not in _POST_PROCESSOR_ANALYZERS:
            try:
                aggregator.aggregate(res.analyzer_name, res.result)
                results_summary.append(f"{res.analyzer_name}: Success")
            except Exception as exc:
                logger.warning(
                    "_aggregate_external_results: skipping malformed result for analyzer=%s scan=%s: %s",
                    res.analyzer_name,
                    scan_id,
                    exc,
                )
                aggregator.add_finding(
                    Finding(
                        id=f"SCAN-ERROR-{res.analyzer_name}",
                        type=FindingType.SYSTEM_WARNING,
                        severity=Severity.HIGH,
                        component="Scanner System",
                        version="",
                        description=f"External result for '{res.analyzer_name}' could not be aggregated: {exc}",
                        scanners=[res.analyzer_name],
                        details=SystemWarningDetails(error_details=str(exc)).model_dump(exclude_none=True),
                    )
                )
                results_summary.append(f"{res.analyzer_name}: Failed")
    del external_results


def _cleanup_analyzer_names(active_analyzers: list[str]) -> list[str]:
    """Analyzer result-row names to purge before a (re)run: internal, post-processor, and crypto.

    Crypto/post-processor rows are regenerated per run and can exist independently of
    active_analyzers (crypto auto-added by an embedded CBOM), so they must be purged explicitly.
    """
    internal_analyzers = [name for name in active_analyzers if name in analyzers]
    return list(set(internal_analyzers) | set(_POST_PROCESSOR_ANALYZERS) | set(CRYPTO_ANALYZERS))


def _prepare_finding_records(
    aggregated_findings: list[Any],
    scan_id: str,
    project_id: str | None,
    scan_created_at: datetime | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Convert aggregated findings to insertion records, splitting out vulnerabilities.

    ``_id`` is deterministic per (scan, finding identity) so a raced double-persist collides
    on insert instead of storing the whole finding set twice.
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


def _summary_cve_id(record: dict[str, Any]) -> str:
    """First CVE id found on the aggregated record; falls back to the component:version id."""
    details = record.get("details") or {}
    for entry in details.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        for candidate in (entry.get("id"), entry.get("resolved_cve"), *(entry.get("aliases") or [])):
            if isinstance(candidate, str) and candidate.startswith("CVE-"):
                return candidate
    for alias in record.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return str(record.get("id") or "")


def _build_findings_summary(
    vulnerability_findings: list[dict[str, Any]],
    limit: int = _FINDINGS_SUMMARY_LIMIT,
) -> list[dict[str, Any]]:
    """Compact, bounded, vulnerability-only summary; details trimmed to the CVE id to bound size."""
    summary: list[dict[str, Any]] = []
    for record in vulnerability_findings[:limit]:
        cve_id = _summary_cve_id(record)
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
    scan_doc: Any,
    db: Database,
    result_repo: AnalysisResultRepository,
    callgraph_repo: CallgraphRepository,
    scan_repo: ScanRepository,
    github_token: str | None,
    results_summary: list[str],
) -> None:
    if "epss_kev" in active_analyzers and vulnerability_findings:
        await _run_epss_kev_enrichment(vulnerability_findings, scan_id, result_repo, github_token, results_summary)

    if "reachability" in active_analyzers and vulnerability_findings and project_id:
        await _run_reachability_enrichment(
            vulnerability_findings,
            scan_id,
            project_id,
            scan_doc,
            db,
            callgraph_repo,
            result_repo,
            scan_repo,
            results_summary,
        )


async def _persist_findings_and_waivers(
    findings_to_insert: list[dict[str, Any]],
    scan_id: str,
    project_id: str | None,
    finding_repo: FindingRepository,
    db: Database,
) -> tuple[int, int, list[Waiver]]:
    """Insert findings, apply waivers, return (persisted_count, ignored_count, active_waivers)."""
    await finding_repo.delete_many({"scan_id": scan_id})
    persisted_count = 0
    for i in range(0, len(findings_to_insert), _BULK_CHUNK_SIZE):
        persisted_count += await finding_repo.create_many_raw(findings_to_insert[i : i + _BULK_CHUNK_SIZE])

    from app.repositories import WaiverRepository

    active_waivers: list[Waiver] = []
    if project_id:
        waiver_repo = WaiverRepository(db)
        active_waivers = await waiver_repo.find_active_for_project(project_id, include_global=True)

    from app.services.stats import _apply_waivers

    await _apply_waivers(finding_repo, scan_id, active_waivers)
    from pymongo import ReadPreference

    findings_primary = db.findings.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
    ignored_count = await findings_primary.count_documents({"scan_id": scan_id, "waived": True})
    return persisted_count, ignored_count, active_waivers


def _as_utc(dt: datetime | None) -> datetime | None:
    """Normalise a possibly-naive datetime to timezone-aware UTC for comparison."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _should_update_project_latest_scan(
    scan_id: str,
    scan_doc: Any,
    project_id: str,
    scan_repo: ScanRepository,
    project_repo: ProjectRepository,
    authoritative: bool = True,
) -> bool:
    """True unless a strictly-newer scan (by created_at) is already the project's latest.

    Guards against a late/out-of-order scan clobbering latest_scan_id/stats with stale data.
    A non-authoritative scan (no SBOM ever received) may only become latest when the project
    has none yet, so a SAST-only pipeline run cannot wipe the SBOM-derived picture.
    """
    project_doc = await project_repo.get_by_id_strong(project_id)
    current_latest_id = getattr(project_doc, "latest_scan_id", None) if project_doc else None
    if not authoritative and current_latest_id and current_latest_id != scan_id:
        return False
    if not current_latest_id or current_latest_id == scan_id:
        return True

    current_latest = await scan_repo.get_by_id_strong(current_latest_id)
    if not current_latest:
        return True

    this_created = _as_utc(getattr(scan_doc, "created_at", None))
    current_created = _as_utc(getattr(current_latest, "created_at", None))
    if this_created is None or current_created is None:
        return True
    return this_created >= current_created


async def _finalize_scan_and_project(
    scan_id: str,
    scan_doc: Any,
    project_id: str | None,
    total_findings_count: int,
    ignored_count: int,
    stats: Any,
    latest_run_summary: dict,
    scan_repo: ScanRepository,
    project_repo: ProjectRepository,
    status: str = SCAN_STATUS_COMPLETED,
    error: str | None = None,
    external_load_start: datetime | None = None,
    findings_summary: list[dict[str, Any]] | None = None,
    failed_analyzers: list[str] | None = None,
    authoritative: bool = True,
) -> bool:
    """Persist the final scan status, ignored count, and (on success) project stats.

    Returns True when the scan was finalised, False when completion was aborted because a
    late scanner result arrived during processing (the scan is rescheduled instead).
    """
    set_fields: dict[str, Any] = {
        "status": status,
        "findings_count": total_findings_count,
        "ignored_count": ignored_count,
        "stats": stats.model_dump(),
        "completed_at": datetime.now(timezone.utc),
        "latest_run": latest_run_summary,
        "findings_summary": findings_summary or [],
        "failed_analyzers": failed_analyzers or None,
    }
    if error:
        set_fields["error"] = error
    unset_fields = {
        "received_results": "",
        "last_result_at": "",
    }

    if status in SCAN_USABLE_STATUSES and external_load_start is not None:
        # Atomic completion guard: only complete if no scanner result arrived after loading
        # began, closing the TOCTOU window where a late result would be $unset and lost.
        updated = await scan_repo.collection.find_one_and_update(
            {
                "_id": scan_id,
                "$or": [
                    {"last_result_at": {"$exists": False}},
                    {"last_result_at": None},
                    {"last_result_at": {"$lt": external_load_start}},
                ],
            },
            {"$set": set_fields, "$unset": unset_fields},
        )
        if updated is None:
            logger.warning(
                "Scan %s: late scanner result detected during finalize; rescheduling "
                "instead of completing to avoid dropping results.",
                scan_id,
            )
            if analysis_race_conditions_total:
                analysis_race_conditions_total.inc()
            await scan_repo.update_raw(
                scan_id,
                {"$set": {"status": "pending"}, "$inc": {"retry_count": 1}},
            )
            return False
    else:
        await scan_repo.update_raw(scan_id, {"$set": set_fields, "$unset": unset_fields})

    if scan_doc.is_rescan and scan_doc.original_scan_id:
        await scan_repo.update_raw(
            scan_doc.original_scan_id,
            {"$set": {"latest_rescan_id": scan_id, "latest_run": latest_run_summary}},
        )

    # A failed or out-of-order scan must not become the project's latest or overwrite its stats.
    if (
        project_id
        and status != SCAN_STATUS_FAILED
        and await _should_update_project_latest_scan(
            scan_id, scan_doc, project_id, scan_repo, project_repo, authoritative=authoritative
        )
    ):
        await project_repo.update_raw(
            project_id,
            {
                "$set": {
                    "stats": stats.model_dump(),
                    "last_scan_at": datetime.now(timezone.utc),
                    "latest_scan_id": scan_id,
                }
            },
        )
    return True


async def _filter_out_waived_findings(aggregated_findings: list[Any], scan_id: str, db: Database) -> list[Any]:
    """Drop findings waived in this scan so notifications/webhooks match the waiver-aware stats.

    Waivers are applied only as DB updates; in-memory Finding objects are never marked waived,
    so re-read the persisted waived finding_ids and exclude them before notifying.
    """
    from pymongo import ReadPreference

    findings_primary = db.findings.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
    cursor = findings_primary.find({"scan_id": scan_id, "waived": True}, {"finding_id": 1})
    waived_ids = set()
    async for doc in cursor:
        fid = doc.get("finding_id")
        if fid is not None:
            waived_ids.add(fid)

    if not waived_ids:
        return aggregated_findings
    return [f for f in aggregated_findings if getattr(f, "id", None) not in waived_ids]


async def _send_integrations_and_notifications(
    project_id: str | None,
    scan_id: str,
    scan_doc: Any,
    stats: Any,
    aggregated_findings: list[Any],
    results_summary: list[str],
    db: Database,
) -> None:
    if not project_id:
        return
    from pymongo import ReadPreference

    projects_primary = db.projects.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
    project_data = await projects_primary.find_one({"_id": project_id})
    if not project_data:
        return
    project = Project(**project_data)
    await decorate_gitlab_mr(scan_id, stats, scan_doc, project, db)
    await send_scan_notifications(scan_id, project, aggregated_findings, results_summary, db)


async def _project_has_active_waivers(project_id: str, db: Database) -> bool:
    """Cheap existence check: does the project (or a global waiver) have an active waiver?
    Used to skip the post-analysis recalc when there is nothing to re-anchor/lapse."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    query = {
        "$and": [
            {"$or": [{"project_id": project_id}, {"project_id": None}]},
            {
                "$or": [
                    {"expiration_date": {"$exists": False}},
                    {"expiration_date": None},
                    {"expiration_date": {"$gt": now}},
                ]
            },
        ]
    }
    return (await db.waivers.count_documents(query, limit=1)) > 0


def _release_memory_to_os() -> None:
    """Force gc and release glibc heap pages back to OS (Linux-only)."""
    import gc

    gc.collect()
    try:
        import ctypes

        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except (OSError, AttributeError):
        pass


async def run_analysis(scan_id: str, sboms: list[dict[str, Any]], active_analyzers: list[str], db: Database) -> bool:
    """Orchestrate analysis for an SBOM scan; returns False if rescheduled due to a race condition."""
    logger.info(f"Starting analysis for scan {scan_id}")
    aggregation_start_time = time.time()
    aggregator = ResultAggregator()
    results_summary: list[str] = []

    scan_repo = ScanRepository(db)
    result_repo = AnalysisResultRepository(db)
    finding_repo = FindingRepository(db)
    callgraph_repo = CallgraphRepository(db)
    project_repo = ProjectRepository(db)

    scan_doc = await scan_repo.get_by_id_strong(scan_id)
    if not scan_doc:
        # Mark terminal — worker re-claim only matches scans still in "pending".
        logger.error(f"Scan {scan_id} not found, marking as failed")
        await scan_repo.update_raw(
            scan_id,
            {"$set": {"status": "failed", "error": "scan not found"}},
        )
        return False

    project_id: str | None = scan_doc.project_id
    scan_type: str | None = getattr(scan_doc, "scan_type", None)

    # For CBOM scans, always include crypto analyzers regardless of project config.
    if scan_type == "cbom":
        active_analyzers = list(set(active_analyzers) | CRYPTO_ANALYZERS)

    cleanup_names = _cleanup_analyzer_names(active_analyzers)
    if cleanup_names:
        await result_repo.delete_many({"scan_id": scan_id, "analyzer_name": {"$in": cleanup_names}})

    if scan_doc.is_rescan and analysis_rescan_operations_total:
        analysis_rescan_operations_total.inc()

    await _carry_over_external_results(scan_id, scan_doc, db)

    settings_repo = SystemSettingsRepository(db)
    system_settings = await settings_repo.get()

    project_license_policy, project_analyzer_settings = await _load_project_settings_overrides(project_id, project_repo)

    fs = primary_gridfs_bucket(db)
    sboms_to_process = _resolve_sboms_to_process(sboms, scan_type)

    # Resolve every SBOM before the first dependency delete: a partial GridFS failure must
    # not wipe the stored deps of the SBOMs that did not load.
    resolved_sboms: list[dict[str, Any] | None] = [
        await _resolve_sbom(item, fs, aggregator) for item in sboms_to_process
    ]
    sbom_load_failures = sum(1 for resolved in resolved_sboms if resolved is None)
    sboms_expected = len(resolved_sboms)
    gridfs_expected = _count_gridfs_refs(sboms_to_process)
    persist_deps = sbom_load_failures == 0
    if not persist_deps:
        logger.warning(
            "Scan %s: %d/%d SBOMs failed to resolve; skipping dependency persistence to keep stored dependencies",
            scan_id,
            sbom_load_failures,
            sboms_expected,
        )

    old_deps_deleted = False
    for index, current_sbom in enumerate(resolved_sboms):
        if current_sbom is None:
            continue
        sbom_results, old_deps_deleted = await _process_sbom(
            index,
            current_sbom,
            scan_id,
            db,
            aggregator,
            active_analyzers,
            system_settings,
            project_license_policy=project_license_policy,
            project_analyzer_settings=project_analyzer_settings,
            project_id=project_id,
            scan_type=scan_type,
            persist_deps=persist_deps,
            old_deps_deleted=old_deps_deleted,
        )
        resolved_sboms[index] = None
        results_summary.extend(sbom_results)

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
    total_findings_count = len(findings_to_insert)

    github_token = system_settings.github_token
    if not github_token:
        github_token = await _get_github_instance_token(db)

    await _run_vuln_enrichments(
        active_analyzers,
        vulnerability_findings,
        scan_id,
        project_id,
        scan_doc,
        db,
        result_repo,
        callgraph_repo,
        scan_repo,
        github_token,
        results_summary,
    )

    persisted_findings_count, ignored_count, active_waivers = await _persist_findings_and_waivers(
        findings_to_insert, scan_id, project_id, finding_repo, db
    )
    _track_waiver_metrics(active_waivers)

    stats = await calculate_comprehensive_stats(db, scan_id)

    sbom_load_failed = gridfs_expected > 0 and sbom_load_failures >= gridfs_expected
    if sbom_load_failed:
        logger.error(
            "Scan %s: all SBOMs failed to load from GridFS — marking failed (was silently completing)",
            scan_id,
        )

    failed_analyzers = _failed_analyzer_names(results_summary)
    partial_reasons: list[str] = []
    if failed_analyzers:
        partial_reasons.append(f"analyzers failed or returned partial results: {', '.join(failed_analyzers)}")
    if not sbom_load_failed and sbom_load_failures:
        partial_reasons.append(f"{sbom_load_failures} of {sboms_expected} SBOMs failed to load")
    if persisted_findings_count < total_findings_count:
        partial_reasons.append(f"only {persisted_findings_count} of {total_findings_count} findings were persisted")
    total_findings_count = persisted_findings_count

    if sbom_load_failed:
        final_status = SCAN_STATUS_FAILED
        final_error: str | None = "SBOM could not be loaded for analysis"
    elif partial_reasons:
        final_status = SCAN_STATUS_COMPLETED_WITH_ERRORS
        final_error = "; ".join(partial_reasons)
        logger.warning("Scan %s completed with errors: %s", scan_id, final_error)
    else:
        final_status = SCAN_STATUS_COMPLETED
        final_error = None

    latest_run_summary = {
        "scan_id": scan_id,
        "status": final_status,
        "findings_count": total_findings_count,
        "stats": stats.model_dump(),
        "completed_at": datetime.now(timezone.utc),
    }

    if await _check_race_condition(scan_id, external_load_start, scan_repo):
        return False

    if analysis_aggregation_duration_seconds:
        analysis_aggregation_duration_seconds.observe(time.time() - aggregation_start_time)

    finalized = await _finalize_scan_and_project(
        scan_id,
        scan_doc,
        project_id,
        total_findings_count,
        ignored_count,
        stats,
        latest_run_summary,
        scan_repo,
        project_repo,
        status=final_status,
        error=final_error,
        external_load_start=external_load_start,
        findings_summary=_build_findings_summary(vulnerability_findings),
        failed_analyzers=failed_analyzers,
        authoritative=bool(sboms_to_process),
    )
    if not finalized:
        # Rescheduled after a late scanner result raced completion; skip notifying on stale results.
        del aggregated_findings
        _release_memory_to_os()
        return False

    # Re-apply/re-anchor waivers before notifying so webhooks report post-re-anchor stats;
    # skipped when the project has no active waivers.
    if not sbom_load_failed:
        notify_stats = stats
        if project_id and await _project_has_active_waivers(project_id, db):
            from app.services.stats import recalculate_project_stats

            recalced = await recalculate_project_stats(project_id, db)
            if recalced is not None:
                notify_stats = recalced

        notify_findings = await _filter_out_waived_findings(aggregated_findings, scan_id, db)
        await _send_integrations_and_notifications(
            project_id, scan_id, scan_doc, notify_stats, notify_findings, results_summary, db
        )

    del aggregated_findings

    _release_memory_to_os()

    return True
