import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo import UpdateOne

from prometheus_client import Counter, Histogram

from app.models.project import Project, Scan
from app.models.waiver import Waiver
from app.repositories import (
    AnalysisResultRepository,
    CallgraphRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)
from app.repositories.system_settings import SystemSettingsRepository
from app.services.aggregation import ResultAggregator
from app.services.analyzers import Analyzer
from app.services.enrichment import enrich_vulnerability_findings
from app.services.reachability_enrichment import enrich_findings_with_reachability
from app.services.sbom_parser import parse_sbom
from app.services.analysis.registry import CRYPTO_ANALYZERS, VULNERABILITY_ANALYZERS, analyzers, is_crypto_analyzer
from app.services.analysis.stats import (
    build_epss_kev_summary,
    build_reachability_summary,
    calculate_comprehensive_stats,
)
from app.services.analysis.integrations import decorate_gitlab_mr
from app.services.analysis.notifications import send_scan_notifications
from app.services.analysis.types import Database

logger = logging.getLogger(__name__)

_BULK_CHUNK_SIZE = 500

# Import metrics for detailed analysis tracking
analysis_scans_total: Optional[Counter] = None
analysis_errors_total: Optional[Counter] = None
analysis_sbom_processed_total: Optional[Counter] = None
analysis_components_parsed_total: Optional[Counter] = None
analysis_sbom_parse_errors_total: Optional[Counter] = None
analysis_gridfs_operations_total: Optional[Counter] = None
analysis_enrichment_total: Optional[Counter] = None
analysis_epss_scores: Optional[Histogram] = None
analysis_kev_vulnerabilities_total: Optional[Counter] = None
analysis_reachable_vulnerabilities_total: Optional[Counter] = None
analysis_waivers_applied_total: Optional[Counter] = None
analysis_race_conditions_total: Optional[Counter] = None
analysis_rescan_operations_total: Optional[Counter] = None
analysis_aggregation_duration_seconds: Optional[Histogram] = None
analysis_findings_by_type: Optional[Counter] = None
analysis_findings_total: Optional[Counter] = None
analysis_duration_seconds: Optional[Histogram] = None

try:
    from app.core.metrics import (
        analysis_aggregation_duration_seconds,
        analysis_components_parsed_total,
        analysis_enrichment_total,
        analysis_epss_scores,
        analysis_errors_total,
        analysis_findings_by_type,
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
        analysis_duration_seconds,
    )
except ImportError:
    pass


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


async def _get_github_instance_token(db: Database) -> Optional[str]:
    """Fallback: Use access_token from first active GitHub instance."""
    doc = await db.github_instances.find_one(
        {"is_active": True, "access_token": {"$exists": True, "$ne": None}},
        {"access_token": 1},
    )
    return doc.get("access_token") if doc else None


async def _carry_over_external_results(scan_id: str, scan_doc: Optional["Scan"], db: Database) -> None:
    """
    Copies analysis results from the original scan to the re-scan for analyzers
    that are NOT part of the internal SBOM analysis (e.g. Secret Scanning, SAST).
    """
    if not (scan_doc and scan_doc.is_rescan and scan_doc.original_scan_id):
        return

    original_scan_id = scan_doc.original_scan_id
    logger.info(f"Rescan detected. Carrying over external results from {original_scan_id} to {scan_id}")

    internal_analyzer_names = list(analyzers.keys())

    # Find results from the original scan that are NOT internal analyzers
    from app.repositories import AnalysisResultRepository

    result_repo = AnalysisResultRepository(db)
    old_results = await result_repo.find_many(
        {
            "scan_id": original_scan_id,
            "analyzer_name": {"$nin": internal_analyzer_names},
        },
        limit=10000,
    )

    if not old_results:
        return

    # Bulk upsert all external results in a single operation
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
    sbom: Dict[str, Any],
    scan_id: str,
    db: Database,
    aggregator: ResultAggregator,
    settings: Optional[Dict[str, Any]] = None,
    fallback_source: str = "unknown-sbom",
    parsed_components: Optional[List[Dict[str, Any]]] = None,
    project_id: Optional[str] = None,
) -> str:
    analyzer_start_time = time.time()
    try:
        # Track analyzer execution
        if analysis_scans_total:
            analysis_scans_total.labels(analyzer=analyzer_name).inc()

        # Crypto analyzers need project_id, scan_id, and db to read crypto assets from DB
        if is_crypto_analyzer(analyzer_name):
            # Crypto analyzers subclass Analyzer and extend .analyze() with
            # keyword-only parameters; Liskov-compatible but mypy only sees the
            # base signature.
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

        # Track duration
        if analysis_duration_seconds:
            duration = time.time() - analyzer_start_time
            analysis_duration_seconds.labels(analyzer=analyzer_name).observe(duration)

        # Store raw result via repository
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

        # Extract source name from SBOM metadata
        source: str = fallback_source
        if sbom.get("metadata") and sbom["metadata"].get("component"):
            source = str(sbom["metadata"]["component"].get("name", fallback_source))
        elif sbom.get("serialNumber"):
            source = str(sbom.get("serialNumber"))

        # Aggregate result
        aggregator.aggregate(analyzer_name, result, source=source)

        logger.info(f"Analysis {analyzer_name} completed for {scan_id}")
        return f"{analyzer_name}: Success"
    except Exception as e:
        logger.exception("Analysis %s failed: %s", analyzer_name, e)
        # Track errors
        if analysis_errors_total:
            analysis_errors_total.labels(analyzer=analyzer_name).inc()
        # Report failure to aggregator so it appears in findings
        aggregator.aggregate(analyzer_name, {"error": str(e)}, source=f"System: {analyzer_name}")
        return f"{analyzer_name}: Failed"


async def _resolve_sbom(
    item: Any, fs: AsyncIOMotorGridFSBucket, aggregator: ResultAggregator
) -> Optional[Dict[str, Any]]:
    """Resolve a single SBOM item from inline dict or GridFS reference."""
    if isinstance(item, dict) and item.get("type") == "gridfs_reference":
        gridfs_id = item.get("gridfs_id")
        try:
            if analysis_gridfs_operations_total:
                analysis_gridfs_operations_total.labels(operation="download", status="attempt").inc()
            stream = await fs.open_download_stream(ObjectId(gridfs_id))
            content: bytes = await stream.read()
            sbom = json.loads(content)
            del content
            if analysis_gridfs_operations_total:
                analysis_gridfs_operations_total.labels(operation="download", status="success").inc()
            return sbom
        except Exception as gridfs_err:
            logger.exception("Failed to fetch SBOM from GridFS %s: %s", gridfs_id, gridfs_err)
            if analysis_gridfs_operations_total:
                analysis_gridfs_operations_total.labels(operation="download", status="error").inc()
            aggregator.aggregate("system", {"error": f"Failed to load SBOM from GridFS: {gridfs_err}"})
            return None
    result: Optional[Dict[str, Any]] = item
    return result


def _parse_and_track_sbom(current_sbom: Any) -> tuple[Any, List[Dict[str, Any]]]:
    """Try to pre-parse the SBOM and track metrics. Returns (parsed_sbom, parsed_components)."""
    parsed_components: List[Dict[str, Any]] = []
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
    active_analyzers: List[str],
    parsed_sbom: Any,
    parsed_components: List[Dict[str, Any]],
    scan_type: Optional[str],
) -> List[str]:
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
    project_license_policy: Optional[Dict[str, Any]],
    project_analyzer_settings: Optional[Dict[str, Dict[str, Any]]],
) -> Callable[[str], Dict[str, Any]]:
    """Return a function that yields per-analyzer settings dicts."""
    base_settings = system_settings.model_dump() if system_settings else {}
    if project_license_policy:
        base_settings["license_policy"] = project_license_policy

    def _settings_for(analyzer_name: str) -> Dict[str, Any]:
        merged = dict(base_settings)
        if project_analyzer_settings:
            overrides = project_analyzer_settings.get(analyzer_name)
            if overrides:
                merged.update(overrides)
        return merged

    return _settings_for


async def _process_sbom(
    index: int,
    item: Any,
    scan_id: str,
    db: Database,
    fs: AsyncIOMotorGridFSBucket,
    aggregator: ResultAggregator,
    active_analyzers: List[str],
    system_settings: Any,
    project_license_policy: Optional[Dict[str, Any]] = None,
    project_analyzer_settings: Optional[Dict[str, Dict[str, Any]]] = None,
    project_id: Optional[str] = None,
    scan_type: Optional[str] = None,
) -> List[str]:
    """Process a single SBOM: resolve, parse, run analyzers. Returns results summary."""
    current_sbom = await _resolve_sbom(item, fs, aggregator)
    # CBOM-only scans synthesise an empty {} so the analyzer loop fires;
    # only bail when resolution itself failed (returned None).
    if current_sbom is None:
        return []

    fallback_source = f"SBOM #{index + 1}"

    parsed_sbom, parsed_components = _parse_and_track_sbom(current_sbom)

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
    return list(batch_results)


def _track_findings_metrics(aggregated_findings: List[Any]) -> None:
    """Track Prometheus metrics for aggregated findings."""
    for finding in aggregated_findings:
        finding_type = finding.type if hasattr(finding, "type") else "unknown"
        severity = finding.severity if hasattr(finding, "severity") else "unknown"
        if analysis_findings_by_type:
            analysis_findings_by_type.labels(type=finding_type, severity=severity).inc()
        if analysis_findings_total:
            scanners = finding.scanners if hasattr(finding, "scanners") else []
            for scanner_name in scanners:
                analysis_findings_total.labels(analyzer=scanner_name, severity=severity).inc()


async def _enrich_dependencies(dependency_enrichments: Dict[str, Any], scan_id: str, db: Database) -> None:
    """Bulk-update dependencies with aggregated enrichment data."""
    if not dependency_enrichments:
        return

    logger.info(f"Enriching {len(dependency_enrichments)} dependencies with aggregated metadata")
    bulk_ops: List[UpdateOne] = []
    total_updated = 0

    for key, enrichment_data in dependency_enrichments.items():
        parts = key.rsplit("@", 1)
        if len(parts) != 2:
            continue
        name, version = parts
        if enrichment_data:
            bulk_ops.append(
                UpdateOne(
                    {"scan_id": scan_id, "name": name, "version": version},
                    {"$set": enrichment_data},
                )
            )

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

    logger.info(f"Bulk updated {total_updated} dependencies.")


async def _run_epss_kev_enrichment(
    vulnerability_findings: List[Dict[str, Any]],
    scan_id: str,
    result_repo: AnalysisResultRepository,
    github_token: Optional[str],
    results_summary: List[str],
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
            if details.get("is_kev") and analysis_kev_vulnerabilities_total:
                analysis_kev_vulnerabilities_total.inc()

    except Exception as e:
        results_summary.append("epss_kev: Failed")
        logger.warning(f"[epss_kev] Failed to enrich findings: {e}")


async def _run_reachability_enrichment(
    vulnerability_findings: List[Dict[str, Any]],
    scan_id: str,
    project_id: str,
    scan_doc: Scan,
    db: Database,
    callgraph_repo: CallgraphRepository,
    result_repo: AnalysisResultRepository,
    scan_repo: ScanRepository,
    results_summary: List[str],
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


async def _apply_waivers(
    active_waivers: List[Waiver],
    scan_id: str,
    finding_repo: FindingRepository,
) -> None:
    """Apply all active waivers to findings for a scan."""
    from app.services.stats import _build_waiver_query

    for waiver in active_waivers:
        if waiver.vulnerability_id:
            await finding_repo.apply_vulnerability_waiver(
                scan_id=scan_id,
                vulnerability_id=waiver.vulnerability_id,
                waived=True,
                waiver_reason=waiver.reason,
            )
        else:
            query = _build_waiver_query(waiver)
            await finding_repo.apply_finding_waiver(
                scan_id=scan_id,
                query=query,
                waived=True,
                waiver_reason=waiver.reason,
            )


def _track_waiver_metrics(active_waivers: List[Waiver]) -> None:
    """Track Prometheus metrics for applied waivers."""
    if not analysis_waivers_applied_total:
        return

    waiver_types: Dict[str, int] = {}
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
    project_id: Optional[str], project_repo: ProjectRepository
) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Dict[str, Any]]]]:
    """Load license_policy and analyzer_settings from project doc."""
    if not project_id:
        return None, None
    project_doc = await project_repo.get_by_id_strong(project_id)
    if not project_doc:
        return None, None
    license_policy = getattr(project_doc, "license_policy", None) or None
    analyzer_settings = getattr(project_doc, "analyzer_settings", None) or None
    return license_policy, analyzer_settings


def _resolve_sboms_to_process(sboms: List[Dict[str, Any]], scan_type: Optional[str]) -> List[Dict[str, Any]]:
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
    results_summary: List[str],
) -> None:
    """Fetch external analyzer results and aggregate them."""
    external_results = await result_repo.find_by_scan(scan_id, limit=10000)
    for res in external_results:
        if res.analyzer_name not in analyzers:
            aggregator.aggregate(res.analyzer_name, res.result)
            results_summary.append(f"{res.analyzer_name}: Success")
    del external_results


def _prepare_finding_records(
    aggregated_findings: List[Any],
    scan_id: str,
    project_id: Optional[str],
    scan_created_at: Optional[datetime],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Convert aggregated findings to insertion records, splitting out vulnerabilities."""
    findings_to_insert: List[Dict[str, Any]] = []
    vulnerability_findings: List[Dict[str, Any]] = []
    for f in aggregated_findings:
        record: Dict[str, Any] = f.model_dump()
        record["scan_id"] = scan_id
        record["project_id"] = project_id
        record["finding_id"] = f.id
        record["_id"] = str(uuid.uuid4())
        record.setdefault("scan_created_at", scan_created_at)
        findings_to_insert.append(record)
        if record.get("type") == "vulnerability":
            vulnerability_findings.append(record)
    return findings_to_insert, vulnerability_findings


async def _run_vuln_enrichments(
    active_analyzers: List[str],
    vulnerability_findings: List[Dict[str, Any]],
    scan_id: str,
    project_id: Optional[str],
    scan_doc: Any,
    db: Database,
    result_repo: AnalysisResultRepository,
    callgraph_repo: CallgraphRepository,
    scan_repo: ScanRepository,
    github_token: Optional[str],
    results_summary: List[str],
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
    findings_to_insert: List[Dict[str, Any]],
    scan_id: str,
    project_id: Optional[str],
    finding_repo: FindingRepository,
    db: Database,
) -> tuple[int, List[Waiver]]:
    """Insert findings, apply waivers, return (ignored_count, active_waivers)."""
    await finding_repo.delete_many({"scan_id": scan_id})
    for i in range(0, len(findings_to_insert), _BULK_CHUNK_SIZE):
        await finding_repo.create_many_raw(findings_to_insert[i : i + _BULK_CHUNK_SIZE])

    from app.repositories import WaiverRepository

    active_waivers: List[Waiver] = []
    if project_id:
        waiver_repo = WaiverRepository(db)
        active_waivers = await waiver_repo.find_active_for_project(project_id, include_global=True)

    await _apply_waivers(active_waivers, scan_id, finding_repo)
    from pymongo import ReadPreference

    findings_primary = db.findings.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
    ignored_count = await findings_primary.count_documents({"scan_id": scan_id, "waived": True})
    return ignored_count, active_waivers


async def _finalize_scan_and_project(
    scan_id: str,
    scan_doc: Any,
    project_id: Optional[str],
    total_findings_count: int,
    ignored_count: int,
    stats: Any,
    latest_run_summary: dict,
    scan_repo: ScanRepository,
    project_repo: ProjectRepository,
) -> None:
    """Persist completed status, ignored count, and update project stats."""
    await scan_repo.update_raw(
        scan_id,
        {
            "$set": {
                "status": "completed",
                "findings_count": total_findings_count,
                "ignored_count": ignored_count,
                "stats": stats.model_dump(),
                "completed_at": datetime.now(timezone.utc),
                "latest_run": latest_run_summary,
            },
            "$unset": {
                "findings_summary": "",
                "received_results": "",
                "last_result_at": "",
            },
        },
    )

    if scan_doc.is_rescan and scan_doc.original_scan_id:
        await scan_repo.update_raw(
            scan_doc.original_scan_id,
            {"$set": {"latest_rescan_id": scan_id, "latest_run": latest_run_summary}},
        )

    if project_id:
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


async def _send_integrations_and_notifications(
    project_id: Optional[str],
    scan_id: str,
    scan_doc: Any,
    stats: Any,
    aggregated_findings: List[Any],
    results_summary: List[str],
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


def _release_memory_to_os() -> None:
    """Force gc and release glibc heap pages back to OS (Linux-only)."""
    import gc

    gc.collect()
    try:
        import ctypes

        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except (OSError, AttributeError):
        pass


async def run_analysis(scan_id: str, sboms: List[Dict[str, Any]], active_analyzers: List[str], db: Database) -> bool:
    """
    Orchestrates the analysis process for a given SBOM scan.

    Args:
        scan_id: The ID of the scan to analyze
        sboms: List of SBOM documents or GridFS references
        active_analyzers: List of analyzer names to run
        db: Database connection

    Returns:
        True if analysis completed successfully, False if rescheduled due to race condition
    """
    logger.info(f"Starting analysis for scan {scan_id}")
    aggregation_start_time = time.time()
    aggregator = ResultAggregator()
    results_summary: List[str] = []

    # Initialize repositories for consistent data access
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

    project_id: Optional[str] = scan_doc.project_id
    scan_type: Optional[str] = getattr(scan_doc, "scan_type", None)

    # For CBOM scans, always include crypto analyzers regardless of project config.
    if scan_type == "cbom":
        active_analyzers = list(set(active_analyzers) | CRYPTO_ANALYZERS)

    # 0. Cleanup previous results for internal analyzers
    internal_analyzers = [name for name in active_analyzers if name in analyzers]
    if internal_analyzers:
        await result_repo.delete_many({"scan_id": scan_id, "analyzer_name": {"$in": internal_analyzers}})

    if scan_doc.is_rescan and analysis_rescan_operations_total:
        analysis_rescan_operations_total.inc()

    await _carry_over_external_results(scan_id, scan_doc, db)

    settings_repo = SystemSettingsRepository(db)
    system_settings = await settings_repo.get()

    project_license_policy, project_analyzer_settings = await _load_project_settings_overrides(project_id, project_repo)

    fs = AsyncIOMotorGridFSBucket(db)
    sboms_to_process = _resolve_sboms_to_process(sboms, scan_type)

    for index, item in enumerate(sboms_to_process):
        sbom_results = await _process_sbom(
            index,
            item,
            scan_id,
            db,
            fs,
            aggregator,
            active_analyzers,
            system_settings,
            project_license_policy=project_license_policy,
            project_analyzer_settings=project_analyzer_settings,
            project_id=project_id,
            scan_type=scan_type,
        )
        results_summary.extend(sbom_results)

    # 1. Fetch and aggregate external results
    external_load_start = datetime.now(timezone.utc)
    await _aggregate_external_results(aggregator, result_repo, scan_id, results_summary)

    # 2. Collect findings and enrichments, then free aggregator
    aggregated_findings = aggregator.get_findings()
    _track_findings_metrics(aggregated_findings)
    dependency_enrichments = aggregator.get_dependency_enrichments()
    del aggregator

    await _enrich_dependencies(dependency_enrichments, scan_id, db)
    del dependency_enrichments

    # 3. Prepare finding records
    scan_created_at: Optional[datetime] = getattr(scan_doc, "created_at", None)
    findings_to_insert, vulnerability_findings = _prepare_finding_records(
        aggregated_findings, scan_id, project_id, scan_created_at
    )
    total_findings_count = len(findings_to_insert)

    # 4. Resolve GitHub token for enrichment
    github_token = system_settings.github_token
    if not github_token:
        github_token = await _get_github_instance_token(db)

    # 5. Enrich vulnerability findings
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

    # 6. Insert findings and apply waivers
    ignored_count, active_waivers = await _persist_findings_and_waivers(
        findings_to_insert, scan_id, project_id, finding_repo, db
    )
    _track_waiver_metrics(active_waivers)

    stats = await calculate_comprehensive_stats(db, scan_id)

    latest_run_summary = {
        "scan_id": scan_id,
        "status": "completed",
        "findings_count": total_findings_count,
        "stats": stats.model_dump(),
        "completed_at": datetime.now(timezone.utc),
    }

    if await _check_race_condition(scan_id, external_load_start, scan_repo):
        return False

    if analysis_aggregation_duration_seconds:
        analysis_aggregation_duration_seconds.observe(time.time() - aggregation_start_time)

    await _finalize_scan_and_project(
        scan_id,
        scan_doc,
        project_id,
        total_findings_count,
        ignored_count,
        stats,
        latest_run_summary,
        scan_repo,
        project_repo,
    )

    await _send_integrations_and_notifications(
        project_id, scan_id, scan_doc, stats, aggregated_findings, results_summary, db
    )

    del aggregated_findings
    _release_memory_to_os()

    return True
