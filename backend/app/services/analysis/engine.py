import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo import UpdateOne

from app.models.project import Project
from app.repositories import (
    AnalysisResultRepository,
    CallgraphRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)
from app.repositories.system_settings import SystemSettingsRepository
from app.services.aggregator import ResultAggregator
from app.services.analyzers import Analyzer
from app.services.enrichment import enrich_vulnerability_findings
from app.services.reachability_enrichment import enrich_findings_with_reachability
from app.services.sbom_parser import parse_sbom
from app.services.analysis.registry import analyzers
from app.services.analysis.stats import (
    build_epss_kev_summary,
    build_reachability_summary,
    calculate_comprehensive_stats,
)
from app.services.analysis.integrations import decorate_gitlab_mr
from app.services.analysis.notifications import send_scan_notifications
from app.services.analysis.types import Database, ScanDict

logger = logging.getLogger(__name__)

# Import metrics for detailed analysis tracking
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
    # Fallback if metrics module is not available yet
    (
        analysis_scans_total,
        analysis_findings_total,
        analysis_errors_total,
        analysis_sbom_processed_total,
        analysis_components_parsed_total,
        analysis_sbom_parse_errors_total,
        analysis_gridfs_operations_total,
        analysis_enrichment_total,
        analysis_epss_scores,
        analysis_kev_vulnerabilities_total,
        analysis_reachable_vulnerabilities_total,
        analysis_waivers_applied_total,
        analysis_race_conditions_total,
        analysis_rescan_operations_total,
        analysis_aggregation_duration_seconds,
        analysis_findings_by_type,
        analysis_duration_seconds,
    ) = [None] * 17


async def _carry_over_external_results(
    scan_id: str, scan_doc: Optional[ScanDict], db: Database
) -> None:
    """
    Copies analysis results from the original scan to the re-scan for analyzers
    that are NOT part of the internal SBOM analysis (e.g. Secret Scanning, SAST).
    """
    if not (scan_doc and scan_doc.is_rescan and scan_doc.original_scan_id):
        return

    original_scan_id = scan_doc.original_scan_id
    logger.info(
        f"Rescan detected. Carrying over external results from {original_scan_id} to {scan_id}"
    )

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

    for old_result in old_results:
        # Use upsert to avoid race conditions when multiple workers might copy the same result
        # The unique key is (scan_id, analyzer_name, result hash)
        new_result = old_result.model_dump(by_alias=True).copy()
        new_result["_id"] = str(uuid.uuid4())
        new_result["scan_id"] = scan_id
        new_result["created_at"] = datetime.now(timezone.utc)

        # Use upsert via repository (upsert is implicit, no parameter needed)
        await result_repo.upsert(
            {
                "scan_id": scan_id,
                "analyzer_name": old_result["analyzer_name"],
                "result": old_result["result"],
            },
            {"$setOnInsert": new_result},
        )
        logger.debug(f"Carried over result for {old_result['analyzer_name']}")


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
) -> str:
    analyzer_start_time = time.time()
    try:
        # Track analyzer execution
        if analysis_scans_total:
            analysis_scans_total.labels(analyzer=analyzer_name).inc()

        # Pass parsed components to analyzer if available
        result = await analyzer.analyze(
            sbom, settings=settings, parsed_components=parsed_components
        )

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
        logger.error(f"Analysis {analyzer_name} failed: {e}")
        # Track errors
        if analysis_errors_total:
            analysis_errors_total.labels(analyzer=analyzer_name).inc()
        # Report failure to aggregator so it appears in findings
        aggregator.aggregate(
            analyzer_name, {"error": str(e)}, source=f"System: {analyzer_name}"
        )
        return f"{analyzer_name}: Failed"


async def run_analysis(
    scan_id: str, sboms: List[Dict[str, Any]], active_analyzers: List[str], db: Database
) -> bool:
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

    # Fetch scan document ONCE at the beginning - reuse throughout the function
    scan_doc = await scan_repo.get_by_id(scan_id)
    if not scan_doc:
        logger.error(f"Scan {scan_id} not found")
        return False

    project_id: Optional[str] = scan_doc.project_id

    # 0. Cleanup previous results for internal analyzers
    internal_analyzers = [name for name in active_analyzers if name in analyzers]
    if internal_analyzers:
        # Delete via repository for consistency
        await result_repo.delete_many(
            {"scan_id": scan_id, "analyzer_name": {"$in": internal_analyzers}}
        )

    # Check if this is a re-scan and carry over external results
    if scan_doc.is_rescan:
        if analysis_rescan_operations_total:
            analysis_rescan_operations_total.inc()

    await _carry_over_external_results(scan_id, scan_doc, db)

    # Fetch system settings for dynamic configuration
    settings_repo = SystemSettingsRepository(db)
    system_settings = await settings_repo.get()

    # Initialize GridFS
    fs = AsyncIOMotorGridFSBucket(db)

    # Process SBOMs sequentially to save memory
    for index, item in enumerate(sboms):
        current_sbom = None

        # Resolve GridFS reference if needed
        if isinstance(item, dict) and item.get("type") == "gridfs_reference":
            gridfs_id = item.get("gridfs_id")
            try:
                if analysis_gridfs_operations_total:
                    analysis_gridfs_operations_total.labels(
                        operation="download", status="attempt"
                    ).inc()
                stream = await fs.open_download_stream(ObjectId(gridfs_id))
                content: bytes = await stream.read()
                current_sbom = json.loads(content)
                if analysis_gridfs_operations_total:
                    analysis_gridfs_operations_total.labels(
                        operation="download", status="success"
                    ).inc()
            except Exception as gridfs_err:
                logger.error(
                    f"Failed to fetch SBOM from GridFS {gridfs_id}: {gridfs_err}"
                )
                if analysis_gridfs_operations_total:
                    analysis_gridfs_operations_total.labels(
                        operation="download", status="error"
                    ).inc()
                aggregator.aggregate(
                    "system",
                    {"error": f"Failed to load SBOM from GridFS: {gridfs_err}"},
                )
                continue
        else:
            current_sbom = item

        if not current_sbom:
            continue

        # Determine fallback source name
        fallback_source = f"SBOM #{index + 1}"

        # Parse SBOM once
        parsed_components = []
        try:
            parsed_sbom = parse_sbom(current_sbom)
            parsed_components = [dep.to_dict() for dep in parsed_sbom.dependencies]
            logger.info(
                f"Parsed SBOM: format={parsed_sbom.format.value}, components={len(parsed_components)}"
            )
            # Track metrics
            if analysis_sbom_processed_total:
                analysis_sbom_processed_total.labels(
                    format=parsed_sbom.format.value
                ).inc()
            if analysis_components_parsed_total:
                analysis_components_parsed_total.inc(len(parsed_components))
        except Exception as parse_err:
            logger.warning(
                f"Failed to pre-parse SBOM: {parse_err} - analyzers will use fallback parsing"
            )
            if analysis_sbom_parse_errors_total:
                analysis_sbom_parse_errors_total.inc()

        # Run analyzers for THIS SBOM concurrently
        tasks = []
        for analyzer_name in active_analyzers:
            if analyzer_name in analyzers:
                analyzer = analyzers[analyzer_name]
                tasks.append(
                    process_analyzer(
                        analyzer_name,
                        analyzer,
                        current_sbom,
                        scan_id,
                        db,
                        aggregator,
                        settings=system_settings.model_dump() if system_settings else None,
                        fallback_source=fallback_source,
                        parsed_components=(
                            parsed_components if parsed_components else None
                        ),
                    )
                )

        # Wait for this batch to finish
        batch_results = await asyncio.gather(*tasks)
        results_summary.extend(batch_results)

        # Explicitly release memory
        del current_sbom

    # 1. Fetch and Aggregate External Results (TruffleHog, OpenGrep, etc.)
    # We mark the time BEFORE loading external results to detect race conditions later
    external_load_start = datetime.now(timezone.utc)

    # Load external results via repository
    external_results = await result_repo.find_by_scan(scan_id, limit=10000)
    for res in external_results:
        name = res.analyzer_name
        if name not in analyzers:
            aggregator.aggregate(name, res.result)

    # Save aggregated findings to the scan document
    aggregated_findings = aggregator.get_findings()

    # Track findings metrics
    if analysis_findings_by_type:
        for finding in aggregated_findings:
            finding_type = finding.type if hasattr(finding, "type") else "unknown"
            severity = finding.severity if hasattr(finding, "severity") else "unknown"
            analysis_findings_by_type.labels(type=finding_type, severity=severity).inc()

    # Get aggregated dependency enrichments
    dependency_enrichments = aggregator.get_dependency_enrichments()

    # Note: project_id was already fetched at the beginning of the function

    # Enrich dependencies with aggregated data
    if dependency_enrichments:
        logger.info(
            f"Enriching {len(dependency_enrichments)} dependencies with aggregated metadata"
        )

        bulk_ops = []
        for key, enrichment_data in dependency_enrichments.items():
            # key format: "name@version"
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

        if bulk_ops:
            try:
                await db.dependencies.bulk_write(bulk_ops, ordered=False)
                logger.info(f"Bulk updated {len(bulk_ops)} dependencies.")
            except Exception as e:
                logger.error(f"Failed to bulk update dependencies: {e}")

    # Fetch waivers
    waivers = []
    if project_id:
        waivers = await db.waivers.find({"project_id": project_id}).to_list(length=None)

    # Filter active waivers
    active_waivers = [
        w
        for w in waivers
        if not (
            w.get("expiration_date")
            and w["expiration_date"] < datetime.now(timezone.utc)
        )
    ]

    # Save Findings to 'findings' collection
    await finding_repo.delete_many({"scan_id": scan_id})

    findings_to_insert = []
    for f in aggregated_findings:
        record = f.model_dump()
        record["scan_id"] = scan_id
        record["project_id"] = project_id
        record["finding_id"] = f.id
        record["_id"] = str(uuid.uuid4())
        findings_to_insert.append(record)

    # Post-Processing: Enrich vulnerability findings
    vulnerability_findings = [
        f for f in findings_to_insert if f.get("type") == "vulnerability"
    ]

    github_token = system_settings.github_token

    # EPSS/KEV Enrichment
    if "epss_kev" in active_analyzers and vulnerability_findings:
        try:
            await enrich_vulnerability_findings(
                vulnerability_findings, github_token=github_token
            )
            epss_kev_summary = build_epss_kev_summary(vulnerability_findings)
            # Store EPSS/KEV summary via repository
            await result_repo.create_raw(
                {
                    "_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "analyzer_name": "epss_kev",
                    "result": epss_kev_summary,
                    "created_at": datetime.now(timezone.utc),
                }
            )
            logger.info(
                f"[epss_kev] Enriched {len(vulnerability_findings)} vulnerability findings with EPSS/KEV data"
            )

            # Track EPSS/KEV metrics
            if analysis_enrichment_total:
                analysis_enrichment_total.labels(type="epss_kev").inc(
                    len(vulnerability_findings)
                )

            # Track EPSS scores and KEV findings
            for finding in vulnerability_findings:
                details = finding.get("details", {})
                epss_score = details.get("epss_score")
                if epss_score is not None and analysis_epss_scores:
                    try:
                        analysis_epss_scores.observe(float(epss_score))
                    except (ValueError, TypeError):
                        pass

                if details.get("is_kev") and analysis_kev_vulnerabilities_total:
                    analysis_kev_vulnerabilities_total.inc()

        except Exception as e:
            logger.warning(f"[epss_kev] Failed to enrich findings: {e}")

    # Reachability Analysis
    if "reachability" in active_analyzers and vulnerability_findings and project_id:
        callgraph = await callgraph_repo.get_minimal_by_scan(project_id, scan_id)

        if not callgraph:
            pipeline_id = scan_doc.pipeline_id if scan_doc else None
            if pipeline_id:
                callgraph = await callgraph_repo.get_minimal_by_pipeline(
                    project_id, pipeline_id
                )

        if callgraph:
            try:
                enriched_count = await enrich_findings_with_reachability(
                    findings=vulnerability_findings,
                    project_id=str(project_id),
                    db=db,
                    scan_id=scan_id,
                )
                reachability_summary = build_reachability_summary(
                    vulnerability_findings, callgraph.model_dump(by_alias=True), enriched_count
                )
                # Store reachability summary via repository
                await result_repo.create_raw(
                    {
                        "_id": str(uuid.uuid4()),
                        "scan_id": scan_id,
                        "analyzer_name": "reachability",
                        "result": reachability_summary,
                        "created_at": datetime.now(timezone.utc),
                    }
                )
                logger.info(
                    f"[reachability] Enriched {enriched_count} findings for scan {scan_id}"
                )

                # Track reachability metrics
                if analysis_enrichment_total:
                    analysis_enrichment_total.labels(type="reachability").inc(
                        enriched_count
                    )

                # Track reachable vulnerabilities by level
                if analysis_reachable_vulnerabilities_total:
                    for finding in vulnerability_findings:
                        details = finding.get("details", {})
                        reachability = details.get("reachability", {})
                        if reachability.get("is_reachable"):
                            level = reachability.get("level", "unknown")
                            analysis_reachable_vulnerabilities_total.labels(
                                reachability_level=level
                            ).inc()
            except Exception as e:
                logger.warning(f"[reachability] Failed to enrich findings: {e}")
        else:
            await scan_repo.update_raw(
                scan_id,
                {
                    "$set": {
                        "reachability_pending": True,
                        "reachability_pending_since": datetime.now(timezone.utc),
                    }
                },
            )
            logger.info(
                f"[reachability] No callgraph available for scan {scan_id}. Marked as pending."
            )

    if findings_to_insert:
        await finding_repo.create_many_raw(findings_to_insert)

    # Apply waivers via DB updates
    for waiver in active_waivers:
        query = {"scan_id": scan_id}
        if waiver.get("finding_id"):
            query["finding_id"] = waiver["finding_id"]
        if waiver.get("package_name"):
            query["component"] = waiver["package_name"]
        if waiver.get("package_version"):
            query["version"] = waiver["package_version"]
        if waiver.get("finding_type"):
            query["type"] = waiver["finding_type"]

        vulnerability_id = waiver.get("vulnerability_id")
        if vulnerability_id:
            # Use custom repository method with array_filters support
            await finding_repo.apply_vulnerability_waiver(
                scan_id=scan_id,
                vulnerability_id=vulnerability_id,
                waived=True,
                waiver_reason=waiver.get("reason"),
            )
        else:
            # Use custom repository method for finding-level waivers
            await finding_repo.apply_finding_waiver(
                scan_id=scan_id,
                query={k: v for k, v in query.items() if k != "scan_id"},
                waived=True,
                waiver_reason=waiver.get("reason"),
            )

    ignored_count = await finding_repo.count({"scan_id": scan_id, "waived": True})

    # Track waiver metrics
    if analysis_waivers_applied_total:
        # Count by waiver type
        waiver_types = {}
        for waiver in active_waivers:
            waiver_type = (
                "finding_id"
                if waiver.get("finding_id")
                else (
                    "package"
                    if waiver.get("package_name")
                    else (
                        "type"
                        if waiver.get("finding_type")
                        else (
                            "vulnerability_id"
                            if waiver.get("vulnerability_id")
                            else "other"
                        )
                    )
                )
            )
            waiver_types[waiver_type] = waiver_types.get(waiver_type, 0) + 1

        for waiver_type, count in waiver_types.items():
            analysis_waivers_applied_total.labels(type=waiver_type).inc(count)

    # Calculate comprehensive stats
    stats = await calculate_comprehensive_stats(db, scan_id)

    # Prepare latest run summary
    latest_run_summary = {
        "scan_id": scan_id,
        "status": "completed",
        "findings_count": len(aggregated_findings),
        "stats": stats.model_dump(),
        "completed_at": datetime.now(timezone.utc),
    }

    # Race Condition Check: Did new results arrive while we were processing?
    # Specifically, after we started loading external results.
    # We need a fresh query here since last_result_at may have changed during processing
    race_check = await scan_repo.get_by_id(scan_id)
    last_result_at = race_check.last_result_at if race_check else None

    # Ensure timezone-aware comparison (handle legacy timezone-naive datetimes)
    if last_result_at:
        if last_result_at.tzinfo is None:
            # Convert naive datetime to UTC
            last_result_at = last_result_at.replace(tzinfo=timezone.utc)

    if last_result_at and last_result_at >= external_load_start:
        logger.warning(
            f"Race condition detected for scan {scan_id}. "
            f"New results arrived at {last_result_at} (Analysis load start: {external_load_start}). "
            f"Rescheduling scan."
        )
        # Track race condition
        if analysis_race_conditions_total:
            analysis_race_conditions_total.inc()

        # Reset to pending so it gets picked up again
        # IMPORTANT: Increment retry_count to prevent infinite loops
        # This ensures that scans stuck in race condition loops eventually fail
        await scan_repo.update_raw(
            scan_id,
            {
                "$set": {
                    "status": "pending",
                    # We do NOT unset received_results/last_result_at here, keep them for the next run
                },
                "$inc": {"retry_count": 1},
            },
        )
        return False

    # Track aggregation duration
    if analysis_aggregation_duration_seconds:
        aggregation_duration = time.time() - aggregation_start_time
        analysis_aggregation_duration_seconds.observe(aggregation_duration)

    await scan_repo.update_raw(
        scan_id,
        {
            "$set": {
                "status": "completed",
                "findings_count": len(aggregated_findings),
                "ignored_count": ignored_count,
                "stats": stats.model_dump(),
                "completed_at": datetime.now(timezone.utc),
                "latest_run": latest_run_summary,
            },
            "$unset": {
                "findings_summary": "",
                # Clear result tracking fields - they will be repopulated on next pipeline run
                "received_results": "",
                "last_result_at": "",
            },
        },
    )

    # Update Project stats (reuse scan_doc from the beginning)
    if scan_doc.is_rescan and scan_doc.original_scan_id:
        await scan_repo.update_raw(
            scan_doc["original_scan_id"],
            {
                "$set": {
                    "latest_rescan_id": scan_id,
                    "latest_run": latest_run_summary,
                }
            },
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

    # Integrations & Notifications
    if project_id:
        project_data = await project_repo.get_raw_by_id(project_id)
        if project_data:
            project = Project(**project_data)

            # GitLab Decoration
            await decorate_gitlab_mr(
                scan_id, stats, scan_doc, project, system_settings, db
            )

            # Notifications
            await send_scan_notifications(
                scan_id, project, aggregated_findings, results_summary, db
            )

    return True
