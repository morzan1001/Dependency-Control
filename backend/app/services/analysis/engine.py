import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.models.project import Project
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

logger = logging.getLogger(__name__)


async def _carry_over_external_results(scan_id: str, db):
    """
    Copies analysis results from the original scan to the re-scan for analyzers
    that are NOT part of the internal SBOM analysis (e.g. Secret Scanning, SAST).
    """
    current_scan = await db.scans.find_one({"_id": scan_id})
    if not (
        current_scan
        and current_scan.get("is_rescan")
        and current_scan.get("original_scan_id")
    ):
        return

    original_scan_id = current_scan.get("original_scan_id")
    logger.info(
        f"Rescan detected. Carrying over external results from {original_scan_id} to {scan_id}"
    )

    internal_analyzer_names = list(analyzers.keys())

    # Find results from the original scan that are NOT internal analyzers
    cursor = db.analysis_results.find(
        {
            "scan_id": original_scan_id,
            "analyzer_name": {"$nin": internal_analyzer_names},
        }
    )

    async for old_result in cursor:
        # Avoid duplicates if we already copied them (e.g. if worker restarted)
        exists = await db.analysis_results.find_one(
            {
                "scan_id": scan_id,
                "analyzer_name": old_result["analyzer_name"],
                "result": old_result["result"],  # Simple content check
            }
        )

        if not exists:
            new_result = old_result.copy()
            new_result["_id"] = str(uuid.uuid4())
            new_result["scan_id"] = scan_id
            # Update timestamp to reflect this is part of the new scan record
            new_result["created_at"] = datetime.now(timezone.utc)

            await db.analysis_results.insert_one(new_result)
            logger.info(f"Carried over result for {old_result['analyzer_name']}")


async def process_analyzer(
    analyzer_name: str,
    analyzer: Analyzer,
    sbom: Dict[str, Any],
    scan_id: str,
    db,
    aggregator: ResultAggregator,
    settings: Optional[Dict[str, Any]] = None,
    fallback_source: str = "unknown-sbom",
    parsed_components: Optional[List[Dict[str, Any]]] = None,
) -> str:
    try:
        # Pass parsed components to analyzer if available
        result = await analyzer.analyze(
            sbom, settings=settings, parsed_components=parsed_components
        )

        # Store raw result
        await db.analysis_results.insert_one(
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
        return f"{analyzer_name}: Failed"


async def run_analysis(
    scan_id: str, sboms: List[Dict[str, Any]], active_analyzers: List[str], db
):
    """
    Orchestrates the analysis process for a given SBOM scan.
    """
    logger.info(f"Starting analysis for scan {scan_id}")
    aggregator = ResultAggregator()
    results_summary = []

    # 0. Cleanup previous results for internal analyzers
    internal_analyzers = [name for name in active_analyzers if name in analyzers]
    if internal_analyzers:
        await db.analysis_results.delete_many(
            {"scan_id": scan_id, "analyzer_name": {"$in": internal_analyzers}}
        )

    # Check if this is a re-scan and carry over external results
    await _carry_over_external_results(scan_id, db)

    # Fetch system settings for dynamic configuration
    system_settings_doc = await db.system_settings.find_one({"_id": "current"})
    system_settings = system_settings_doc if system_settings_doc else {}

    # Initialize GridFS
    fs = AsyncIOMotorGridFSBucket(db)

    # Process SBOMs sequentially to save memory
    for index, item in enumerate(sboms):
        current_sbom = None

        # Resolve GridFS reference if needed
        if isinstance(item, dict) and item.get("type") == "gridfs_reference":
            gridfs_id = item.get("gridfs_id")
            try:
                stream = await fs.open_download_stream(ObjectId(gridfs_id))
                content: bytes = await stream.read()
                current_sbom = json.loads(content)
            except Exception as gridfs_err:
                logger.error(
                    f"Failed to fetch SBOM from GridFS {gridfs_id}: {gridfs_err}"
                )
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
        except Exception as parse_err:
            logger.warning(
                f"Failed to pre-parse SBOM: {parse_err} - analyzers will use fallback parsing"
            )

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
                        settings=system_settings,
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
    external_results_cursor = db.analysis_results.find({"scan_id": scan_id})
    async for res in external_results_cursor:
        name = res["analyzer_name"]
        if name not in analyzers:
            aggregator.aggregate(name, res["result"])

    # Save aggregated findings to the scan document
    aggregated_findings = aggregator.get_findings()

    # Get aggregated dependency enrichments
    dependency_enrichments = aggregator.get_dependency_enrichments()

    # Fetch scan to get project_id
    scan_doc = await db.scans.find_one({"_id": scan_id})
    project_id = scan_doc.get("project_id") if scan_doc else None

    # Enrich dependencies with aggregated data
    if dependency_enrichments:
        logger.info(
            f"Enriching {len(dependency_enrichments)} dependencies with aggregated metadata"
        )

        for key, enrichment_data in dependency_enrichments.items():
            # key format: "name@version"
            parts = key.rsplit("@", 1)
            if len(parts) != 2:
                continue
            name, version = parts

            if enrichment_data:
                await db.dependencies.update_many(
                    {"scan_id": scan_id, "name": name, "version": version},
                    {"$set": enrichment_data},
                )

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
    await db.findings.delete_many({"scan_id": scan_id})

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

    github_token = system_settings.get("github_token")

    # EPSS/KEV Enrichment
    if "epss_kev" in active_analyzers and vulnerability_findings:
        try:
            await enrich_vulnerability_findings(
                vulnerability_findings, github_token=github_token
            )
            epss_kev_summary = build_epss_kev_summary(vulnerability_findings)
            await db.analysis_results.insert_one(
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
        except Exception as e:
            logger.warning(f"[epss_kev] Failed to enrich findings: {e}")

    # Reachability Analysis
    if "reachability" in active_analyzers and vulnerability_findings and project_id:
        callgraph = await db.callgraphs.find_one(
            {"project_id": project_id, "scan_id": scan_id}
        )

        if not callgraph:
            pipeline_id = scan_doc.get("pipeline_id") if scan_doc else None
            if pipeline_id:
                callgraph = await db.callgraphs.find_one(
                    {"project_id": project_id, "pipeline_id": pipeline_id}
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
                    vulnerability_findings, callgraph, enriched_count
                )
                await db.analysis_results.insert_one(
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
            except Exception as e:
                logger.warning(f"[reachability] Failed to enrich findings: {e}")
        else:
            await db.scans.update_one(
                {"_id": scan_id},
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
        await db.findings.insert_many(findings_to_insert)

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
            await db.findings.update_many(
                {
                    **query,
                    "type": "vulnerability",
                    "details.vulnerabilities.id": vulnerability_id,
                },
                {
                    "$set": {
                        "details.vulnerabilities.$[vuln].waived": True,
                        "details.vulnerabilities.$[vuln].waiver_reason": waiver.get(
                            "reason"
                        ),
                    }
                },
                array_filters=[{"vuln.id": vulnerability_id}],
            )
        else:
            await db.findings.update_many(
                query, {"$set": {"waived": True, "waiver_reason": waiver.get("reason")}}
            )

    ignored_count = await db.findings.count_documents(
        {"scan_id": scan_id, "waived": True}
    )

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

    await db.scans.update_one(
        {"_id": scan_id},
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

    # Update Project stats
    scan = await db.scans.find_one({"_id": scan_id})
    if scan:
        if scan.get("is_rescan") and scan.get("original_scan_id"):
            await db.scans.update_one(
                {"_id": scan["original_scan_id"]},
                {
                    "$set": {
                        "latest_rescan_id": scan_id,
                        "latest_run": latest_run_summary,
                    }
                },
            )

        await db.projects.update_one(
            {"_id": scan["project_id"]},
            {
                "$set": {
                    "stats": stats.model_dump(),
                    "last_scan_at": datetime.now(timezone.utc),
                    "latest_scan_id": scan_id,
                }
            },
        )

    # Integrations & Notifications
    if scan:
        project_data = await db.projects.find_one({"_id": scan["project_id"]})
        if project_data:
            project = Project(**project_data)

            # GitLab Decoration
            await decorate_gitlab_mr(
                scan_id, stats, scan, project, system_settings
            )

            # Notifications
            await send_scan_notifications(
                scan_id, project, aggregated_findings, results_summary, db
            )
