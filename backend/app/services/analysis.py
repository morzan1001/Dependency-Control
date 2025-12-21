from typing import Dict, Any, List
from datetime import datetime, timezone
import uuid
import asyncio
import logging
import json
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from app.services.analyzers import (
    Analyzer, 
    EndOfLifeAnalyzer, 
    OpenSourceMalwareAnalyzer, 
    TrivyAnalyzer,
    OSVAnalyzer,
    DepsDevAnalyzer,
    LicenseAnalyzer,
    GrypeAnalyzer,
    OutdatedAnalyzer,
    TyposquattingAnalyzer
)
from app.services.notifications import notification_service
from app.models.project import Project
from app.models.system import SystemSettings
from app.models.stats import Stats
from app.models.finding_record import FindingRecord
from app.services.aggregator import ResultAggregator
from app.services.gitlab import GitLabService

logger = logging.getLogger(__name__)

analyzers: Dict[str, Analyzer] = {
    "end_of_life": EndOfLifeAnalyzer(),
    "os_malware": OpenSourceMalwareAnalyzer(),
    "trivy": TrivyAnalyzer(),
    "osv": OSVAnalyzer(),
    "deps_dev": DepsDevAnalyzer(),
    "license_compliance": LicenseAnalyzer(),
    "grype": GrypeAnalyzer(),
    "outdated_packages": OutdatedAnalyzer(),
    "typosquatting": TyposquattingAnalyzer()
}

async def _carry_over_external_results(scan_id: str, db):
    """
    Copies analysis results from the original scan to the re-scan for analyzers
    that are NOT part of the internal SBOM analysis (e.g. Secret Scanning, SAST).
    """
    current_scan = await db.scans.find_one({"_id": scan_id})
    if not (current_scan and current_scan.get("is_rescan") and current_scan.get("original_scan_id")):
        return

    original_scan_id = current_scan.get("original_scan_id")
    logger.info(f"Rescan detected. Carrying over external results from {original_scan_id} to {scan_id}")
    
    internal_analyzer_names = list(analyzers.keys())
    
    # Find results from the original scan that are NOT internal analyzers
    cursor = db.analysis_results.find({
        "scan_id": original_scan_id,
        "analyzer_name": {"$nin": internal_analyzer_names}
    })
    
    async for old_result in cursor:
        # Avoid duplicates if we already copied them (e.g. if worker restarted)
        exists = await db.analysis_results.find_one({
            "scan_id": scan_id,
            "analyzer_name": old_result["analyzer_name"],
            "result": old_result["result"] # Simple content check
        })
        
        if not exists:
            new_result = old_result.copy()
            new_result["_id"] = str(uuid.uuid4())
            new_result["scan_id"] = scan_id
            # Update timestamp to reflect this is part of the new scan record
            new_result["created_at"] = datetime.now(timezone.utc)
            
            await db.analysis_results.insert_one(new_result)
            logger.info(f"Carried over result for {old_result['analyzer_name']}")

async def process_analyzer(analyzer_name: str, analyzer: Analyzer, sbom: Dict[str, Any], scan_id: str, db, aggregator: ResultAggregator, settings: Dict[str, Any] = None, fallback_source: str = "unknown-sbom") -> str:
    try:
        result = await analyzer.analyze(sbom, settings=settings)
        
        # Store raw result
        await db.analysis_results.insert_one({
            "_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "analyzer_name": analyzer_name,
            "result": result,
            "created_at": datetime.now(timezone.utc)
        })
        
        # Extract source name from SBOM metadata
        source = fallback_source
        if sbom.get("metadata") and sbom["metadata"].get("component"):
             source = sbom["metadata"]["component"].get("name", fallback_source)
        elif sbom.get("serialNumber"):
             source = sbom.get("serialNumber")

        # Aggregate result
        aggregator.aggregate(analyzer_name, result, source=source)
        
        logger.info(f"Analysis {analyzer_name} completed for {scan_id}")
        return f"{analyzer_name}: Success"
    except Exception as e:
        logger.error(f"Analysis {analyzer_name} failed: {e}")
        return f"{analyzer_name}: Failed"

async def run_analysis(scan_id: str, sboms: List[Dict[str, Any]], active_analyzers: List[str], db):
    """
    Orchestrates the analysis process for a given SBOM scan.
    
    1. Iterates through requested analyzers (e.g., trivy, grype, osv).
    2. Executes each analyzer asynchronously.
    3. Stores raw results in the 'analysis_results' collection.
    4. Aggregates findings from all scanners into a unified format using ResultAggregator.
    5. Updates the 'scans' document with the aggregated summary.
    6. Sends notifications (Email/Slack) to project members.
    """
    logger.info(f"Starting analysis for scan {scan_id}")
    aggregator = ResultAggregator()
    results_summary = []
    
    # 0. Cleanup previous results for internal analyzers
    internal_analyzers = [name for name in active_analyzers if name in analyzers]
    if internal_analyzers:
        await db.analysis_results.delete_many({
            "scan_id": scan_id,
            "analyzer_name": {"$in": internal_analyzers}
        })

    # Check if this is a re-scan and carry over external results (e.g. Secret Scanning, SAST)
    await _carry_over_external_results(scan_id, db)

    # Fetch system settings for dynamic configuration (e.g. API keys)
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
                content = await stream.read()
                current_sbom = json.loads(content)
            except Exception as gridfs_err:
                logger.error(f"Failed to fetch SBOM from GridFS {gridfs_id}: {gridfs_err}")
                # Log a system warning finding
                aggregator.aggregate("system", {"error": f"Failed to load SBOM from GridFS: {gridfs_err}"})
                continue
        else:
            current_sbom = item

        if not current_sbom:
            continue

        # Determine fallback source name
        fallback_source = f"SBOM #{index + 1}"

        # Run analyzers for THIS SBOM concurrently
        tasks = []
        for analyzer_name in active_analyzers:
            if analyzer_name in analyzers:
                analyzer = analyzers[analyzer_name]
                tasks.append(process_analyzer(analyzer_name, analyzer, current_sbom, scan_id, db, aggregator, settings=system_settings, fallback_source=fallback_source))
        
        # Wait for this batch to finish before moving to the next SBOM
        # This ensures we only hold one SBOM in memory at a time
        batch_results = await asyncio.gather(*tasks)
        results_summary.extend(batch_results)
        
        # Explicitly release memory
        del current_sbom

    # 1. Fetch and Aggregate External Results (TruffleHog, OpenGrep, etc.)
    # These are results that were pushed via API endpoints directly to analysis_results
    external_results_cursor = db.analysis_results.find({"scan_id": scan_id})
    async for res in external_results_cursor:
        name = res["analyzer_name"]
        # Only aggregate if it's NOT one of the internal analyzers we just ran
        # (ResultAggregator handles deduplication, but let's be explicit)
        if name not in analyzers:
             aggregator.aggregate(name, res["result"])

    # Save aggregated findings to the scan document
    aggregated_findings = aggregator.get_findings()
    
    # Fetch scan to get project_id
    scan_doc = await db.scans.find_one({"_id": scan_id})
    project_id = scan_doc.get("project_id") if scan_doc else None

    # Fetch waivers
    waivers = []
    if project_id:
        waivers = await db.waivers.find({"project_id": project_id}).to_list(length=None)

    # Filter active waivers
    active_waivers = [w for w in waivers if not (w.get("expiration_date") and w["expiration_date"] < datetime.now(timezone.utc))]

    # Save Findings to 'findings' collection (Point B)
    # First, clear old findings for this scan (idempotency)
    await db.findings.delete_many({"scan_id": scan_id})
    
    findings_to_insert = []
    for f in aggregated_findings:
        # Convert Finding to FindingRecord dict
        # We use the Pydantic model to validate/transform if needed, or just construct dict
        record = f.model_dump()
        record["scan_id"] = scan_id
        record["project_id"] = project_id
        record["finding_id"] = f.id # Map logical ID
        record["_id"] = str(uuid.uuid4()) # New Mongo ID
        findings_to_insert.append(record)
        
    if findings_to_insert:
        await db.findings.insert_many(findings_to_insert)

    # Apply waivers via DB updates (Optimization: Bulk updates instead of loop)
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
            
        await db.findings.update_many(
            query, 
            {"$set": {"waived": True, "waiver_reason": waiver.get("reason")}}
        )

    ignored_count = await db.findings.count_documents({"scan_id": scan_id, "waived": True})

    # Calculate stats via Aggregation (Optimization: Calculation in DB)
    pipeline = [
        {"$match": {"scan_id": scan_id, "waived": False}},
        {"$project": {
            "severity": 1,
            "cvss_score": "$details.cvss_score",
            "calculated_score": {
                "$switch": {
                    "branches": [
                        {"case": {"$eq": ["$severity", "CRITICAL"]}, "then": 10.0},
                        {"case": {"$eq": ["$severity", "HIGH"]}, "then": 7.5},
                        {"case": {"$eq": ["$severity", "MEDIUM"]}, "then": 4.0},
                        {"case": {"$eq": ["$severity", "LOW"]}, "then": 1.0}
                    ],
                    "default": 0.0
                }
            }
        }},
        {"$group": {
            "_id": None,
            "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}},
            "high": {"$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}},
            "medium": {"$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}},
            "low": {"$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}},
            "info": {"$sum": {"$cond": [{"$eq": ["$severity", "INFO"]}, 1, 0]}},
            "unknown": {"$sum": {"$cond": [{"$eq": ["$severity", "UNKNOWN"]}, 1, 0]}},
            "risk_score": {"$sum": {"$toDouble": {"$ifNull": ["$cvss_score", "$calculated_score"]}}}
        }}
    ]

    stats_result = await db.findings.aggregate(pipeline).to_list(1)
    
    stats = Stats()
    if stats_result:
        res = stats_result[0]
        stats.critical = res.get("critical", 0)
        stats.high = res.get("high", 0)
        stats.medium = res.get("medium", 0)
        stats.low = res.get("low", 0)
        stats.info = res.get("info", 0)
        stats.unknown = res.get("unknown", 0)
        stats.risk_score = round(res.get("risk_score", 0.0), 1)

    # Prepare latest run summary
    latest_run_summary = {
        "scan_id": scan_id,
        "status": "completed",
        "findings_count": len(aggregated_findings),
        "stats": stats.model_dump(),
        "completed_at": datetime.now(timezone.utc)
    }

    await db.scans.update_one(
        {"_id": scan_id},
        {"$set": {
            "status": "completed", 
            "findings_count": len(aggregated_findings),
            "ignored_count": ignored_count,
            "stats": stats.model_dump(),
            "completed_at": datetime.now(timezone.utc),
            # If it's an original scan, it is its own latest run
            "latest_run": latest_run_summary
        },
        "$unset": {"findings_summary": ""} # Remove legacy field if it exists
        }
    )
    
    # Update Project stats
    scan = await db.scans.find_one({"_id": scan_id})
    if scan:
        # If this is a re-scan, update the original scan's latest_run info
        # BUT DO NOT overwrite the original scan's own stats/status
        if scan.get("is_rescan") and scan.get("original_scan_id"):
            await db.scans.update_one(
                {"_id": scan["original_scan_id"]},
                {"$set": {
                    "latest_rescan_id": scan_id,
                    "latest_run": latest_run_summary
                }}
            )

        await db.projects.update_one(
            {"_id": scan["project_id"]},
            {"$set": {
                "stats": stats.model_dump(), 
                "last_scan_at": datetime.now(timezone.utc),
                "latest_scan_id": scan_id
            }}
        )

    # GitLab Merge Request Decoration
    try:
        scan = await db.scans.find_one({"_id": scan_id})
        if scan:
            project_data = await db.projects.find_one({"_id": scan["project_id"]})
            if project_data:
                project = Project(**project_data)
                
                if project.gitlab_mr_comments_enabled and project.gitlab_project_id and scan.get("commit_hash"):
                    # Ensure we have a valid SystemSettings object
                    settings_obj = SystemSettings(**system_settings)
                    gitlab_service = GitLabService(settings_obj)
                    
                    mrs = await gitlab_service.get_merge_requests_for_commit(project.gitlab_project_id, scan["commit_hash"])
                    
                    if mrs:
                        # Construct Markdown Comment
                        # Use dashboard_url from settings if available, otherwise try to infer or use a placeholder
                        dashboard_url = getattr(settings_obj, "dashboard_url", "http://localhost:5173")
                        scan_url = f"{dashboard_url}/projects/{project.id}/scans/{scan_id}"
                        
                        status_emoji = "✅"
                        if stats.risk_score > 0:
                            status_emoji = "⚠️"
                        if stats.critical > 0 or stats.high > 0:
                            status_emoji = "🚨"
                            
                        comment_body = f"""
### {status_emoji} Dependency Control Scan Results

**Status:** Completed
**Risk Score:** {stats.risk_score}

| Severity | Count |
| :--- | :--- |
| 🔴 Critical | {stats.critical} |
| 🟠 High | {stats.high} |
| 🟡 Medium | {stats.medium} |
| 🔵 Low | {stats.low} |

[View Full Report]({scan_url})
"""
                        for mr in mrs:
                            await gitlab_service.post_merge_request_comment(project.gitlab_project_id, mr["iid"], comment_body)
                            logger.info(f"Posted scan results to MR !{mr['iid']} for project {project.name}")

    except Exception as e:
        logger.error(f"Failed to decorate GitLab MR: {e}")

    # Send Notification
    try:
        scan = await db.scans.find_one({"_id": scan_id})
        if scan:
            project_data = await db.projects.find_one({"_id": scan["project_id"]})
            if project_data:
                project = Project(**project_data)
                await notification_service.notify_project_members(
                    project=project, 
                    event_type="analysis_completed", 
                    subject=f"Analysis Completed: {project.name}", 
                    message=f"Scan {scan_id} completed.\nFound {len(aggregated_findings)} issues.\nResults:\n" + "\n".join(results_summary),
                    db=db
                )
    except Exception as e:
        logger.error(f"Failed to send notifications: {e}")

