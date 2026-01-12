import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.core.constants import sort_by_severity
from app.models.project import Project
from app.models.stats import (
    PrioritizedCounts,
    ReachabilityStats,
    Stats,
    ThreatIntelligenceStats,
)
from app.models.system import SystemSettings
from app.services.aggregator import ResultAggregator
from app.services.analyzers import (
    Analyzer,
    DepsDevAnalyzer,
    EndOfLifeAnalyzer,
    EPSSKEVAnalyzer,
    GrypeAnalyzer,
    HashVerificationAnalyzer,
    LicenseAnalyzer,
    MaintainerRiskAnalyzer,
    OpenSourceMalwareAnalyzer,
    OSVAnalyzer,
    OutdatedAnalyzer,
    ReachabilityAnalyzer,
    TrivyAnalyzer,
    TyposquattingAnalyzer,
)
from app.services.gitlab import GitLabService
from app.services.notifications import notification_service
from app.services.reachability_enrichment import enrich_findings_with_reachability
from app.services.sbom_parser import parse_sbom
from app.services.vulnerability_enrichment import enrich_vulnerability_findings

logger = logging.getLogger(__name__)

# Regular analyzers that process SBOMs
analyzers: Dict[str, Analyzer] = {
    "end_of_life": EndOfLifeAnalyzer(),
    "os_malware": OpenSourceMalwareAnalyzer(),
    "trivy": TrivyAnalyzer(),
    "osv": OSVAnalyzer(),
    "deps_dev": DepsDevAnalyzer(),
    "license_compliance": LicenseAnalyzer(),
    "grype": GrypeAnalyzer(),
    "outdated_packages": OutdatedAnalyzer(),
    "typosquatting": TyposquattingAnalyzer(),
    "hash_verification": HashVerificationAnalyzer(),
    "maintainer_risk": MaintainerRiskAnalyzer(),
}

# Post-processing analyzers that enrich existing findings
# These run AFTER regular analyzers and don't process SBOMs directly
post_processors: Dict[str, Analyzer] = {
    "epss_kev": EPSSKEVAnalyzer(),
    "reachability": ReachabilityAnalyzer(),
}

# Vulnerability scanner names (post-processors depend on these)
VULNERABILITY_ANALYZERS: Set[str] = {"trivy", "grype", "osv", "deps_dev"}


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


async def run_analysis(
    scan_id: str, sboms: List[Dict[str, Any]], active_analyzers: List[str], db
):
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
        await db.analysis_results.delete_many(
            {"scan_id": scan_id, "analyzer_name": {"$in": internal_analyzers}}
        )

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
                logger.error(
                    f"Failed to fetch SBOM from GridFS {gridfs_id}: {gridfs_err}"
                )
                # Log a system warning finding
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

        # Parse SBOM once using the unified parser - all analyzers use these normalized components
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

    # Get aggregated dependency enrichments (merged from all sources)
    dependency_enrichments = aggregator.get_dependency_enrichments()

    # Fetch scan to get project_id
    scan_doc = await db.scans.find_one({"_id": scan_id})
    project_id = scan_doc.get("project_id") if scan_doc else None

    # Enrich dependencies with aggregated data from all scanners
    # This includes: deps.dev metadata, license analysis, etc.
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
        record["finding_id"] = f.id  # Map logical ID
        record["_id"] = str(uuid.uuid4())  # New Mongo ID
        findings_to_insert.append(record)

    # Post-Processing: Enrich vulnerability findings with additional data
    # These only run if the corresponding post-processor is enabled
    vulnerability_findings = [
        f for f in findings_to_insert if f.get("type") == "vulnerability"
    ]

    # Extract GitHub token from system settings for authenticated API access
    github_token = system_settings.get("github_token")

    # EPSS/KEV Enrichment (only if epss_kev analyzer is active)
    epss_kev_summary = None
    if "epss_kev" in active_analyzers and vulnerability_findings:
        try:
            await enrich_vulnerability_findings(
                vulnerability_findings, github_token=github_token
            )

            # Build summary for raw data view
            epss_kev_summary = _build_epss_kev_summary(vulnerability_findings)

            # Store summary in analysis_results
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

    # Reachability Analysis (only if reachability analyzer is active)
    if "reachability" in active_analyzers and vulnerability_findings:
        # Check if callgraph exists for this scan
        # Priority: scan_id > pipeline_id (fallback)
        callgraph = await db.callgraphs.find_one(
            {"project_id": project_id, "scan_id": scan_id}
        )

        if not callgraph:
            # Fallback: try to find callgraph via pipeline_id
            pipeline_id = scan_doc.get("pipeline_id") if scan_doc else None
            if pipeline_id:
                callgraph = await db.callgraphs.find_one(
                    {"project_id": project_id, "pipeline_id": pipeline_id}
                )

        if callgraph:
            # Callgraph exists - run reachability analysis now
            try:
                enriched_count = await enrich_findings_with_reachability(
                    findings=vulnerability_findings,
                    project_id=project_id,
                    db=db,
                    scan_id=scan_id,
                )

                # Build and store reachability summary
                reachability_summary = _build_reachability_summary(
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

                if enriched_count > 0:
                    logger.info(
                        f"[reachability] Enriched {enriched_count} findings for scan {scan_id}"
                    )
                else:
                    logger.info(
                        f"[reachability] No vulnerable symbols matched in callgraph for scan {scan_id}"
                    )
            except Exception as e:
                logger.warning(f"[reachability] Failed to enrich findings: {e}")
        else:
            # No callgraph yet - mark scan as pending
            # When callgraph is uploaded, it will trigger reachability analysis
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
                f"[reachability] No callgraph available for scan {scan_id}. "
                f"Marked as pending - will run when callgraph is uploaded."
            )

    if findings_to_insert:
        await db.findings.insert_many(findings_to_insert)

    # Apply waivers via DB updates (Optimization: Bulk updates instead of loop)
    # Waivers can now target specific vulnerabilities within aggregated findings
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

        # Handle vulnerability_id for granular CVE-level waivers
        vulnerability_id = waiver.get("vulnerability_id")
        if vulnerability_id:
            # For vulnerability-specific waivers, we need to update the nested vulnerability
            # within the details.vulnerabilities array, not waive the entire finding
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
            # Standard waiver - waive the entire finding
            await db.findings.update_many(
                query, {"$set": {"waived": True, "waiver_reason": waiver.get("reason")}}
            )

    ignored_count = await db.findings.count_documents(
        {"scan_id": scan_id, "waived": True}
    )

    # Calculate comprehensive stats via Aggregation (with EPSS/KEV/Reachability)
    stats = await _calculate_comprehensive_stats(db, scan_id)

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
                # If it's an original scan, it is its own latest run
                "latest_run": latest_run_summary,
            },
            "$unset": {"findings_summary": ""},  # Remove legacy field if it exists
        },
    )

    # Update Project stats
    scan = await db.scans.find_one({"_id": scan_id})
    if scan:
        # If this is a re-scan, update the original scan's latest_run info
        # BUT DO NOT overwrite the original scan's own stats/status
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

    # GitLab Merge Request Decoration
    try:
        scan = await db.scans.find_one({"_id": scan_id})
        if scan:
            project_data = await db.projects.find_one({"_id": scan["project_id"]})
            if project_data:
                project = Project(**project_data)

                if (
                    project.gitlab_mr_comments_enabled
                    and project.gitlab_project_id
                    and scan.get("commit_hash")
                ):
                    # Ensure we have a valid SystemSettings object
                    settings_obj = SystemSettings(**system_settings)
                    gitlab_service = GitLabService(settings_obj)

                    mrs = await gitlab_service.get_merge_requests_for_commit(
                        project.gitlab_project_id, scan["commit_hash"]
                    )

                    if mrs:
                        # Construct Markdown Comment
                        # Use dashboard_url from settings if available, otherwise try to infer or use a placeholder
                        dashboard_url = getattr(
                            settings_obj, "dashboard_url", "http://localhost:5173"
                        )
                        scan_url = (
                            f"{dashboard_url}/projects/{project.id}/scans/{scan_id}"
                        )

                        status_emoji = "[OK]"
                        if stats.risk_score > 0:
                            status_emoji = "[WARNING]"
                        if stats.critical > 0 or stats.high > 0:
                            status_emoji = "[ALERT]"

                        comment_body = f"""
### {status_emoji} Dependency Control Scan Results

**Status:** Completed
**Risk Score:** {stats.risk_score}

| Severity | Count |
| :--- | :--- |
| Critical | {stats.critical} |
| High | {stats.high} |
| Medium | {stats.medium} |
| Low | {stats.low} |

[View Full Report]({scan_url})
"""
                        for mr in mrs:
                            # Check for existing comment to update instead of creating a new one (deduplication)
                            existing_notes = await gitlab_service.get_merge_request_notes(
                                project.gitlab_project_id, mr["iid"]
                            )
                            
                            existing_comment_id = None
                            for note in existing_notes:
                                if "Dependency Control Scan Results" in note.get("body", ""):
                                    existing_comment_id = note["id"]
                                    break
                            
                            if existing_comment_id:
                                await gitlab_service.update_merge_request_comment(
                                    project.gitlab_project_id, mr["iid"], existing_comment_id, comment_body
                                )
                                logger.info(
                                    f"Updated scan results on MR !{mr['iid']} for project {project.name}"
                                )
                            else:
                                await gitlab_service.post_merge_request_comment(
                                    project.gitlab_project_id, mr["iid"], comment_body
                                )
                                logger.info(
                                    f"Posted scan results to MR !{mr['iid']} for project {project.name}"
                                )

    except Exception as e:
        logger.error(f"Failed to decorate GitLab MR: {e}")

    # Send Notifications
    try:
        scan = await db.scans.find_one({"_id": scan_id})
        if scan:
            project_data = await db.projects.find_one({"_id": scan["project_id"]})
            if project_data:
                project = Project(**project_data)

                # Always send analysis_completed notification
                await notification_service.notify_project_members(
                    project=project,
                    event_type="analysis_completed",
                    subject=f"Analysis Completed: {project.name}",
                    message=f"Scan {scan_id} completed.\nFound {len(aggregated_findings)} issues.\nResults:\n"
                    + "\n".join(results_summary),
                    db=db,
                )

                # Check for critical vulnerabilities and send vulnerability_found notification
                # Convert Finding objects to dicts for attribute access
                vulnerability_findings = [
                    f.model_dump()
                    for f in aggregated_findings
                    if f.type == "vulnerability"
                ]

                if vulnerability_findings:
                    # Extract KEV and high EPSS vulnerabilities
                    kev_vulns = []
                    high_epss_vulns = []
                    critical_vulns = []

                    for finding in vulnerability_findings:
                        details = finding.get("details", {})
                        vulns = details.get("vulnerabilities", [details])

                        for vuln in vulns:
                            vuln_info = {
                                "id": vuln.get("id", finding.get("id", "Unknown")),
                                "severity": vuln.get(
                                    "severity", finding.get("severity", "UNKNOWN")
                                ),
                                "package": finding.get("component", "Unknown"),
                                "version": finding.get("version", ""),
                                "in_kev": vuln.get("in_kev", False),
                                "epss_score": vuln.get("epss_score"),
                                "kev_due_date": vuln.get("kev_due_date"),
                                "kev_ransomware_use": vuln.get(
                                    "kev_ransomware_use", False
                                ),
                            }

                            if vuln.get("in_kev"):
                                kev_vulns.append(vuln_info)

                            if vuln.get("epss_score") and vuln.get("epss_score") >= 0.1:
                                high_epss_vulns.append(vuln_info)

                            if vuln.get("severity") in ["CRITICAL", "HIGH"] or vuln.get(
                                "in_kev"
                            ):
                                critical_vulns.append(vuln_info)

                    # Send vulnerability_found notification if there are KEV, high EPSS, or critical/high vulns
                    if kev_vulns or high_epss_vulns or critical_vulns:
                        # Sort and get top 10 most critical vulnerabilities for email
                        top_vulns = sorted(
                            critical_vulns,
                            key=lambda x: (
                                not x.get("in_kev", False),  # KEV first
                                -(x.get("epss_score") or 0),  # Then by EPSS
                                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                                    x.get("severity", "LOW"), 4
                                ),
                            ),
                        )[:10]

                        subject = "🔴 Security Alert: "
                        if kev_vulns:
                            subject += f"{len(kev_vulns)} KEV Vulnerabilities in {project.name}"
                        elif high_epss_vulns:
                            subject += f"High-Risk Vulnerabilities in {project.name}"
                        else:
                            subject += f"Critical Vulnerabilities in {project.name}"

                        message = f"Security scan detected critical vulnerabilities in {project.name}.\n\n"
                        if kev_vulns:
                            message += f"⚠️ {len(kev_vulns)} Known Exploited Vulnerabilities (CISA KEV)\n"
                        if high_epss_vulns:
                            message += f"🎯 {len(high_epss_vulns)} vulnerabilities with high exploitation probability (EPSS > 10%)\n"
                        message += f"\nTotal critical/high vulnerabilities: {len(critical_vulns)}\n"

                        # Add top vulnerabilities details
                        if top_vulns:
                            message += "\n📋 Top Priority Vulnerabilities:\n"
                            for i, vuln in enumerate(top_vulns, 1):
                                vuln_line = f"  {i}. {vuln['id']} ({vuln['severity']})"
                                vuln_line += f" - {vuln['package']}"
                                if vuln["version"]:
                                    vuln_line += f"@{vuln['version']}"
                                if vuln.get("in_kev"):
                                    vuln_line += " [KEV]"
                                if vuln.get("epss_score"):
                                    vuln_line += (
                                        f" [EPSS: {vuln['epss_score']*100:.1f}%]"
                                    )
                                message += vuln_line + "\n"

                        message += f"\nView full report: {scan_id}"

                        await notification_service.notify_project_members(
                            project=project,
                            event_type="vulnerability_found",
                            subject=subject,
                            message=message,
                            db=db,
                        )

                        logger.info(
                            f"Sent vulnerability_found notification for project {project.name}: "
                            f"{len(kev_vulns)} KEV, {len(high_epss_vulns)} high EPSS, {len(critical_vulns)} critical/high"
                        )
    except Exception as e:
        logger.error(f"Failed to send notifications: {e}")


def _build_epss_kev_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a summary of EPSS/KEV enrichment for raw data view.

    Args:
        findings: List of vulnerability findings that were enriched

    Returns:
        Summary dict with statistics and details
    """
    summary: Dict[str, Any] = {
        "total_vulnerabilities": len(findings),
        "epss_enriched": 0,
        "kev_matches": 0,
        "kev_ransomware": 0,
        "epss_scores": {
            "high": 0,  # > 0.1 (10%)
            "medium": 0,  # 0.01 - 0.1 (1-10%)
            "low": 0,  # < 0.01 (< 1%)
        },
        "exploit_maturity": {
            "weaponized": 0,
            "active": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
        },
        "avg_epss_score": None,
        "max_epss_score": None,
        "avg_risk_score": None,
        "max_risk_score": None,
        "kev_details": [],
        "high_risk_cves": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    epss_scores = []
    risk_scores = []

    for finding in findings:
        details = finding.get("details", {})

        # EPSS enrichment
        epss_score = details.get("epss_score")
        if epss_score is not None:
            summary["epss_enriched"] += 1
            epss_scores.append(epss_score)

            if epss_score > 0.1:
                summary["epss_scores"]["high"] += 1
            elif epss_score > 0.01:
                summary["epss_scores"]["medium"] += 1
            else:
                summary["epss_scores"]["low"] += 1

        # KEV enrichment
        if details.get("in_kev"):
            summary["kev_matches"] += 1
            kev_detail = {
                "cve": finding.get("finding_id") or finding.get("id", ""),
                "component": finding.get("component", ""),
                "due_date": details.get("kev_due_date"),
                "ransomware": details.get("kev_ransomware_use", False),
            }
            summary["kev_details"].append(kev_detail)

            if details.get("kev_ransomware_use"):
                summary["kev_ransomware"] += 1

        # Exploit maturity
        maturity = details.get("exploit_maturity", "unknown")
        if maturity in summary["exploit_maturity"]:
            summary["exploit_maturity"][maturity] += 1

        # Risk score
        risk_score = details.get("risk_score")
        if risk_score is not None:
            risk_scores.append(risk_score)

            # Track high-risk CVEs (risk_score > 70)
            if risk_score > 70:
                summary["high_risk_cves"].append(
                    {
                        "cve": finding.get("finding_id") or finding.get("id", ""),
                        "component": finding.get("component", ""),
                        "version": finding.get("version", ""),
                        "risk_score": round(risk_score, 1),
                        "epss_score": round(epss_score, 4) if epss_score else None,
                        "in_kev": details.get("in_kev", False),
                        "exploit_maturity": maturity,
                    }
                )

    # Calculate averages
    if epss_scores:
        summary["avg_epss_score"] = round(sum(epss_scores) / len(epss_scores), 4)
        summary["max_epss_score"] = round(max(epss_scores), 4)

    if risk_scores:
        summary["avg_risk_score"] = round(sum(risk_scores) / len(risk_scores), 1)
        summary["max_risk_score"] = round(max(risk_scores), 1)

    # Sort high-risk CVEs by risk score
    summary["high_risk_cves"].sort(key=lambda x: x["risk_score"], reverse=True)
    # Limit to top 20
    summary["high_risk_cves"] = summary["high_risk_cves"][:20]

    return summary


def _build_reachability_summary(
    findings: List[Dict[str, Any]], callgraph: Dict[str, Any], enriched_count: int
) -> Dict[str, Any]:
    """
    Build a summary of reachability analysis for raw data view.

    Args:
        findings: List of vulnerability findings that were analyzed
        callgraph: The callgraph document used for analysis
        enriched_count: Number of findings that were enriched

    Returns:
        Summary dict with statistics and details
    """
    summary: Dict[str, Any] = {
        "total_vulnerabilities": len(findings),
        "analyzed": enriched_count,
        "reachability_levels": {
            "confirmed": 0,  # Symbol-level match
            "likely": 0,  # Import-level match
            "unknown": 0,  # Could not determine
            "unreachable": 0,  # Confirmed not used
        },
        "callgraph_info": {
            "language": callgraph.get("language", "unknown"),
            "total_modules": len(callgraph.get("module_usage", {})),
            "total_imports": len(callgraph.get("import_map", {})),
            "generated_at": (
                callgraph.get("created_at", "").isoformat()
                if hasattr(callgraph.get("created_at", ""), "isoformat")
                else str(callgraph.get("created_at", ""))
            ),
        },
        "reachable_vulnerabilities": [],
        "unreachable_vulnerabilities": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    for finding in findings:
        reachable = finding.get("reachable")
        reachability_level = finding.get("reachability_level", "unknown")

        vuln_info = {
            "cve": finding.get("finding_id") or finding.get("id", ""),
            "component": finding.get("component", ""),
            "version": finding.get("version", ""),
            "severity": finding.get("severity", "unknown"),
            "reachability_level": reachability_level,
            "reachable_functions": finding.get("reachable_functions", [])[
                :5
            ],  # Limit to 5
        }

        if reachability_level in summary["reachability_levels"]:
            summary["reachability_levels"][reachability_level] += 1

        if reachable is True:
            summary["reachable_vulnerabilities"].append(vuln_info)
        elif reachable is False:
            summary["unreachable_vulnerabilities"].append(vuln_info)

    # Sort by severity (most severe first)
    summary["reachable_vulnerabilities"] = sort_by_severity(
        summary["reachable_vulnerabilities"], key="severity", reverse=True
    )
    summary["unreachable_vulnerabilities"] = sort_by_severity(
        summary["unreachable_vulnerabilities"], key="severity", reverse=True
    )

    # Limit lists to top 30
    summary["reachable_vulnerabilities"] = summary["reachable_vulnerabilities"][:30]
    summary["unreachable_vulnerabilities"] = summary["unreachable_vulnerabilities"][:30]

    return summary


async def _calculate_comprehensive_stats(db, scan_id: str) -> Stats:
    """
    Calculate comprehensive statistics including EPSS/KEV and Reachability data.

    This function calculates:
    1. Traditional severity-based counts (critical, high, medium, low, info)
    2. Threat intelligence stats (KEV count, EPSS scores, weaponized vulns)
    3. Reachability stats (reachable/unreachable counts)
    4. Prioritized counts (actionable vulns that are both exploitable AND reachable)
    5. Adjusted risk score incorporating all factors

    Args:
        db: Database connection
        scan_id: The scan ID to calculate stats for

    Returns:
        Stats object with all fields populated
    """
    # Comprehensive aggregation pipeline
    pipeline = [
        {"$match": {"scan_id": scan_id, "waived": False}},
        {
            "$project": {
                "severity": 1,
                "cvss_score": {"$ifNull": ["$details.cvss_score", None]},
                "epss_score": {"$ifNull": ["$details.epss_score", None]},
                "is_kev": {"$ifNull": ["$details.is_kev", False]},
                "kev_ransomware": {"$ifNull": ["$details.kev_ransomware", False]},
                "reachable": {"$ifNull": ["$reachable", None]},
                "reachability_level": {"$ifNull": ["$reachability_level", "unknown"]},
                "risk_score": {"$ifNull": ["$details.risk_score", None]},
                # Calculate default CVSS-based score if none provided
                "calculated_score": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$severity", "CRITICAL"]}, "then": 10.0},
                            {"case": {"$eq": ["$severity", "HIGH"]}, "then": 7.5},
                            {"case": {"$eq": ["$severity", "MEDIUM"]}, "then": 4.0},
                            {"case": {"$eq": ["$severity", "LOW"]}, "then": 1.0},
                        ],
                        "default": 0.0,
                    }
                },
            }
        },
        {
            "$group": {
                "_id": None,
                # Traditional severity counts
                "critical": {
                    "$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}
                },
                "high": {"$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}},
                "medium": {"$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}},
                "low": {"$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}},
                "info": {"$sum": {"$cond": [{"$eq": ["$severity", "INFO"]}, 1, 0]}},
                "unknown": {
                    "$sum": {"$cond": [{"$eq": ["$severity", "UNKNOWN"]}, 1, 0]}
                },
                "total": {"$sum": 1},
                # Traditional risk score sum
                "risk_score_sum": {
                    "$sum": {"$ifNull": ["$cvss_score", "$calculated_score"]}
                },
                # Adjusted risk scores (including enrichment data)
                "adjusted_risk_score_sum": {
                    "$sum": {"$ifNull": ["$risk_score", "$calculated_score"]}
                },
                # KEV statistics
                "kev_count": {"$sum": {"$cond": [{"$eq": ["$is_kev", True]}, 1, 0]}},
                "kev_ransomware_count": {
                    "$sum": {"$cond": [{"$eq": ["$kev_ransomware", True]}, 1, 0]}
                },
                # EPSS statistics
                "epss_scores": {
                    "$push": {
                        "$cond": [
                            {"$ne": ["$epss_score", None]},
                            "$epss_score",
                            "$$REMOVE",
                        ]
                    }
                },
                "high_epss_count": {
                    "$sum": {"$cond": [{"$gte": ["$epss_score", 0.1]}, 1, 0]}
                },
                "medium_epss_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$gte": ["$epss_score", 0.01]},
                                    {"$lt": ["$epss_score", 0.1]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Reachability statistics
                "reachability_analyzed": {
                    "$sum": {"$cond": [{"$ne": ["$reachable", None]}, 1, 0]}
                },
                "reachable_count": {
                    "$sum": {"$cond": [{"$eq": ["$reachable", True]}, 1, 0]}
                },
                "unreachable_count": {
                    "$sum": {"$cond": [{"$eq": ["$reachable", False]}, 1, 0]}
                },
                "confirmed_reachable": {
                    "$sum": {
                        "$cond": [{"$eq": ["$reachability_level", "confirmed"]}, 1, 0]
                    }
                },
                "likely_reachable": {
                    "$sum": {
                        "$cond": [{"$eq": ["$reachability_level", "likely"]}, 1, 0]
                    }
                },
                # Reachable by severity
                "reachable_critical": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$reachable", True]},
                                    {"$eq": ["$severity", "CRITICAL"]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "reachable_high": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$reachable", True]},
                                    {"$eq": ["$severity", "HIGH"]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Actionable: KEV or high EPSS AND reachable (or reachability unknown)
                "actionable_critical": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$severity", "CRITICAL"]},
                                    {
                                        "$or": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.1]},
                                        ]
                                    },
                                    {
                                        "$or": [
                                            {"$eq": ["$reachable", True]},
                                            {
                                                "$eq": ["$reachable", None]
                                            },  # Unknown = assume reachable
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "actionable_high": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$severity", "HIGH"]},
                                    {
                                        "$or": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.1]},
                                        ]
                                    },
                                    {
                                        "$or": [
                                            {"$eq": ["$reachable", True]},
                                            {"$eq": ["$reachable", None]},
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "actionable_total": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {
                                        "$or": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.1]},
                                        ]
                                    },
                                    {
                                        "$or": [
                                            {"$eq": ["$reachable", True]},
                                            {"$eq": ["$reachable", None]},
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Deprioritized: unreachable OR (low EPSS and not KEV)
                "deprioritized_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$or": [
                                    {"$eq": ["$reachable", False]},
                                    {
                                        "$and": [
                                            {"$ne": ["$is_kev", True]},
                                            {
                                                "$or": [
                                                    {"$eq": ["$epss_score", None]},
                                                    {"$lt": ["$epss_score", 0.01]},
                                                ]
                                            },
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Weaponized: KEV with ransomware or high EPSS with KEV
                "weaponized_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$or": [
                                    {"$eq": ["$kev_ransomware", True]},
                                    {
                                        "$and": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.5]},
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Active exploitation: KEV or very high EPSS
                "active_exploitation_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$or": [
                                    {"$eq": ["$is_kev", True]},
                                    {"$gte": ["$epss_score", 0.7]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
            }
        },
    ]

    stats_result = await db.findings.aggregate(pipeline).to_list(1)

    # Initialize stats with defaults
    stats = Stats()

    if stats_result:
        res = stats_result[0]

        # Traditional severity counts
        stats.critical = res.get("critical", 0)
        stats.high = res.get("high", 0)
        stats.medium = res.get("medium", 0)
        stats.low = res.get("low", 0)
        stats.info = res.get("info", 0)
        stats.unknown = res.get("unknown", 0)
        stats.risk_score = round(res.get("risk_score_sum", 0.0), 1)
        stats.adjusted_risk_score = round(res.get("adjusted_risk_score_sum", 0.0), 1)

        # Calculate EPSS statistics
        epss_scores = [s for s in res.get("epss_scores", []) if s is not None]
        avg_epss = sum(epss_scores) / len(epss_scores) if epss_scores else None
        max_epss = max(epss_scores) if epss_scores else None

        # Threat Intelligence Stats
        stats.threat_intel = ThreatIntelligenceStats(
            kev_count=res.get("kev_count", 0),
            kev_ransomware_count=res.get("kev_ransomware_count", 0),
            high_epss_count=res.get("high_epss_count", 0),
            medium_epss_count=res.get("medium_epss_count", 0),
            avg_epss_score=round(avg_epss, 4) if avg_epss else None,
            max_epss_score=round(max_epss, 4) if max_epss else None,
            weaponized_count=res.get("weaponized_count", 0),
            active_exploitation_count=res.get("active_exploitation_count", 0),
        )

        # Reachability Stats
        stats.reachability = ReachabilityStats(
            analyzed_count=res.get("reachability_analyzed", 0),
            reachable_count=res.get("reachable_count", 0),
            likely_reachable_count=res.get("likely_reachable", 0),
            unreachable_count=res.get("unreachable_count", 0),
            unknown_count=res.get("total", 0) - res.get("reachability_analyzed", 0),
            reachable_critical=res.get("reachable_critical", 0),
            reachable_high=res.get("reachable_high", 0),
        )

        # Prioritized Counts
        stats.prioritized = PrioritizedCounts(
            total=res.get("total", 0),
            critical=res.get("critical", 0),
            high=res.get("high", 0),
            medium=res.get("medium", 0),
            low=res.get("low", 0),
            actionable_critical=res.get("actionable_critical", 0),
            actionable_high=res.get("actionable_high", 0),
            actionable_total=res.get("actionable_total", 0),
            deprioritized_count=res.get("deprioritized_count", 0),
        )

    return stats
