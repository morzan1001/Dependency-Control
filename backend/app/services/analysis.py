from typing import Dict, Any, List
from datetime import datetime
import uuid
import asyncio
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
from app.services.aggregator import ResultAggregator

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

async def process_analyzer(analyzer_name: str, analyzer: Analyzer, sbom: Dict[str, Any], scan_id: str, db, aggregator: ResultAggregator) -> str:
    try:
        result = await analyzer.analyze(sbom)
        
        # Store raw result
        await db.analysis_results.insert_one({
            "_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "analyzer_name": analyzer_name,
            "result": result,
            "created_at": datetime.utcnow()
        })
        
        # Aggregate result
        aggregator.aggregate(analyzer_name, result)
        
        print(f"Analysis {analyzer_name} completed for {scan_id}")
        return f"{analyzer_name}: Success"
    except Exception as e:
        print(f"Analysis {analyzer_name} failed: {e}")
        return f"{analyzer_name}: Failed"

async def run_analysis(scan_id: str, sbom: Dict[str, Any], active_analyzers: List[str], db):
    """
    Orchestrates the analysis process for a given SBOM scan.
    
    1. Iterates through requested analyzers (e.g., trivy, grype, osv).
    2. Executes each analyzer asynchronously.
    3. Stores raw results in the 'analysis_results' collection.
    4. Aggregates findings from all scanners into a unified format using ResultAggregator.
    5. Updates the 'scans' document with the aggregated summary.
    6. Sends notifications (Email/Slack) to project members.
    """
    print(f"Starting analysis for scan {scan_id}")
    aggregator = ResultAggregator()
    
    tasks = []
    for analyzer_name in active_analyzers:
        if analyzer_name in analyzers:
            analyzer = analyzers[analyzer_name]
            tasks.append(process_analyzer(analyzer_name, analyzer, sbom, scan_id, db, aggregator))
            
    results_summary = await asyncio.gather(*tasks)

    # Save aggregated findings to the scan document
    aggregated_findings = aggregator.get_findings()
    
    # Fetch scan to get project_id
    scan_doc = await db.scans.find_one({"_id": scan_id})
    project_id = scan_doc.get("project_id") if scan_doc else None

    # Fetch waivers
    waivers = []
    if project_id:
        waivers = await db.waivers.find({"project_id": project_id}).to_list(length=None)

    # Pre-process waivers for O(1) lookup
    # We group waivers by finding_id and package_name to reduce the search space
    active_waivers = [w for w in waivers if not (w.get("expiration_date") and w["expiration_date"] < datetime.utcnow())]
    
    waivers_by_id = {}
    waivers_by_component = {}
    waivers_generic = []

    for w in active_waivers:
        if w.get("finding_id"):
            waivers_by_id.setdefault(w["finding_id"], []).append(w)
        elif w.get("package_name"):
            waivers_by_component.setdefault(w["package_name"], []).append(w)
        else:
            waivers_generic.append(w)

    # Apply waivers
    ignored_count = 0
    for finding in aggregated_findings:
        is_waived = False
        waiver_reason = None
        
        # Determine candidates: specific ID matches + component matches + generic waivers
        candidates = (
            waivers_by_id.get(finding.get("id"), []) + 
            waivers_by_component.get(finding.get("component"), []) + 
            waivers_generic
        )
        
        for waiver in candidates:
            # Check criteria (expiration already checked)
            match = True
            
            # Note: finding_id and package_name are implicitly checked by the lookup strategy 
            # for the respective lists, but we check everything to be safe and handle the generic/mixed cases correctly.
            
            if waiver.get("finding_id") and waiver["finding_id"] != finding.get("id"):
                match = False
            if match and waiver.get("package_name") and waiver["package_name"] != finding.get("component"):
                match = False
            if match and waiver.get("package_version") and waiver["package_version"] != finding.get("version"):
                match = False
            if match and waiver.get("finding_type") and waiver["finding_type"] != finding.get("type"):
                match = False
                
            if match:
                is_waived = True
                waiver_reason = waiver.get("reason")
                break
        
        if is_waived:
            finding["waived"] = True
            finding["waiver_reason"] = waiver_reason
            ignored_count += 1
        else:
            finding["waived"] = False

    # Calculate stats (excluding waived)
    stats = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
        "risk_score": 0.0
    }
    
    for finding in aggregated_findings:
        if finding.get("waived"):
            continue

        severity = finding.get("severity", "UNKNOWN").lower()
        if severity in stats:
            stats[severity] += 1
        else:
            stats["unknown"] += 1

        # Calculate Risk Score
        # Prefer CVSS Score if available, otherwise map from Severity
        score = finding.get("details", {}).get("cvss_score")
        
        if score is None:
            sev_upper = severity.upper()
            if sev_upper == "CRITICAL": score = 10.0
            elif sev_upper == "HIGH": score = 7.5
            elif sev_upper == "MEDIUM": score = 4.0
            elif sev_upper == "LOW": score = 1.0
            else: score = 0.0
        
        stats["risk_score"] += float(score)

    # Round risk score
    stats["risk_score"] = round(stats["risk_score"], 1)

    await db.scans.update_one(
        {"_id": scan_id},
        {"$set": {
            "status": "completed", 
            "findings_summary": aggregated_findings,
            "findings_count": len(aggregated_findings),
            "ignored_count": ignored_count,
            "stats": stats,
            "completed_at": datetime.utcnow()
        }}
    )
    
    # Update Project stats
    scan = await db.scans.find_one({"_id": scan_id})
    if scan:
        await db.projects.update_one(
            {"_id": scan["project_id"]},
            {"$set": {
                "stats": stats, 
                "last_scan_at": datetime.utcnow(),
                "latest_scan_id": scan_id
            }}
        )

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
        print(f"Failed to send notifications: {e}")

