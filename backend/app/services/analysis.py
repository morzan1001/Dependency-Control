from typing import Dict, Any, List
from datetime import datetime
import uuid
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
    results_summary = []
    aggregator = ResultAggregator()
    
    for analyzer_name in active_analyzers:
        if analyzer_name in analyzers:
            analyzer = analyzers[analyzer_name]
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
                results_summary.append(f"{analyzer_name}: Success")
            except Exception as e:
                print(f"Analysis {analyzer_name} failed: {e}")
                results_summary.append(f"{analyzer_name}: Failed")

    # Save aggregated findings to the scan document
    aggregated_findings = aggregator.get_findings()
    
    # Calculate stats
    stats = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0
    }
    
    for finding in aggregated_findings:
        severity = finding.get("severity", "UNKNOWN").lower()
        if severity in stats:
            stats[severity] += 1
        else:
            stats["unknown"] += 1

    await db.scans.update_one(
        {"_id": scan_id},
        {"$set": {
            "status": "completed", 
            "findings_summary": aggregated_findings,
            "findings_count": len(aggregated_findings),
            "stats": stats,
            "completed_at": datetime.utcnow()
        }}
    )
    
    # Update Project stats
    scan = await db.scans.find_one({"_id": scan_id})
    if scan:
        await db.projects.update_one(
            {"_id": scan["project_id"]},
            {"$set": {"stats": stats, "last_scan_at": datetime.utcnow()}}
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

