import asyncio
import logging
from datetime import datetime, timedelta, timezone
from app.db.mongodb import get_database
from app.models.project import Project, Scan
from app.models.system import SystemSettings

logger = logging.getLogger(__name__)

async def check_scheduled_rescans(worker_manager):
    """
    Checks for projects that need a periodic re-scan.
    """
    if not worker_manager:
        return

    logger.info("Checking for scheduled re-scans...")
    try:
        db = await get_database()
        
        # Get System Settings
        settings_data = await db.system_settings.find_one({"_id": "current"})
        system_settings = SystemSettings(**settings_data) if settings_data else SystemSettings()
        
        # Iterate over all projects
        # Optimization: We could filter in the query, but logic is complex due to "None" overrides
        async for project_data in db.projects.find({}):
            try:
                project = Project(**project_data)
                
                # Determine if enabled
                enabled = project.rescan_enabled
                if enabled is None:
                    enabled = system_settings.global_rescan_enabled
                
                if not enabled:
                    continue
                    
                # Determine interval
                interval_hours = project.rescan_interval
                if interval_hours is None:
                    interval_hours = system_settings.global_rescan_interval
                    
                if interval_hours <= 0:
                    continue
                    
                # Check last scan time
                last_scan = project.last_scan_at
                if not last_scan:
                    # If never scanned, we can't re-scan
                    continue
                    
                # Check if time to scan
                next_scan_due = last_scan + timedelta(hours=interval_hours)
                if datetime.now(timezone.utc) < next_scan_due:
                    continue
                    
                # Check if there is already a pending/processing scan for this project
                active_scan = await db.scans.find_one({
                    "project_id": project.id,
                    "status": {"$in": ["pending", "processing"]}
                })
                
                if active_scan:
                    # logger.info(f"Project {project.name} due for re-scan, but has active scan {active_scan['_id']}. Skipping.")
                    continue
                    
                # Find the latest SUCCESSFUL scan with SBOMs
                # We need SBOMs to re-scan
                latest_valid_scan = await db.scans.find_one(
                    {
                        "project_id": project.id,
                        "status": "completed",
                        "sbom_refs": {"$exists": True, "$ne": []}
                    },
                    sort=[("created_at", -1)]
                )
                
                if not latest_valid_scan:
                    logger.info(f"Project {project.name} due for re-scan, but no valid previous scan with SBOMs found.")
                    continue
                    
                # Create Re-Scan
                logger.info(f"Triggering re-scan for project {project.name} (Last scan: {last_scan})")
                
                new_scan = Scan(
                    project_id=project.id,
                    branch=latest_valid_scan.get("branch", "unknown"),
                    commit_hash=latest_valid_scan.get("commit_hash"),
                    pipeline_id=None, # Important: Don't collide with ingest
                    pipeline_iid=latest_valid_scan.get("pipeline_iid"),
                    project_url=latest_valid_scan.get("project_url"),
                    pipeline_url=latest_valid_scan.get("pipeline_url"),
                    job_id=latest_valid_scan.get("job_id"),
                    job_started_at=latest_valid_scan.get("job_started_at"),
                    project_name=latest_valid_scan.get("project_name"),
                    commit_message=latest_valid_scan.get("commit_message"),
                    commit_tag=latest_valid_scan.get("commit_tag"),
                    
                    sbom_refs=latest_valid_scan.get("sbom_refs", []),
                    
                    status="pending",
                    created_at=datetime.now(timezone.utc),
                    is_rescan=True,
                    original_scan_id=str(latest_valid_scan["_id"])
                )
                
                await db.scans.insert_one(new_scan.dict(by_alias=True))
                
                # Update original scan to point to this new pending rescan (so UI can show "Scanning...")
                await db.scans.update_one(
                    {"_id": str(latest_valid_scan["_id"])},
                    {"$set": {
                        "status": "pending", # Set original scan to pending to indicate activity
                        "latest_rescan_id": new_scan.id
                    }}
                )

                await worker_manager.add_job(new_scan.id)
            except Exception as e:
                logger.error(f"Error processing project {project_data.get('name')}: {e}")

    except Exception as e:
        logger.error(f"Scheduled re-scan check failed: {e}")

async def run_housekeeping():
    """
    Periodically cleans up old scan data based on project retention settings.
    """
    logger.info("Starting housekeeping task...")
    
    try:
        db = await get_database()
        
        # Get System Settings
        settings_data = await db.system_settings.find_one({"_id": "current"})
        system_settings = SystemSettings(**settings_data) if settings_data else SystemSettings()
        
        # Determine retention strategy
        if system_settings.retention_mode == "global":
            retention_days = system_settings.global_retention_days
            if retention_days > 0:
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
                logger.info(f"Running global housekeeping. Deleting scans older than {cutoff_date}")
                
                # Find old scans
                cursor = db.scans.find(
                    {"created_at": {"$lt": cutoff_date}},
                    {"_id": 1}
                )
                
                scan_ids_to_delete = [str(doc["_id"]) async for doc in cursor]
                
                if scan_ids_to_delete:
                    # Bulk delete
                    await db.analysis_results.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    await db.findings.delete_many({"scan_id": {"$in": scan_ids_to_delete}}) # Also delete findings
                    await db.dependencies.delete_many({"scan_id": {"$in": scan_ids_to_delete}}) # Also delete dependencies
                    result = await db.scans.delete_many({"_id": {"$in": scan_ids_to_delete}})
                    logger.info(f"Global housekeeping: Deleted {result.deleted_count} scans.")
                    
        else:
            # Project-specific retention (Optimized: Group by retention_days)
            logger.info("Running project-specific housekeeping...")
            
            # Group projects by retention_days to minimize DB queries
            pipeline = [
                {"$match": {"retention_days": {"$gt": 0}}}, # Ignore keep-forever
                {"$group": {
                    "_id": "$retention_days",
                    "project_ids": {"$push": "$_id"}
                }}
            ]
            
            async for group in db.projects.aggregate(pipeline):
                days = group["_id"]
                project_ids = group["project_ids"]
                
                if not days or days <= 0: 
                    continue
                    
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
                
                # Find scans for this batch of projects that are too old
                cursor = db.scans.find(
                    {
                        "project_id": {"$in": project_ids},
                        "created_at": {"$lt": cutoff_date}
                    },
                    {"_id": 1}
                )
                
                scan_ids_to_delete = [str(doc["_id"]) async for doc in cursor]
                
                if scan_ids_to_delete:
                    # Bulk delete for this retention group
                    await db.analysis_results.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    await db.findings.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    await db.dependencies.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    result = await db.scans.delete_many({"_id": {"$in": scan_ids_to_delete}})
                    
                    logger.info(f"Retention {days} days: Deleted {result.deleted_count} scans from {len(project_ids)} projects.")

    except Exception as e:
        logger.error(f"Housekeeping task failed: {e}")

async def recover_stuck_scans(worker_manager=None):
    """
    Identifies scans that have been stuck in 'processing' state for too long
    and resets them to 'pending' or marks them as 'failed'.
    """
    logger.info("Running stuck scan recovery...")
    try:
        db = await get_database()
        # Timeout threshold: 30 minutes
        timeout_threshold = datetime.now(timezone.utc) - timedelta(minutes=30)
        max_retries = 3
        
        # Find stuck scans
        cursor = db.scans.find({
            "status": "processing",
            "$or": [
                {"analysis_started_at": {"$lt": timeout_threshold}},
                {"analysis_started_at": {"$exists": False}},
                {"analysis_started_at": None}
            ]
        })
        
        async for scan in cursor:
            scan_id = scan["_id"]
            retry_count = scan.get("retry_count", 0)
            
            if retry_count < max_retries:
                logger.warning(f"Scan {scan_id} stuck in processing. Resetting to pending (Retry {retry_count + 1}/{max_retries}).")
                result = await db.scans.update_one(
                    {
                        "_id": scan_id,
                        "status": "processing"
                    },
                    {
                        "$set": {
                            "status": "pending",
                            "worker_id": None,
                            "analysis_started_at": None
                        },
                        "$inc": {"retry_count": 1}
                    }
                )
                
                # Re-queue the job if worker_manager is available and we successfully reset it
                if worker_manager and result.modified_count > 0:
                    await worker_manager.add_job(str(scan_id))
                    
            else:
                logger.error(f"Scan {scan_id} failed after {max_retries} retries.")
                await db.scans.update_one(
                    {
                        "_id": scan_id,
                        "status": "processing"
                    },
                    {
                        "$set": {
                            "status": "failed",
                            "error": "Analysis timed out or worker crashed multiple times."
                        }
                    }
                )

    except Exception as e:
        logger.error(f"Stuck scan recovery failed: {e}")

async def housekeeping_loop(worker_manager=None):
    """
    Runs the housekeeping tasks.
    - Stuck scan recovery: Every 5 minutes
    - Data retention cleanup: Every 24 hours
    """
    last_retention_run = datetime.min
    
    while True:
        # Run stuck scan recovery
        await recover_stuck_scans(worker_manager)
        
        # Run scheduled re-scans
        await check_scheduled_rescans(worker_manager)
        
        # Run retention cleanup if 24 hours passed
        if (datetime.now(timezone.utc) - last_retention_run) > timedelta(hours=24):
            await run_housekeeping()
            last_retention_run = datetime.now(timezone.utc)
            
        # Sleep for 5 minutes
        await asyncio.sleep(5 * 60)
