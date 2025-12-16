import asyncio
import logging
from datetime import datetime, timedelta
from app.db.mongodb import get_database
from app.models.project import Project
from app.models.system import SystemSettings

logger = logging.getLogger(__name__)

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
                cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
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
                    
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                
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

async def housekeeping_loop():
    """
    Runs the housekeeping task every 24 hours.
    """
    while True:
        await run_housekeeping()
        # Sleep for 24 hours
        await asyncio.sleep(24 * 60 * 60)
