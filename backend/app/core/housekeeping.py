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
        
        # Iterate over all projects
        async for project_data in db.projects.find({}):
            try:
                project = Project(**project_data)
                
                # Determine retention days
                if system_settings.retention_mode == "global":
                    retention_days = system_settings.global_retention_days
                else:
                    retention_days = project.retention_days
                
                # If retention is 0 or less, it means "keep forever"
                if retention_days <= 0:
                    continue
                    
                cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
                
                # Find scans older than cutoff_date to get their IDs
                cursor = db.scans.find(
                    {
                        "project_id": project.id,
                        "created_at": {"$lt": cutoff_date}
                    },
                    {"_id": 1}
                )
                
                scan_ids_to_delete = []
                async for scan in cursor:
                    scan_ids_to_delete.append(str(scan["_id"]))
                
                if scan_ids_to_delete:
                    # Delete Analysis Results first
                    ar_delete_result = await db.analysis_results.delete_many({
                        "scan_id": {"$in": scan_ids_to_delete}
                    })
                    
                    # Delete Scans
                    scan_delete_result = await db.scans.delete_many({
                        "_id": {"$in": scan_ids_to_delete}
                    })
                    
                    logger.info(f"Project {project.id}: Deleted {scan_delete_result.deleted_count} old scans and {ar_delete_result.deleted_count} analysis results.")
                    
            except Exception as e:
                logger.error(f"Error performing housekeeping for project {project_data.get('_id')}: {e}")
                
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
