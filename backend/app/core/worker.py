import asyncio
import logging
from app.db.mongodb import get_database
from app.services.analysis import run_analysis
from app.core.config import settings

logger = logging.getLogger(__name__)

class AnalysisWorkerManager:
    def __init__(self, num_workers: int = 2):
        self.queue = asyncio.Queue()
        self.num_workers = num_workers
        self.workers = []

    async def start(self):
        """Starts the worker tasks and recovers pending jobs from DB."""
        logger.info(f"Starting {self.num_workers} analysis workers...")
        
        # Start workers first
        for i in range(self.num_workers):
            task = asyncio.create_task(self.worker(f"worker-{i}"))
            self.workers.append(task)
            
        # Recover pending jobs from DB
        try:
            db = await get_database()
            # Find scans that are pending
            cursor = db.scans.find({"status": "pending"})
            count = 0
            async for scan in cursor:
                await self.queue.put(str(scan["_id"]))
                count += 1
            
            if count > 0:
                logger.info(f"Recovered {count} pending scans from database.")
        except Exception as e:
            logger.error(f"Failed to recover pending jobs: {e}")

    async def stop(self):
        """Stops all worker tasks."""
        logger.info("Stopping analysis workers...")
        for task in self.workers:
            task.cancel()
        # Wait for tasks to cancel? usually not needed in shutdown

    async def add_job(self, scan_id: str):
        """Adds a new scan job to the queue."""
        await self.queue.put(scan_id)
        logger.info(f"Job {scan_id} added to queue. Queue size: {self.queue.qsize()}")

    async def worker(self, name: str):
        """Worker loop that processes jobs from the queue."""
        logger.info(f"Worker {name} started")
        while True:
            try:
                scan_id = await self.queue.get()
                logger.info(f"Worker {name} picked up scan {scan_id}")
                
                db = await get_database()
                
                # Atomic Claim: Try to set status to 'processing' ONLY IF it is currently 'pending'
                # This prevents multiple workers (across different pods) from processing the same scan.
                scan = await db.scans.find_one_and_update(
                    {"_id": scan_id, "status": "pending"},
                    {"$set": {"status": "processing", "worker_id": name}},
                    return_document=True
                )
                
                if not scan:
                    # If scan is None, it means either:
                    # 1. It doesn't exist (deleted)
                    # 2. It's already being processed by another worker (status != pending)
                    logger.info(f"Scan {scan_id} already claimed or not found. Skipping.")
                    self.queue.task_done()
                    continue
                
                # Fetch project config (for active analyzers)
                project = await db.projects.find_one({"_id": scan["project_id"]})
                if not project:
                    logger.error(f"Project for scan {scan_id} not found, skipping.")
                    await db.scans.update_one(
                        {"_id": scan_id},
                        {"$set": {"status": "failed", "error": "Project not found"}}
                    )
                    self.queue.task_done()
                    continue

                try:
                    # Run the actual analysis
                    await run_analysis(
                        scan_id=scan_id,
                        sbom=scan["sbom"],
                        active_analyzers=project.get("active_analyzers", []),
                        db=db
                    )
                    # Note: run_analysis should ideally update status to 'completed'
                    # If it doesn't, we should do it here. Assuming run_analysis handles it for now based on previous code.
                    
                except Exception as e:
                    logger.error(f"Error processing scan {scan_id}: {e}")
                    await db.scans.update_one(
                        {"_id": scan_id},
                        {"$set": {"status": "failed", "error": str(e)}}
                    )

                self.queue.task_done()
                logger.info(f"Worker {name} finished scan {scan_id}")
                
            except asyncio.CancelledError:
                logger.info(f"Worker {name} stopped")
                break
            except Exception as e:
                logger.error(f"Worker {name} crashed: {e}")
                await asyncio.sleep(1) # Prevent tight loop if something is really broken

# Global instance
worker_manager = AnalysisWorkerManager(num_workers=settings.WORKER_COUNT)
