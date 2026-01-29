import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional

from app.core.config import settings
from app.core.housekeeping import housekeeping_loop, stale_scan_loop
from app.db.mongodb import get_database
from app.services.analysis import run_analysis
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

# Import metrics for worker monitoring
try:
    from app.core.metrics import (
        worker_active_count,
        worker_job_duration_seconds,
        worker_jobs_processed_total,
        worker_queue_size,
    )
except ImportError:
    # Fallback if metrics module is not available yet
    worker_queue_size = None
    worker_active_count = None
    worker_jobs_processed_total = None
    worker_job_duration_seconds = None


class AnalysisWorkerManager:
    """Manages analysis worker tasks and job queue."""

    def __init__(self, num_workers: int = 2) -> None:
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.num_workers = num_workers
        self.workers: List[asyncio.Task[None]] = []
        self.housekeeping_task: Optional[asyncio.Task[None]] = None
        self.stale_scan_task: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        """Starts the worker tasks and recovers pending jobs from DB."""
        logger.info(f"Starting {self.num_workers} analysis workers...")

        # Start workers first
        for i in range(self.num_workers):
            task = asyncio.create_task(self.worker(f"worker-{i}"))
            self.workers.append(task)

        # Update worker count metric
        if worker_active_count:
            worker_active_count.set(self.num_workers)

        # Start housekeeping task (slow: every 5 minutes)
        self.housekeeping_task = asyncio.create_task(housekeeping_loop(self))
        logger.info("Housekeeping task started.")

        # Start stale scan loop (fast: every 10 seconds)
        self.stale_scan_task = asyncio.create_task(stale_scan_loop(self))
        logger.info("Stale scan loop started.")

        # Recover pending jobs from DB
        try:
            db = await get_database()
            # Find scans that are pending
            # Optimization: Only fetch _id, don't load full SBOMs
            # Limit recovery to prevent queue overload in case of many pending scans
            recovery_limit = 1000  # Configurable limit
            cursor = (
                db.scans.find({"status": "pending"}, {"_id": 1})
                .sort("created_at", 1)
                .limit(recovery_limit)
            )

            count = 0
            async for scan in cursor:
                await self.queue.put(str(scan["_id"]))
                count += 1

            if count > 0:
                logger.info(f"Recovered {count} pending scans from database.")
                if count >= recovery_limit:
                    logger.warning(
                        f"Recovery limit ({recovery_limit}) reached. "
                        f"Some pending scans may not have been queued. "
                        f"They will be picked up by housekeeping."
                    )
        except Exception as e:
            logger.error(f"Failed to recover pending jobs: {e}")

    async def stop(self) -> None:
        """Stops all worker tasks."""
        logger.info("Stopping analysis workers...")
        for task in self.workers:
            task.cancel()

        if self.housekeeping_task:
            self.housekeeping_task.cancel()
            logger.info("Housekeeping task stopped.")

        if self.stale_scan_task:
            self.stale_scan_task.cancel()
            logger.info("Stale scan loop stopped.")

    async def add_job(self, scan_id: str) -> None:
        """Adds a new scan job to the queue."""
        await self.queue.put(scan_id)
        queue_size = self.queue.qsize()
        logger.info(f"Job {scan_id} added to queue. Queue size: {queue_size}")

        # Update queue size metric
        if worker_queue_size:
            worker_queue_size.set(queue_size)

    async def worker(self, name: str) -> None:
        """Worker loop that processes jobs from the queue."""
        logger.info(f"Worker {name} started")
        while True:
            try:
                scan_id = await self.queue.get()
                logger.info(f"Worker {name} picked up scan {scan_id}")

                # Update queue size metric
                if worker_queue_size:
                    worker_queue_size.set(self.queue.qsize())

                # Track job processing time
                job_start_time = time.time()

                db = await get_database()

                # Atomic Claim: Try to set status to 'processing' ONLY IF it is currently 'pending'
                # This prevents multiple workers (across different pods) from processing the same scan.
                scan = await db.scans.find_one_and_update(
                    {"_id": scan_id, "status": "pending"},
                    {
                        "$set": {
                            "status": "processing",
                            "worker_id": name,
                            "analysis_started_at": datetime.now(timezone.utc),
                        }
                    },
                    return_document=True,
                )

                if not scan:
                    # If scan is None, it means either:
                    # 1. It doesn't exist (deleted)
                    # 2. It's already being processed by another worker (status != pending)
                    logger.info(
                        f"Scan {scan_id} already claimed or not found. Skipping."
                    )
                    self.queue.task_done()
                    continue

                # Fetch project config (for active analyzers)
                project = await db.projects.find_one({"_id": scan["project_id"]})
                if not project:
                    logger.error(f"Project for scan {scan_id} not found, skipping.")
                    await db.scans.update_one(
                        {"_id": scan_id},
                        {"$set": {"status": "failed", "error": "Project not found"}},
                    )
                    self.queue.task_done()
                    continue

                try:
                    # Prepare SBOMs list (pass refs list, let run_analysis handle loading)
                    sbom_refs = scan.get("sbom_refs", [])

                    # Run the actual analysis
                    success = await run_analysis(
                        scan_id=scan_id,
                        sboms=sbom_refs,
                        active_analyzers=project.get("active_analyzers", []),
                        db=db,
                    )

                    if not success:
                        # Race condition detected - check retry count before re-queueing
                        retry_count = scan.get("retry_count", 0)
                        max_retries = 5  # Configurable limit

                        if retry_count >= max_retries:
                            logger.error(
                                f"Scan {scan_id} failed after {retry_count} retries due to persistent race conditions. Marking as failed."
                            )
                            await db.scans.update_one(
                                {"_id": scan_id},
                                {
                                    "$set": {
                                        "status": "failed",
                                        "error": f"Analysis failed after {retry_count} retry attempts due to race conditions.",
                                    }
                                },
                            )
                            self.queue.task_done()
                            continue

                        logger.info(
                            f"Scan {scan_id} requires re-processing (race condition). "
                            f"Re-queueing (attempt {retry_count + 1}/{max_retries})."
                        )
                        # Increment retry counter
                        await db.scans.update_one(
                            {"_id": scan_id}, {"$inc": {"retry_count": 1}}
                        )
                        await self.queue.put(scan_id)
                        self.queue.task_done()
                        continue

                    # run_analysis updates the status to 'completed' upon success.
                    # Track successful job processing
                    if worker_jobs_processed_total:
                        worker_jobs_processed_total.labels(status="success").inc()
                    if worker_job_duration_seconds:
                        job_duration = time.time() - job_start_time
                        worker_job_duration_seconds.observe(job_duration)

                except Exception as e:
                    logger.error(f"Error processing scan {scan_id}: {e}")
                    await db.scans.update_one(
                        {"_id": scan_id},
                        {"$set": {"status": "failed", "error": str(e)}},
                    )
                    # Track failed job processing
                    if worker_jobs_processed_total:
                        worker_jobs_processed_total.labels(status="failed").inc()

                    # Trigger analysis_failed webhook
                    try:
                        project = await db.projects.find_one(
                            {"_id": scan.get("project_id")}
                        )
                        if project:
                            await webhook_service.trigger_analysis_failed(
                                db=db,
                                scan_id=scan_id,
                                project_id=str(project["_id"]),
                                project_name=project.get("name", "Unknown"),
                                error_message=str(e),
                            )
                    except Exception as webhook_err:
                        logger.error(
                            f"Failed to trigger analysis_failed webhook: {webhook_err}"
                        )

                self.queue.task_done()
                logger.info(f"Worker {name} finished scan {scan_id}")

            except asyncio.CancelledError:
                logger.info(f"Worker {name} stopped")
                break
            except Exception as e:
                logger.error(f"Worker {name} crashed: {e}")
                await asyncio.sleep(
                    1
                )  # Prevent tight loop if something is really broken


# Type alias for external use
WorkerManager = AnalysisWorkerManager

# Global instance
worker_manager = AnalysisWorkerManager(num_workers=settings.WORKER_COUNT)
