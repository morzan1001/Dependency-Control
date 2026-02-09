import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import List, Optional, Set

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

# Default graceful shutdown timeout (should be less than K8s terminationGracePeriodSeconds)
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 25


class AnalysisWorkerManager:
    """Manages analysis worker tasks and job queue."""

    def __init__(self, num_workers: int = 2) -> None:
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.num_workers = num_workers
        self.workers: List[asyncio.Task[None]] = []
        self.housekeeping_task: Optional[asyncio.Task[None]] = None
        self.stale_scan_task: Optional[asyncio.Task[None]] = None
        # Graceful shutdown state
        self._shutting_down: bool = False
        self._active_scans: Set[str] = set()  # Currently processing scan IDs
        self._shutdown_event: asyncio.Event = asyncio.Event()

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
            cursor = db.scans.find({"status": "pending"}, {"_id": 1}).sort("created_at", 1).limit(recovery_limit)

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

    async def stop(self, timeout: Optional[float] = None) -> None:
        """
        Gracefully stops all worker tasks.

        1. Signals shutdown (stops accepting new jobs)
        2. Stops housekeeping tasks immediately
        3. Waits for workers to finish current scan (with timeout)
        4. Returns unclaimed queue items to DB as pending (they already are)
        5. Force-cancels workers if timeout exceeded

        Args:
            timeout: Max seconds to wait for graceful shutdown.
                     Default: DEFAULT_SHUTDOWN_TIMEOUT_SECONDS
        """
        if timeout is None:
            timeout = DEFAULT_SHUTDOWN_TIMEOUT_SECONDS

        logger.info(
            f"Initiating graceful shutdown (timeout: {timeout}s, "
            f"active scans: {len(self._active_scans)}, "
            f"queue size: {self.queue.qsize()})..."
        )

        # 1. Signal shutdown - stop accepting new jobs
        self._shutting_down = True
        self._shutdown_event.set()

        # 2. Stop housekeeping tasks immediately (they're not critical)
        if self.housekeeping_task:
            self.housekeeping_task.cancel()
            logger.info("Housekeeping task cancelled.")

        if self.stale_scan_task:
            self.stale_scan_task.cancel()
            logger.info("Stale scan loop cancelled.")

        # 3. Log queue items that will be left behind (they're still pending in DB)
        queue_size = self.queue.qsize()
        if queue_size > 0:
            logger.info(
                f"Leaving {queue_size} items in queue - they remain 'pending' in DB "
                f"and will be recovered by other pods or on restart."
            )
            # Drain the queue to prevent memory leak (items are already in DB as pending)
            while not self.queue.empty():
                try:
                    self.queue.get_nowait()
                    self.queue.task_done()
                except asyncio.QueueEmpty:
                    break

        # 4. Wait for active scans to complete (with timeout)
        if self._active_scans:
            logger.info(f"Waiting for {len(self._active_scans)} active scan(s) to complete: {self._active_scans}")
            try:
                # Wait for workers to finish their current work
                await asyncio.wait_for(self._wait_for_active_scans(), timeout=timeout)
                logger.info("All active scans completed gracefully.")
            except asyncio.TimeoutError:
                logger.warning(
                    f"Shutdown timeout ({timeout}s) exceeded. "
                    f"Force-cancelling {len(self._active_scans)} active scan(s): "
                    f"{self._active_scans}. "
                    f"These will be recovered by housekeeping as stuck scans."
                )

        # 5. Cancel all worker tasks (they should have exited by now or will be force-stopped)
        for task in self.workers:
            if not task.done():
                task.cancel()

        # Wait for tasks to be cancelled
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)

        # Update metrics
        if worker_active_count:
            worker_active_count.set(0)
        if worker_queue_size:
            worker_queue_size.set(0)

        logger.info("Graceful shutdown complete.")

    async def _wait_for_active_scans(self) -> None:
        """Wait until all active scans are completed."""
        while self._active_scans:
            await asyncio.sleep(0.5)

    def is_shutting_down(self) -> bool:
        """Check if the worker manager is shutting down."""
        return self._shutting_down

    async def add_job(self, scan_id: str) -> bool:
        """
        Adds a new scan job to the queue.

        Returns:
            True if job was added, False if rejected (shutting down)
        """
        if self._shutting_down:
            logger.warning(
                f"Job {scan_id} rejected - worker manager is shutting down. "
                f"Scan remains 'pending' in DB and will be processed by another pod."
            )
            return False

        await self.queue.put(scan_id)
        queue_size = self.queue.qsize()
        logger.info(f"Job {scan_id} added to queue. Queue size: {queue_size}")

        # Update queue size metric
        if worker_queue_size:
            worker_queue_size.set(queue_size)

        return True

    async def worker(self, name: str) -> None:
        """Worker loop that processes jobs from the queue."""
        hostname = os.getenv("HOSTNAME", "unknown")
        worker_id = f"{hostname}/{name}"
        logger.info(f"Worker {worker_id} started")

        while True:
            try:
                # Check if we're shutting down and queue is empty
                if self._shutting_down and self.queue.empty():
                    logger.info(f"Worker {worker_id} exiting - shutdown signaled and queue empty")
                    break

                # Use wait_for with timeout to check shutdown periodically
                try:
                    scan_id = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    # No item in queue, check shutdown and continue
                    if self._shutting_down:
                        logger.info(f"Worker {worker_id} exiting - shutdown signaled")
                        break
                    continue

                # If shutting down, put the item back and exit
                if self._shutting_down:
                    # Don't process new items during shutdown - let other pods handle them
                    logger.info(f"Worker {worker_id} returning scan {scan_id} to queue - shutting down")
                    # Item stays in DB as 'pending', just mark as done
                    self.queue.task_done()
                    break

                logger.info(f"Worker {worker_id} picked up scan {scan_id}")

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
                            "worker_id": worker_id,  # Full hostname/worker format
                            "analysis_started_at": datetime.now(timezone.utc),
                        }
                    },
                    return_document=True,
                )

                if not scan:
                    # If scan is None, it means either:
                    # 1. It doesn't exist (deleted)
                    # 2. It's already being processed by another worker (status != pending)
                    logger.info(f"Scan {scan_id} already claimed or not found. Skipping.")
                    self.queue.task_done()
                    continue

                # Track this scan as actively processing (for graceful shutdown)
                self._active_scans.add(scan_id)

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
                        await db.scans.update_one({"_id": scan_id}, {"$inc": {"retry_count": 1}})
                        # Remove from active scans before re-queueing
                        self._active_scans.discard(scan_id)
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
                        project = await db.projects.find_one({"_id": scan.get("project_id")})
                        if project:
                            await webhook_service.trigger_analysis_failed(
                                db=db,
                                scan_id=scan_id,
                                project_id=str(project["_id"]),
                                project_name=project.get("name", "Unknown"),
                                error_message=str(e),
                            )
                    except Exception as webhook_err:
                        logger.error(f"Failed to trigger analysis_failed webhook: {webhook_err}")

                # Remove from active scans tracking
                self._active_scans.discard(scan_id)
                self.queue.task_done()
                logger.info(f"Worker {worker_id} finished scan {scan_id}")

            except asyncio.CancelledError:
                logger.info(f"Worker {worker_id} cancelled during shutdown")
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} crashed: {e}")
                await asyncio.sleep(1)  # Prevent tight loop if something is really broken


# Type alias for external use
WorkerManager = AnalysisWorkerManager

# Global instance
worker_manager = AnalysisWorkerManager(num_workers=settings.WORKER_COUNT)
