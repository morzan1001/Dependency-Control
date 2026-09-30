"""Ad-hoc analysis: queue a posted SBOM for the analysis pipeline and fetch the result without a scan."""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from bson import ObjectId
from fastapi import HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.api.deps import AdhocKeyDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.request_body import read_json_body
from app.api.v1.helpers.responses import RESP_AUTH_400
from app.core.config import settings
from app.core.constants import (
    ADHOC_JOB_TTL_SECONDS,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
)
from app.core.worker import worker_manager
from app.db.mongodb import open_gridfs_download_with_retry
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse, AdhocJob
from app.services.analysis.adhoc_report import render_adhoc_html
from app.services.gridfs_maintenance import iter_gridfs_chunks

router = CustomAPIRouter()

_JOB_NOT_FOUND = "Analysis job not found"
_WORKER_LOST = "The worker running this analysis stopped responding. Post the request again."

_DESCRIPTION = """
Queue an analysis of posted SBOMs and scanner results. The answer is 202 with a `job_id`;
`GET /api/v1/analyze/{job_id}` answers 202 while the job waits or runs, then 200 with findings,
statistics, dependencies and recommendations, or `?format=html` for the same result as a
standalone report document. The posted input and the result are kept for 24 hours and readable
only by the key owner; no scan, findings or dependency records are written.

Every run enriches vulnerability findings through the EPSS API, GitHub's advisory API and the
CISA KEV catalog, and the default analyzer set includes `osv`, which sends the package
coordinates read out of the posted SBOMs to `api.osv.dev`. Several further analyzers reach a
third party of their own once named. Pass an explicit `analyzers` list to decide what leaves
this process; `analyzers.notes` in the result names every stage that did, and the host it reached.

Posted scanner output is validated entry by entry against the same models `/api/v1/ingest/*`
uses. A scanner whose entries do not validate is reported in `analyzers.errored` and contributes
no findings, so a report the pipeline could not read never reads as an all-clear.
"""

_HTML_RESPONSE: dict[int | str, dict[str, Any]] = {200: {"content": {"text/html": {"schema": {"type": "string"}}}}}


@router.post(
    "/analyze",
    status_code=status.HTTP_202_ACCEPTED,
    responses=RESP_AUTH_400,
    summary="Queue an ad-hoc analysis",
    description=_DESCRIPTION,
)
async def analyze(request: Request, db: DatabaseDep, authenticated: AdhocKeyDep) -> AdhocJob:
    _owner, key = authenticated
    payload = await read_json_body(request, AdhocAnalyzeRequest)
    data = await asyncio.to_thread(lambda: payload.model_dump_json().encode())
    job_id = str(uuid.uuid4())
    input_file_id = await AsyncIOMotorGridFSBucket(db).upload_from_stream(f"adhoc-{job_id}-input.json", data)
    now = datetime.now(timezone.utc)
    await db.adhoc_jobs.insert_one(
        {
            "_id": job_id,
            "owner_id": key["user_id"],
            "status": SCAN_STATUS_PENDING,
            "input_file_id": str(input_file_id),
            "created_at": now,
            "expires_at": now + timedelta(seconds=ADHOC_JOB_TTL_SECONDS),
        }
    )
    await worker_manager.add_adhoc_job(job_id)
    return AdhocJob(job_id=job_id, status=SCAN_STATUS_PENDING)


@router.get(
    "/analyze/{job_id}",
    response_model=AdhocAnalyzeResponse,
    responses={202: {"model": AdhocJob}, **_HTML_RESPONSE},
    summary="Fetch an ad-hoc analysis result",
)
async def analysis_result(
    job_id: str,
    db: DatabaseDep,
    authenticated: AdhocKeyDep,
    format: Literal["json", "html"] = "json",
) -> Response:
    _owner, key = authenticated
    job = await db.adhoc_jobs.find_one({"_id": job_id, "owner_id": key["user_id"]})
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_JOB_NOT_FOUND)
    if job["status"] == SCAN_STATUS_FAILED:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=job["error"])
    if job["status"] != SCAN_STATUS_COMPLETED:
        silent_since = datetime.now(timezone.utc) - timedelta(seconds=settings.HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS)
        if job["status"] == SCAN_STATUS_PROCESSING and job["heartbeat_at"] < silent_since:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=_WORKER_LOST)
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content={"job_id": job_id, "status": job["status"]})

    stream = await open_gridfs_download_with_retry(AsyncIOMotorGridFSBucket(db), ObjectId(job["result_file_id"]))
    if format == "html":
        raw = await stream.read()
        return HTMLResponse(
            await asyncio.to_thread(lambda: render_adhoc_html(AdhocAnalyzeResponse.model_validate_json(raw)))
        )
    return StreamingResponse(iter_gridfs_chunks(stream), media_type="application/json")
