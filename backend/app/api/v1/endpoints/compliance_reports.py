"""Compliance report REST endpoints.

Endpoints:
    POST   /compliance/reports          -> create a report job (202)
    GET    /compliance/reports          -> list reports (filter + paginate)
    GET    /compliance/reports/{id}     -> report metadata
    GET    /compliance/reports/{id}/download -> stream the GridFS artifact
    DELETE /compliance/reports/{id}     -> delete report + artifact

Report generation is done in a FastAPI BackgroundTask, which hands off to
`ComplianceReportEngine`. A best-effort webhook is fired after completion.
"""

import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from pydantic import BaseModel, Field

from app.api.deps import get_current_active_user, get_database
from app.core.constants import WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED
from app.models.compliance_report import ComplianceReport
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.analytics.scopes import ScopeResolver
from app.services.compliance.engine import ComplianceReportEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["compliance-reports"])

_MAX_CONCURRENT_PENDING = 10
_SCOPE_PATTERN = "^(project|team|global|user)$"


class ReportRequest(BaseModel):
    scope: Literal["project", "team", "global", "user"] = Field(..., pattern=_SCOPE_PATTERN)
    scope_id: Optional[str] = None
    framework: ReportFramework
    format: ReportFormat
    comment: Optional[str] = Field(None, max_length=1000)


class ReportAck(BaseModel):
    report_id: str
    status: str


def _status_str(value: Any) -> str:
    return str(value.value) if hasattr(value, "value") else str(value)


@router.post("/reports", response_model=ReportAck, status_code=202)
async def create_report(
    req: ReportRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> ReportAck:
    try:
        await ScopeResolver(db, current_user).resolve(
            scope=req.scope,
            scope_id=req.scope_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Scope resolution failed: {exc}")

    repo = ComplianceReportRepository(db)
    pending_count = await repo.count_pending_for_user(current_user.id)
    if pending_count >= _MAX_CONCURRENT_PENDING:
        raise HTTPException(
            status_code=429,
            detail=f"Too many pending reports ({pending_count}). Wait for some to complete.",
            headers={"Retry-After": "60"},
        )

    report = ComplianceReport(
        scope=req.scope,
        scope_id=req.scope_id,
        framework=req.framework,
        format=req.format,
        status=ReportStatus.PENDING,
        requested_by=current_user.id,
        requested_at=datetime.now(timezone.utc),
        comment=req.comment,
    )
    await repo.insert(report)

    background_tasks.add_task(_run_and_webhook, db, report, current_user)
    return ReportAck(report_id=report.id, status=_status_str(report.status))


@router.get("/reports")
async def list_reports(
    scope: Optional[str] = Query(None, pattern=_SCOPE_PATTERN),
    scope_id: Optional[str] = None,
    framework: Optional[ReportFramework] = None,
    status: Optional[ReportStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> dict[str, Any]:
    repo = ComplianceReportRepository(db)
    reports = await repo.list(
        scope=scope,
        scope_id=scope_id,
        framework=framework,
        status=status,
        skip=skip,
        limit=limit,
    )
    return {"reports": [r.model_dump(by_alias=True) for r in reports]}


@router.get("/reports/{report_id}")
async def get_report(
    report_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> dict[str, Any]:
    r = await ComplianceReportRepository(db).get(report_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return r.model_dump(by_alias=True)


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> StreamingResponse:
    r = await ComplianceReportRepository(db).get(report_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Report not found")
    status_val = _status_str(r.status)
    if status_val != "completed":
        raise HTTPException(status_code=409, detail=f"Report not ready (status: {status_val})")
    if r.artifact_gridfs_id is None:
        raise HTTPException(status_code=410, detail="Artifact expired or missing")
    try:
        await ScopeResolver(db, current_user).resolve(scope=r.scope, scope_id=r.scope_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Scope resolution failed: {exc}")

    bucket = AsyncIOMotorGridFSBucket(db)
    try:
        stream = await bucket.open_download_stream(r.artifact_gridfs_id)
    except Exception:
        raise HTTPException(status_code=410, detail="Artifact storage error")

    async def _iter() -> AsyncIterator[bytes]:
        try:
            while True:
                chunk = await stream.readchunk()
                if not chunk:
                    break
                yield chunk
        finally:
            # motor's AgnosticGridOut.close() returns a coroutine at runtime
            # though the stub claims None; await defensively.
            close_result: Any = stream.close()  # type: ignore[func-returns-value]
            if close_result is not None:
                await close_result

    headers = {"Content-Disposition": f'attachment; filename="{r.artifact_filename}"'}
    return StreamingResponse(
        _iter(),
        media_type=r.artifact_mime_type or "application/octet-stream",
        headers=headers,
    )


@router.delete("/reports/{report_id}", status_code=204)
async def delete_report(
    report_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> None:
    repo = ComplianceReportRepository(db)
    r = await repo.get(report_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if r.requested_by != current_user.id:
        perms: frozenset[str] = getattr(current_user, "permissions", frozenset()) or frozenset()
        if "system:manage" not in perms:
            raise HTTPException(
                status_code=403,
                detail="Cannot delete a report you did not request",
            )
    if r.artifact_gridfs_id:
        bucket = AsyncIOMotorGridFSBucket(db)
        try:
            await bucket.delete(r.artifact_gridfs_id)
        except Exception:
            pass
    await repo.delete(report_id)


async def _run_and_webhook(db: AsyncIOMotorDatabase, report: ComplianceReport, user: User) -> None:
    """BackgroundTask target: run engine then fire best-effort webhook."""
    engine = ComplianceReportEngine()
    try:
        await engine.generate(report=report, db=db, user=user)
    except Exception:
        logger.exception("Compliance report engine failed for %s", report.id)

    try:
        from app.services.webhooks import webhook_service

        fresh = await ComplianceReportRepository(db).get(report.id)
        fresh_status = None
        fresh_summary: dict = {}
        if fresh is not None:
            fresh_status = _status_str(fresh.status)
            fresh_summary = fresh.summary or {}
        payload = {
            "event": WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "report_id": report.id,
            "framework": _status_str(report.framework),
            "format": _status_str(report.format),
            "scope": report.scope,
            "scope_id": report.scope_id,
            "status": fresh_status,
            "summary": fresh_summary,
        }
        await webhook_service.trigger_webhooks(
            db,
            event_type=WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED,
            payload=payload,
            project_id=report.scope_id if report.scope == "project" else None,
        )
    except Exception:
        logger.exception("Compliance-report webhook dispatch failed (non-blocking)")
