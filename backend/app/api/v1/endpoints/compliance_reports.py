"""Compliance report REST endpoints; generation runs in a BackgroundTask that announces its outcome."""

import logging
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from fastapi import BackgroundTasks, HTTPException, Query
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from pydantic import BaseModel, Field

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.core.constants import (
    MAX_COMPLIANCE_REPORT_PAGE,
    MAX_CONCURRENT_COMPLIANCE_REPORTS,
    NOTIFICATION_EVENT_COMPLIANCE_REPORT_GENERATED,
    WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED,
    ScopeName,
)
from app.core.permissions import Permissions, has_permission
from app.db.mongodb import open_gridfs_download_with_retry
from app.models.compliance_report import ComplianceReport
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.analytics.scopes import ScopeResolutionError, ScopeResolver
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.visibility import report_visibility_filter
from app.services.gridfs_maintenance import iter_gridfs_chunks
from app.services.notifications.service import safe_notify_project_event
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

router = CustomAPIRouter(prefix="/compliance", tags=["compliance-reports"])

_REPORT_NOT_FOUND = "Report not found"


class ReportRequest(BaseModel):
    scope: ScopeName
    scope_id: str | None = None
    framework: ReportFramework
    format: ReportFormat
    comment: str | None = Field(None, max_length=1000)


class ReportAck(BaseModel):
    report_id: str
    status: str


def _status_str(value: Any) -> str:
    return str(value.value) if hasattr(value, "value") else str(value)


@router.post(
    "/reports",
    status_code=202,
    responses={
        403: {"description": "Forbidden"},
        429: {"description": "Too many pending reports"},
    },
)
async def create_report(
    req: ReportRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ReportAck:
    await ScopeResolver(db, current_user).resolve(scope=req.scope, scope_id=req.scope_id)

    repo = ComplianceReportRepository(db)
    pending_count = await repo.count_pending_for_user(current_user.id)
    if pending_count >= MAX_CONCURRENT_COMPLIANCE_REPORTS:
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
    await repo.create(report)

    background_tasks.add_task(_run_and_webhook, db, report, current_user)
    return ReportAck(report_id=report.id, status=_status_str(report.status))


async def _user_can_see_report(db: AsyncIOMotorDatabase, user: User, report: ComplianceReport) -> bool:
    """True iff the ScopeResolver resolves the report's scope for this user; scope='user' is gated on requester id (ScopeResolver ignores scope_id there) with system:manage as an admin escape."""
    if report.scope == "user":
        return report.requested_by == str(user.id) or has_permission(user.permissions, Permissions.SYSTEM_MANAGE)
    try:
        await ScopeResolver(db, user).resolve(scope=report.scope, scope_id=report.scope_id)
    except ScopeResolutionError:
        return False
    return True


@router.get("/reports")
async def list_reports(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scope: ScopeName | None = Query(None),
    scope_id: str | None = None,
    framework: ReportFramework | None = None,
    status: ReportStatus | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_COMPLIANCE_REPORT_PAGE),
) -> dict[str, Any]:
    reports = await ComplianceReportRepository(db).list(
        visibility=await report_visibility_filter(db, current_user, scope),
        scope=scope,
        scope_id=scope_id,
        framework=framework,
        status=status,
        skip=skip,
        limit=limit,
    )
    return {"reports": [r.model_dump(by_alias=True) for r in reports]}


@router.get(
    "/reports/{report_id}",
    responses={404: {"description": "Report not found"}},
)
async def get_report(
    report_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    r = await ComplianceReportRepository(db).get_by_id(report_id)
    if r is None:
        raise HTTPException(status_code=404, detail=_REPORT_NOT_FOUND)
    if not await _user_can_see_report(db, current_user, r):
        # Don't leak the report's existence to a caller without scope access.
        raise HTTPException(status_code=404, detail=_REPORT_NOT_FOUND)
    return r.model_dump(by_alias=True)


@router.get(
    "/reports/{report_id}/download",
    responses={
        404: {"description": "Report not found"},
        409: {"description": "Report not ready"},
        410: {"description": "Artifact expired or unavailable"},
    },
)
async def download_report(
    report_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> StreamingResponse:
    r = await ComplianceReportRepository(db).get_by_id(report_id)
    if r is None or not await _user_can_see_report(db, current_user, r):
        raise HTTPException(status_code=404, detail=_REPORT_NOT_FOUND)
    status_val = _status_str(r.status)
    if status_val != "completed":
        raise HTTPException(status_code=409, detail=f"Report not ready (status: {status_val})")
    try:
        # artifact_gridfs_id is stored as a string; GridFS needs an ObjectId.
        stream = await open_gridfs_download_with_retry(AsyncIOMotorGridFSBucket(db), ObjectId(r.artifact_gridfs_id))
    except Exception as exc:
        raise HTTPException(status_code=410, detail="Artifact storage error") from exc

    headers = {"Content-Disposition": f'attachment; filename="{r.artifact_filename}"'}
    return StreamingResponse(
        iter_gridfs_chunks(stream),
        media_type=r.artifact_mime_type or "application/octet-stream",
        headers=headers,
    )


@router.delete(
    "/reports/{report_id}",
    status_code=204,
    responses={
        403: {"description": "Forbidden"},
        404: {"description": "Report not found"},
    },
)
async def delete_report(
    report_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> None:
    repo = ComplianceReportRepository(db)
    r = await repo.get_by_id(report_id)
    if r is None:
        raise HTTPException(status_code=404, detail=_REPORT_NOT_FOUND)
    if r.requested_by != current_user.id and not has_permission(current_user.permissions, Permissions.SYSTEM_MANAGE):
        raise HTTPException(
            status_code=403,
            detail="Cannot delete a report you did not request",
        )
    await repo.delete(report_id)


async def _run_and_webhook(db: AsyncIOMotorDatabase, report: ComplianceReport, user: User) -> None:
    """Run the engine, announce the outcome by webhook and tell project members once the report is ready."""
    try:
        status, summary = await ComplianceReportEngine().generate(report=report, db=db, user=user)
    except Exception:
        logger.exception("Compliance report engine failed for %s", report.id)
        stored = await ComplianceReportRepository(db).get_by_id(report.id)
        if stored is None:
            return
        status, summary = stored.status, stored.summary

    payload = {
        "event": WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "report_id": report.id,
        "framework": _status_str(report.framework),
        "format": _status_str(report.format),
        "scope": report.scope,
        "scope_id": report.scope_id,
        "status": _status_str(status),
        "summary": summary,
    }
    await webhook_service.safe_trigger_webhooks(
        db,
        event_type=WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED,
        payload=payload,
        project_id=report.scope_id if report.scope == "project" else None,
        team_ids=[report.scope_id] if report.scope == "team" and report.scope_id else None,
        context="compliance_reports",
    )

    if status == ReportStatus.COMPLETED and report.scope == "project":
        await safe_notify_project_event(
            db,
            project_id=report.scope_id,
            event_type=NOTIFICATION_EVENT_COMPLIANCE_REPORT_GENERATED,
            subject=f"Compliance report ready ({_status_str(report.framework)})",
            message=f"A new {_status_str(report.framework)} compliance report ({_status_str(report.format)}) is available for this project.",
            context="compliance_reports",
        )
