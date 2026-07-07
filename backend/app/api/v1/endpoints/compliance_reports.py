"""Compliance report REST endpoints; generation runs in a BackgroundTask with a best-effort webhook on completion."""

import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Literal, Optional

from bson import ObjectId
from fastapi import BackgroundTasks, HTTPException, Query
from fastapi.responses import StreamingResponse
from gridfs.errors import NoFile
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from pydantic import BaseModel, Field

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.core.constants import MAX_CONCURRENT_COMPLIANCE_REPORTS, WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED
from app.models.compliance_report import ComplianceReport
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.analytics.scopes import ScopeResolver
from app.services.compliance.engine import ComplianceReportEngine

logger = logging.getLogger(__name__)

router = CustomAPIRouter(prefix="/compliance", tags=["compliance-reports"])

_SCOPE_PATTERN = "^(project|team|global|user)$"
_REPORT_NOT_FOUND = "Report not found"


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


@router.post(
    "/reports",
    response_model=ReportAck,
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
    await repo.insert(report)

    background_tasks.add_task(_run_and_webhook, db, report, current_user)
    return ReportAck(report_id=report.id, status=_status_str(report.status))


async def _user_can_see_report(db: AsyncIOMotorDatabase, user: User, report: ComplianceReport) -> bool:
    """True iff the ScopeResolver resolves the report's scope for this user; scope='user' is gated on requester id (ScopeResolver ignores scope_id there) with system:manage as an admin escape."""
    if report.scope == "user":
        if report.requested_by == str(user.id):
            return True
        from app.core.permissions import Permissions, has_permission

        return has_permission(getattr(user, "permissions", []) or [], Permissions.SYSTEM_MANAGE)
    try:
        await ScopeResolver(db, user).resolve(scope=report.scope, scope_id=report.scope_id)
        return True
    except Exception:
        # Any resolution failure (permission or missing project) must hide the report.
        return False


async def _build_visibility_filter(db: AsyncIOMotorDatabase, user: User) -> Dict[str, Any]:
    """Build the $or filter capturing every scope a user may see, so list pagination runs on already-filtered results."""
    from app.core.permissions import Permissions, has_permission
    from app.repositories.teams import TeamRepository

    perms = getattr(user, "permissions", []) or []
    is_super = has_permission(perms, Permissions.SYSTEM_MANAGE)
    user_id = str(user.id)

    branches: List[Dict[str, Any]] = []

    user_branch: Dict[str, Any] = {"scope": "user"}
    if not is_super:
        user_branch["requested_by"] = user_id
    branches.append(user_branch)

    project_ids = await ScopeResolver(db, user)._list_user_project_ids()  # noqa: SLF001
    if project_ids:
        branches.append({"scope": "project", "scope_id": {"$in": project_ids}})

    team_repo = TeamRepository(db)
    user_teams = await team_repo.find_by_member(user_id)
    team_ids = [str(t.id) for t in user_teams]
    if team_ids:
        branches.append({"scope": "team", "scope_id": {"$in": team_ids}})

    if is_super or has_permission(perms, Permissions.ANALYTICS_GLOBAL):
        branches.append({"scope": "global"})

    return {"$or": branches}


@router.get("/reports")
async def list_reports(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scope: Optional[str] = Query(None, pattern=_SCOPE_PATTERN),
    scope_id: Optional[str] = None,
    framework: Optional[ReportFramework] = None,
    status: Optional[ReportStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    repo = ComplianceReportRepository(db)
    visibility = await _build_visibility_filter(db, current_user)
    reports = await repo.list(
        scope=scope,
        scope_id=scope_id,
        framework=framework,
        status=status,
        skip=skip,
        limit=limit,
        extra_filter=visibility,
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
    r = await ComplianceReportRepository(db).get(report_id)
    if r is None:
        raise HTTPException(status_code=404, detail=_REPORT_NOT_FOUND)
    if not await _user_can_see_report(db, current_user, r):
        # Don't leak the report's existence to a caller without scope access.
        raise HTTPException(status_code=404, detail=_REPORT_NOT_FOUND)
    return r.model_dump(by_alias=True)


@router.get(
    "/reports/{report_id}/download",
    responses={
        403: {"description": "Forbidden"},
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
    r = await ComplianceReportRepository(db).get(report_id)
    if r is None:
        raise HTTPException(status_code=404, detail=_REPORT_NOT_FOUND)
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
        # artifact_gridfs_id is stored as a string; GridFS needs an ObjectId.
        stream = await bucket.open_download_stream(ObjectId(r.artifact_gridfs_id))
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
            # motor's AgnosticGridOut.close() returns a coroutine at runtime though the stub claims None.
            close_result: Any = stream.close()  # type: ignore[func-returns-value]
            if close_result is not None:
                await close_result

    headers = {"Content-Disposition": f'attachment; filename="{r.artifact_filename}"'}
    return StreamingResponse(
        _iter(),
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
    r = await repo.get(report_id)
    if r is None:
        raise HTTPException(status_code=404, detail=_REPORT_NOT_FOUND)
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
            await bucket.delete(ObjectId(r.artifact_gridfs_id))
        except NoFile:
            pass  # already gone — nothing to clean up
        except Exception:
            logger.warning("Failed to delete GridFS artifact %s", r.artifact_gridfs_id, exc_info=True)
    await repo.delete(report_id)


async def _run_and_webhook(db: AsyncIOMotorDatabase, report: ComplianceReport, user: User) -> None:
    """BackgroundTask target: run engine then fire best-effort webhook."""
    engine = ComplianceReportEngine()
    try:
        await engine.generate(report=report, db=db, user=user)
    except Exception:
        logger.exception("Compliance report engine failed for %s", report.id)

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
    await webhook_service.safe_trigger_webhooks(
        db,
        event_type=WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED,
        payload=payload,
        project_id=report.scope_id if report.scope == "project" else None,
        context="compliance_reports",
    )

    if report.scope == "project" and report.scope_id:
        from app.services.notifications.service import safe_notify_project_event

        await safe_notify_project_event(
            db,
            project_id=report.scope_id,
            event_type="compliance_report_generated",
            subject=f"Compliance report ready ({_status_str(report.framework)})",
            message=f"A new {_status_str(report.framework)} compliance report ({_status_str(report.format)}) is available for this project.",
            context="compliance_reports",
        )
