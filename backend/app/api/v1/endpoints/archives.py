"""
Archive API Endpoints

Provides endpoints for listing, downloading, restoring, and managing archived scan data.
"""

import math
from datetime import datetime
from typing import List, Optional

from fastapi import HTTPException, Query
from fastapi.responses import StreamingResponse

from app.api.router import CustomAPIRouter
from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH_404, RESP_AUTH_404_500
from app.core.constants import PROJECT_ROLE_ADMIN
from app.core.permissions import Permissions, has_permission
from app.core.encryption import decrypt, is_encryption_enabled
from app.core.s3 import download_bytes, is_archive_enabled
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.schemas.archive import (
    AdminArchiveListItem,
    AdminArchiveListResponse,
    ArchiveListItem,
    ArchiveListResponse,
    ArchiveRestoreResponse,
    ScanPinResponse,
)
from app.services.archive import restore_scan

router = CustomAPIRouter()
admin_router = CustomAPIRouter()

_MSG_ARCHIVE_NOT_CONFIGURED = "Archive storage is not configured"


def _require_archive_permission(user_permissions: List[str], permission: str) -> None:
    """Raise 403 if user lacks the given archive permission."""
    if not has_permission(user_permissions, permission):
        raise HTTPException(status_code=403, detail="Not enough permissions")


def _require_archive_enabled() -> None:
    """Raise 501 if S3 archive storage is not configured."""
    if not is_archive_enabled():
        raise HTTPException(status_code=501, detail=_MSG_ARCHIVE_NOT_CONFIGURED)


@router.get(
    "/{project_id}/archives",
    response_model=ArchiveListResponse,
    summary="List archived scans for a project",
    responses=RESP_AUTH_404,
)
async def list_archives(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    branch: Optional[str] = Query(None, description="Filter by branch name"),
    date_from: Optional[datetime] = Query(None, description="Filter scans created from this date"),
    date_to: Optional[datetime] = Query(None, description="Filter scans created until this date"),
) -> ArchiveListResponse:
    """List all archived scans for a project. Requires archive:read permission."""
    _require_archive_permission(current_user.permissions, Permissions.ARCHIVE_READ)
    await check_project_access(project_id, current_user, db)

    _require_archive_enabled()

    repo = ArchiveMetadataRepository(db)
    skip = (page - 1) * size
    total = await repo.count_by_project(project_id, branch=branch, date_from=date_from, date_to=date_to)
    archives = await repo.find_by_project(
        project_id,
        skip=skip,
        limit=size,
        branch=branch,
        date_from=date_from,
        date_to=date_to,
    )

    items = [
        ArchiveListItem(
            id=a.id,
            scan_id=a.scan_id,
            branch=a.branch,
            commit_hash=a.commit_hash,
            scan_created_at=a.scan_created_at,
            archived_at=a.archived_at,
            compressed_size_bytes=a.compressed_size_bytes,
            findings_count=a.findings_count,
            critical_findings_count=a.critical_findings_count,
            high_findings_count=a.high_findings_count,
            dependencies_count=a.dependencies_count,
            sbom_filenames=a.sbom_filenames,
        )
        for a in archives
    ]

    return ArchiveListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=max(1, math.ceil(total / size)) if total > 0 else 1,
    )


@router.get(
    "/{project_id}/archives/branches",
    response_model=List[str],
    summary="Get distinct branch names in project archives",
    responses=RESP_AUTH_404,
)
async def list_archive_branches(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> List[str]:
    """Get all unique branch names in a project's archives. Requires archive:read."""
    _require_archive_permission(current_user.permissions, Permissions.ARCHIVE_READ)
    await check_project_access(project_id, current_user, db)

    _require_archive_enabled()

    repo = ArchiveMetadataRepository(db)
    return await repo.get_distinct_branches(project_id)


@router.post(
    "/{project_id}/archives/{scan_id}/restore",
    response_model=ArchiveRestoreResponse,
    summary="Restore an archived scan back to MongoDB",
    responses=RESP_AUTH_404_500,
)
async def restore_archive(
    project_id: str,
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ArchiveRestoreResponse:
    """
    Restore an archived scan and all its data from S3 back to MongoDB.
    The restored scan is automatically pinned to prevent re-archival by housekeeping.
    Requires archive:restore permission and project admin role.
    """
    _require_archive_permission(current_user.permissions, Permissions.ARCHIVE_RESTORE)
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)

    _require_archive_enabled()

    repo = ArchiveMetadataRepository(db)
    metadata = await repo.find_by_scan_id(scan_id)

    if not metadata or metadata.project_id != project_id:
        raise HTTPException(status_code=404, detail="Archive not found for this project")

    result = await restore_scan(db, scan_id)
    if not result:
        raise HTTPException(status_code=500, detail="Failed to restore archive")

    return result


@router.get(
    "/{project_id}/archives/{scan_id}/download",
    summary="Download an archived scan bundle",
    responses=RESP_AUTH_404_500,
)
async def download_archive(
    project_id: str,
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> StreamingResponse:
    """Download the raw .json.gz archive file. Requires archive:download permission."""
    _require_archive_permission(current_user.permissions, Permissions.ARCHIVE_DOWNLOAD)
    await check_project_access(project_id, current_user, db)

    _require_archive_enabled()

    repo = ArchiveMetadataRepository(db)
    metadata = await repo.find_by_scan_id(scan_id)

    if not metadata or metadata.project_id != project_id:
        raise HTTPException(status_code=404, detail="Archive not found for this project")

    try:
        data = await download_bytes(metadata.s3_key)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to download archive from storage")

    if is_encryption_enabled():
        data = decrypt(data)

    return StreamingResponse(
        iter([data]),
        media_type="application/gzip",
        headers={
            "Content-Disposition": f'attachment; filename="{scan_id}.json.gz"',
            "Content-Length": str(len(data)),
        },
    )


@router.post(
    "/{project_id}/scans/{scan_id}/pin",
    response_model=ScanPinResponse,
    summary="Pin a scan to prevent archival by housekeeping",
    responses=RESP_AUTH_404_500,
)
async def pin_scan(
    project_id: str,
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ScanPinResponse:
    """Pin a scan so housekeeping will not archive or delete it. Requires archive:restore + project admin."""
    _require_archive_permission(current_user.permissions, Permissions.ARCHIVE_RESTORE)
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)

    scan = await db.scans.find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await db.scans.update_one({"_id": scan_id}, {"$set": {"pinned": True}})
    return ScanPinResponse(scan_id=scan_id, pinned=True)


@router.post(
    "/{project_id}/scans/{scan_id}/unpin",
    response_model=ScanPinResponse,
    summary="Unpin a scan to allow archival by housekeeping",
    responses=RESP_AUTH_404_500,
)
async def unpin_scan(
    project_id: str,
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ScanPinResponse:
    """Unpin a scan so housekeeping can archive or delete it again. Requires archive:restore + project admin."""
    _require_archive_permission(current_user.permissions, Permissions.ARCHIVE_RESTORE)
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)

    scan = await db.scans.find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await db.scans.update_one({"_id": scan_id}, {"$set": {"pinned": False}})
    return ScanPinResponse(scan_id=scan_id, pinned=False)


# ---------------------------------------------------------------------------
# Admin endpoints (registered under /api/v1/archives)
# ---------------------------------------------------------------------------


@admin_router.get(
    "/all",
    response_model=AdminArchiveListResponse,
    summary="List all archives across all projects (admin)",
    responses=RESP_AUTH_404,
)
async def list_all_archives(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    branch: Optional[str] = Query(None, description="Filter by branch name"),
    date_from: Optional[datetime] = Query(None, description="Filter scans created from this date"),
    date_to: Optional[datetime] = Query(None, description="Filter scans created until this date"),
) -> AdminArchiveListResponse:
    """List all archived scans across all projects. Requires archive:read_all permission."""
    _require_archive_permission(current_user.permissions, Permissions.ARCHIVE_READ_ALL)

    _require_archive_enabled()

    repo = ArchiveMetadataRepository(db)
    skip = (page - 1) * size
    total = await repo.count_all(
        branch=branch,
        date_from=date_from,
        date_to=date_to,
        project_id=project_id,
    )
    archives = await repo.find_all(
        skip=skip,
        limit=size,
        branch=branch,
        date_from=date_from,
        date_to=date_to,
        project_id=project_id,
    )

    # Batch-lookup project names
    unique_project_ids = list({a.project_id for a in archives})
    project_names: dict = {}
    if unique_project_ids:
        cursor = db.projects.find({"_id": {"$in": unique_project_ids}}, {"_id": 1, "name": 1})
        async for doc in cursor:
            project_names[doc["_id"]] = doc.get("name", doc["_id"])

    items = [
        AdminArchiveListItem(
            id=a.id,
            scan_id=a.scan_id,
            project_id=a.project_id,
            project_name=project_names.get(a.project_id),
            branch=a.branch,
            commit_hash=a.commit_hash,
            scan_created_at=a.scan_created_at,
            archived_at=a.archived_at,
            compressed_size_bytes=a.compressed_size_bytes,
            findings_count=a.findings_count,
            critical_findings_count=a.critical_findings_count,
            high_findings_count=a.high_findings_count,
            dependencies_count=a.dependencies_count,
            sbom_filenames=a.sbom_filenames,
        )
        for a in archives
    ]

    return AdminArchiveListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=max(1, math.ceil(total / size)) if total > 0 else 1,
    )
