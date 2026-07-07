"""Endpoints for listing, downloading, restoring, and managing archived scan data."""

import logging
import math
import time
from datetime import datetime
from typing import Annotated, AsyncIterator, List, Optional

from fastapi import HTTPException, Query
from fastapi.responses import StreamingResponse

from app.api.router import CustomAPIRouter
from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH_404, RESP_AUTH_404_500
from app.core.constants import PROJECT_ROLE_ADMIN
from app.core.permissions import Permissions, has_permission
from app.core.encryption import decrypt_stream, is_encryption_enabled
from app.core.metrics import (
    ArchiveFailureReason,
    archive_failures_total,
    archive_operation_duration_seconds,
    archive_operations_total,
)
from app.core.s3 import download_stream, is_archive_enabled
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

logger = logging.getLogger(__name__)

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
    summary="List archived scans for a project",
    responses=RESP_AUTH_404,
)
async def list_archives(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 20,
    branch: Annotated[Optional[str], Query(description="Filter by branch name")] = None,
    date_from: Annotated[Optional[datetime], Query(description="Filter scans created from this date")] = None,
    date_to: Annotated[Optional[datetime], Query(description="Filter scans created until this date")] = None,
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
    summary="Restore an archived scan back to MongoDB",
    responses=RESP_AUTH_404_500,
)
async def restore_archive(
    project_id: str,
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ArchiveRestoreResponse:
    """Restore an archived scan from S3 back into MongoDB (404 if absent, 409 if already present, 500 otherwise)."""
    _require_archive_permission(current_user.permissions, Permissions.ARCHIVE_RESTORE)
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)

    _require_archive_enabled()

    repo = ArchiveMetadataRepository(db)
    metadata = await repo.find_by_scan_id(scan_id)

    if not metadata or metadata.project_id != project_id:
        raise HTTPException(status_code=404, detail="Archive not found for this project")

    result = await restore_scan(db, scan_id)
    if not result:
        # restore_scan returns None for several failures; if the scan now exists
        # it was a concurrent restore → 409 (best-effort, small TOCTOU window).
        existing_scan = await db.scans.find_one({"_id": scan_id})
        if existing_scan:
            raise HTTPException(status_code=409, detail="Scan already exists in MongoDB")
        raise HTTPException(status_code=500, detail="Failed to restore archive")

    logger.info(
        "archive.restore",
        extra={
            "user_id": getattr(current_user, "id", None),
            "scan_id": scan_id,
            "project_id": project_id,
            "collections_restored": result.collections_restored,
        },
    )
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
    """Download the raw bundle as a stream. Requires archive:download permission."""
    _require_archive_permission(current_user.permissions, Permissions.ARCHIVE_DOWNLOAD)
    await check_project_access(project_id, current_user, db)
    _require_archive_enabled()

    repo = ArchiveMetadataRepository(db)
    metadata = await repo.find_by_scan_id(scan_id)
    if not metadata or metadata.project_id != project_id:
        raise HTTPException(status_code=404, detail="Archive not found for this project")

    logger.info(
        "archive.download.initiated",
        extra={
            "user_id": getattr(current_user, "id", None),
            "scan_id": scan_id,
            "project_id": project_id,
            "s3_key": metadata.s3_key,
        },
    )

    start_time = time.monotonic()

    async def _stream() -> AsyncIterator[bytes]:
        try:
            chunks = download_stream(metadata.s3_key, bucket=metadata.s3_bucket)
            if is_encryption_enabled():
                chunks = decrypt_stream(chunks)
            async for chunk in chunks:
                yield chunk
            logger.info(
                "archive.download.completed",
                extra={
                    "scan_id": scan_id,
                    "project_id": project_id,
                    "s3_key": metadata.s3_key,
                },
            )
            duration = time.monotonic() - start_time
            archive_operations_total.labels(operation="download", status="success").inc()
            archive_operation_duration_seconds.labels(operation="download").observe(duration)
        except Exception:
            archive_failures_total.labels(operation="download", reason=ArchiveFailureReason.S3_ERROR).inc()
            archive_operations_total.labels(operation="download", status="failure").inc()
            raise

    suffix = ".bundle" if is_encryption_enabled() else ".json.gz"
    media_type = "application/octet-stream" if is_encryption_enabled() else "application/gzip"

    return StreamingResponse(
        _stream(),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{scan_id}{suffix}"'},
    )


@router.post(
    "/{project_id}/scans/{scan_id}/pin",
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
    logger.info(
        "archive.pin",
        extra={
            "user_id": getattr(current_user, "id", None),
            "scan_id": scan_id,
            "project_id": project_id,
        },
    )
    return ScanPinResponse(scan_id=scan_id, pinned=True)


@router.post(
    "/{project_id}/scans/{scan_id}/unpin",
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
    logger.info(
        "archive.unpin",
        extra={
            "user_id": getattr(current_user, "id", None),
            "scan_id": scan_id,
            "project_id": project_id,
        },
    )
    return ScanPinResponse(scan_id=scan_id, pinned=False)


@admin_router.get(
    "/all",
    summary="List all archives across all projects (admin)",
    responses=RESP_AUTH_404,
)
async def list_all_archives(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 20,
    project_id: Annotated[Optional[str], Query(description="Filter by project ID")] = None,
    branch: Annotated[Optional[str], Query(description="Filter by branch name")] = None,
    date_from: Annotated[Optional[datetime], Query(description="Filter scans created from this date")] = None,
    date_to: Annotated[Optional[datetime], Query(description="Filter scans created until this date")] = None,
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
