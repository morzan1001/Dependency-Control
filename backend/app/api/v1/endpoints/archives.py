"""
Archive API Endpoints

Provides endpoints for listing, downloading, and restoring archived scan data.
"""

import math

from fastapi import HTTPException, Query
from fastapi.responses import StreamingResponse

from app.api.router import CustomAPIRouter
from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH_404, RESP_AUTH_404_500
from app.core.constants import PROJECT_ROLE_ADMIN
from app.core.s3 import download_bytes, is_archive_enabled
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.schemas.archive import (
    ArchiveListItem,
    ArchiveListResponse,
    ArchiveRestoreResponse,
)
from app.services.archive import restore_scan

router = CustomAPIRouter()


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
) -> ArchiveListResponse:
    """List all archived scans for a project. Requires project access."""
    await check_project_access(project_id, current_user, db)

    if not is_archive_enabled():
        raise HTTPException(status_code=501, detail="Archive storage is not configured")

    repo = ArchiveMetadataRepository(db)
    skip = (page - 1) * size
    total = await repo.count_by_project(project_id)
    archives = await repo.find_by_project(project_id, skip=skip, limit=size)

    items = [
        ArchiveListItem(
            id=a.id,
            scan_id=a.scan_id,
            branch=a.branch,
            commit_hash=a.commit_hash,
            scan_created_at=a.scan_created_at,
            archived_at=a.archived_at,
            compressed_size_bytes=a.compressed_size_bytes,
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
    Requires project admin role.
    """
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)

    if not is_archive_enabled():
        raise HTTPException(status_code=501, detail="Archive storage is not configured")

    # Verify archive belongs to this project
    repo = ArchiveMetadataRepository(db)
    metadata = await repo.find_by_scan_id(scan_id)

    if not metadata or metadata.project_id != project_id:
        raise HTTPException(status_code=404, detail="Archive not found for this project")

    result = await restore_scan(db, scan_id)
    if not result:
        raise HTTPException(status_code=500, detail="Failed to restore archive")

    return ArchiveRestoreResponse(
        scan_id=result["scan_id"],
        project_id=result["project_id"],
        collections_restored=result["collections_restored"],
    )


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
    """
    Download the raw .json.gz archive file.
    Requires project access.
    """
    await check_project_access(project_id, current_user, db)

    if not is_archive_enabled():
        raise HTTPException(status_code=501, detail="Archive storage is not configured")

    repo = ArchiveMetadataRepository(db)
    metadata = await repo.find_by_scan_id(scan_id)

    if not metadata or metadata.project_id != project_id:
        raise HTTPException(status_code=404, detail="Archive not found for this project")

    try:
        data = await download_bytes(metadata.s3_key)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to download archive from storage")

    return StreamingResponse(
        iter([data]),
        media_type="application/gzip",
        headers={
            "Content-Disposition": f'attachment; filename="{scan_id}.json.gz"',
            "Content-Length": str(len(data)),
        },
    )
