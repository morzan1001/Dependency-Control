"""Policy audit endpoints (list/detail/revert/prune); system scope is admin-only, project scope is member-read/admin-write."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import Body, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import (
    RESP_400,
    RESP_400_403,
    RESP_400_403_404,
    RESP_400_404,
    RESP_403,
    RESP_403_404,
    RESP_404,
)
from app.core.config import settings
from app.models.crypto_policy import CryptoPolicy
from app.models.user import User
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.crypto_policy import CryptoRule
from app.schemas.policy_audit import PolicyAuditAction
from app.services.audit.history import record_policy_change

logger = logging.getLogger(__name__)

router = CustomAPIRouter(tags=["policy-audit"])


@router.get("/crypto-policies/system/audit", responses=RESP_403)
async def list_system_audit(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    _require_admin(current_user)
    entries = await PolicyAuditRepository(db).list(
        policy_scope="system",
        skip=skip,
        limit=limit,
    )
    return {"entries": [e.model_dump(by_alias=True) for e in entries]}


@router.get("/crypto-policies/system/audit/{version}", responses=RESP_403_404)
async def get_system_audit_entry(
    version: int,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    _require_admin(current_user)
    entry = await PolicyAuditRepository(db).get_by_version(
        policy_scope="system",
        project_id=None,
        version=version,
    )
    if entry is None:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    return entry.model_dump(by_alias=True)


@router.post(
    "/crypto-policies/system/revert",
    responses={
        **RESP_400_403_404,
        500: {"description": "Reverted policy not found"},
    },
)
async def revert_system_policy(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    body: dict = Body(...),
) -> dict[str, Any]:
    _require_admin(current_user)
    target_raw = body.get("target_version")
    if target_raw is None:
        raise HTTPException(status_code=400, detail="target_version required")
    target_version = int(target_raw)
    comment = body.get("comment")
    await _revert_policy(
        db=db,
        actor=current_user,
        policy_scope="system",
        project_id=None,
        target_version=target_version,
        comment=comment,
    )
    policy = await CryptoPolicyRepository(db).get_system_policy()
    if policy is None:
        raise HTTPException(status_code=500, detail="Reverted policy not found")
    return policy.model_dump(by_alias=True)


@router.delete("/crypto-policies/system/audit", responses=RESP_400_403)
async def prune_system_audit(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    before: str = Query(..., description="Delete entries older than this ISO date"),
) -> dict[str, Any]:
    _require_admin(current_user)
    cutoff = _parse_datetime(before)
    _enforce_min_prune_cutoff(cutoff)
    deleted = await PolicyAuditRepository(db).delete_older_than(
        policy_scope="system",
        project_id=None,
        cutoff=cutoff,
    )
    return {"deleted": deleted}


@router.get("/projects/{project_id}/crypto-policy/audit")
async def list_project_audit(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    await check_project_access(project_id, current_user, db, required_role="viewer")
    entries = await PolicyAuditRepository(db).list(
        policy_scope="project",
        project_id=project_id,
        skip=skip,
        limit=limit,
    )
    return {"entries": [e.model_dump(by_alias=True) for e in entries]}


@router.get("/projects/{project_id}/crypto-policy/audit/{version}", responses=RESP_404)
async def get_project_audit_entry(
    project_id: str,
    version: int,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    await check_project_access(project_id, current_user, db, required_role="viewer")
    entry = await PolicyAuditRepository(db).get_by_version(
        policy_scope="project",
        project_id=project_id,
        version=version,
    )
    if entry is None:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    return entry.model_dump(by_alias=True)


@router.post("/projects/{project_id}/crypto-policy/revert", responses=RESP_400_404)
async def revert_project_policy(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    body: dict = Body(...),
) -> dict[str, Any]:
    # 'owner' is not a project role; PROJECT_ROLES = viewer|editor|admin.
    await check_project_access(project_id, current_user, db, required_role="admin")
    target_raw = body.get("target_version")
    if target_raw is None:
        raise HTTPException(status_code=400, detail="target_version required")
    target_version = int(target_raw)
    comment = body.get("comment")
    await _revert_policy(
        db=db,
        actor=current_user,
        policy_scope="project",
        project_id=project_id,
        target_version=target_version,
        comment=comment,
    )
    policy = await CryptoPolicyRepository(db).get_project_policy(project_id)
    return policy.model_dump(by_alias=True) if policy else {}


@router.delete("/projects/{project_id}/crypto-policy/audit", responses=RESP_400)
async def prune_project_audit(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    before: str = Query(...),
) -> dict[str, Any]:
    await check_project_access(project_id, current_user, db, required_role="admin")
    cutoff = _parse_datetime(before)
    _enforce_min_prune_cutoff(cutoff)
    deleted = await PolicyAuditRepository(db).delete_older_than(
        policy_scope="project",
        project_id=project_id,
        cutoff=cutoff,
    )
    return {"deleted": deleted}


@router.get("/projects/{project_id}/license-policy/audit")
async def list_project_license_audit(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """List license-policy audit entries for a project (viewer+ role)."""
    await check_project_access(project_id, current_user, db, required_role="viewer")
    entries = await PolicyAuditRepository(db).list(
        policy_scope="project",
        project_id=project_id,
        policy_type="license",
        skip=skip,
        limit=limit,
    )
    return {"entries": [e.model_dump(by_alias=True) for e in entries]}


@router.get("/projects/{project_id}/license-policy/audit/{version}", responses=RESP_404)
async def get_project_license_audit_entry(
    project_id: str,
    version: int,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Fetch a single license-policy audit entry by version."""
    await check_project_access(project_id, current_user, db, required_role="viewer")
    entry = await PolicyAuditRepository(db).get_by_version(
        policy_scope="project",
        project_id=project_id,
        version=version,
        policy_type="license",
    )
    if entry is None:
        raise HTTPException(status_code=404, detail=f"License-policy version {version} not found")
    return entry.model_dump(by_alias=True)


# revert/prune for license-policy audit omitted: overwriting license settings would need a non-trivial merge with peer analyzer settings.


def _parse_datetime(value: str) -> datetime:
    """Parse an ISO-8601 datetime string, tolerating space-encoded '+' from URLs."""
    # A raw-URL '+00:00' arrives with the '+' as a space; restore it before parsing.
    value = value.replace(" ", "+")
    return datetime.fromisoformat(value)


def _min_prune_days() -> int:
    return settings.POLICY_AUDIT_MIN_PRUNE_DAYS


def _enforce_min_prune_cutoff(cutoff: datetime) -> None:
    """Reject prune requests whose cutoff is too recent, preserving forensic history."""
    days = _min_prune_days()
    # Normalise a possibly-naive client timestamp to UTC.
    now = datetime.now(timezone.utc)
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    min_age_boundary = now - timedelta(days=days)
    if cutoff > min_age_boundary:
        raise HTTPException(
            status_code=400,
            detail=(f"before must be at least {days} days in the past to preserve forensic history"),
        )


def _require_admin(user: User) -> None:
    perms: frozenset[str] = getattr(user, "permissions", frozenset()) or frozenset()
    if "system:manage" not in perms:
        raise HTTPException(status_code=403, detail="system:manage permission required")


async def _revert_policy(
    *,
    db: AsyncIOMotorDatabase,
    actor: User,
    policy_scope: Literal["system", "project"],
    project_id: Optional[str],
    target_version: int,
    comment: Optional[str],
) -> None:
    target_entry = await PolicyAuditRepository(db).get_by_version(
        policy_scope=policy_scope,
        project_id=project_id,
        version=target_version,
    )
    if target_entry is None:
        raise HTTPException(status_code=404, detail=f"Version {target_version} not found")

    snapshot = target_entry.snapshot
    rules = [CryptoRule.model_validate(r) for r in snapshot.get("rules", [])]

    policy_repo = CryptoPolicyRepository(db)
    current: Optional[CryptoPolicy]
    if policy_scope == "system":
        current = await policy_repo.get_system_policy()
    else:
        if project_id is None:
            raise HTTPException(status_code=400, detail="project_id required for project scope")
        current = await policy_repo.get_project_policy(project_id)
    new_version = (current.version + 1) if current else 1

    new_policy = CryptoPolicy(
        scope=policy_scope,
        project_id=project_id if policy_scope == "project" else None,
        rules=rules,
        version=new_version,
    )

    await record_policy_change(
        db,
        policy_scope=policy_scope,
        project_id=project_id,
        old_policy=current,
        new_policy=new_policy,
        action=PolicyAuditAction.REVERT,
        actor=actor,
        comment=comment,
        reverted_from_version=target_version,
    )
    if policy_scope == "system":
        await policy_repo.upsert_system_policy(new_policy)
    else:
        await policy_repo.upsert_project_policy(new_policy)
