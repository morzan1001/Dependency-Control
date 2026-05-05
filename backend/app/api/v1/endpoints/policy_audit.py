"""
Policy audit endpoints — list / detail / revert / prune.

System scope: admin only.
Project scope: member for reads, owner/admin for writes.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import Body, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_active_user, get_database
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
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


# ---------- SYSTEM SCOPE ----------


@router.get("/crypto-policies/system/audit")
async def list_system_audit(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> dict[str, Any]:
    _require_admin(current_user)
    entries = await PolicyAuditRepository(db).list(
        policy_scope="system",
        skip=skip,
        limit=limit,
    )
    return {"entries": [e.model_dump(by_alias=True) for e in entries]}


@router.get("/crypto-policies/system/audit/{version}")
async def get_system_audit_entry(
    version: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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


@router.post("/crypto-policies/system/revert")
async def revert_system_policy(
    body: dict = Body(...),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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


@router.delete("/crypto-policies/system/audit")
async def prune_system_audit(
    before: str = Query(..., description="Delete entries older than this ISO date"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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


# ---------- PROJECT SCOPE ----------


@router.get("/projects/{project_id}/crypto-policy/audit")
async def list_project_audit(
    project_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> dict[str, Any]:
    await check_project_access(project_id, current_user, db, required_role="viewer")
    entries = await PolicyAuditRepository(db).list(
        policy_scope="project",
        project_id=project_id,
        skip=skip,
        limit=limit,
    )
    return {"entries": [e.model_dump(by_alias=True) for e in entries]}


@router.get("/projects/{project_id}/crypto-policy/audit/{version}")
async def get_project_audit_entry(
    project_id: str,
    version: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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


@router.post("/projects/{project_id}/crypto-policy/revert")
async def revert_project_policy(
    project_id: str,
    body: dict = Body(...),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> dict[str, Any]:
    # Note: "owner" isn't a project role — PROJECT_ROLES = viewer|editor|admin.
    # The previous string crashed check_project_access with ValueError.
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


@router.delete("/projects/{project_id}/crypto-policy/audit")
async def prune_project_audit(
    project_id: str,
    before: str = Query(...),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> dict[str, Any]:
    # Same "owner" -> "admin" normalisation as revert_project_policy above.
    await check_project_access(project_id, current_user, db, required_role="admin")
    cutoff = _parse_datetime(before)
    _enforce_min_prune_cutoff(cutoff)
    deleted = await PolicyAuditRepository(db).delete_older_than(
        policy_scope="project",
        project_id=project_id,
        cutoff=cutoff,
    )
    return {"deleted": deleted}


# ---------- LICENSE POLICY AUDIT (PROJECT SCOPE ONLY) ----------


@router.get("/projects/{project_id}/license-policy/audit")
async def list_project_license_audit(
    project_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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


@router.get("/projects/{project_id}/license-policy/audit/{version}")
async def get_project_license_audit_entry(
    project_id: str,
    version: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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


# NOTE: revert/prune for license-policy audit is intentionally deferred:
#   * revert would need to overwrite project.license_policy and/or
#     project.analyzer_settings['license_compliance'] — a merge with other
#     analyzer settings is non-trivial (stomping peer settings would be a bug).
#   * prune reuses the min-cutoff guard from crypto; when revert ships we'll
#     add the matching DELETE endpoint with policy_type='license'.


# ---------- HELPERS ----------


def _parse_datetime(value: str) -> datetime:
    """Parse an ISO-8601 datetime string, tolerating space-encoded '+' from URLs."""
    # When '+00:00' is embedded in a raw URL, the '+' becomes a space in the
    # query string. Restore it before parsing.
    value = value.replace(" ", "+")
    return datetime.fromisoformat(value)


def _min_prune_days() -> int:
    """Return the configured minimum prune age in days from settings."""
    return settings.POLICY_AUDIT_MIN_PRUNE_DAYS


def _enforce_min_prune_cutoff(cutoff: datetime) -> None:
    """Reject prune requests that would delete recent audit history.

    ``cutoff`` is the boundary passed as ``?before=``; entries older than
    it are deleted. The cutoff itself must be at least
    ``_min_prune_days`` in the past so recent forensic evidence is never
    destroyed by an overly-aggressive prune.
    """
    days = _min_prune_days()
    # Use UTC and normalise the cutoff in case the client sends a naive
    # timestamp (rare but permitted by datetime.fromisoformat).
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
