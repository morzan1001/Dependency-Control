"""
Policy audit endpoints — list / detail / revert / prune.

System scope: admin only.
Project scope: member for reads, owner/admin for writes.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from app.api.deps import get_current_active_user, get_database
from app.api.v1.helpers.projects import check_project_access
from app.models.crypto_policy import CryptoPolicy
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.crypto_policy import CryptoRule
from app.schemas.policy_audit import PolicyAuditAction
from app.services.audit.history import record_policy_change

router = APIRouter(tags=["policy-audit"])


# ---------- SYSTEM SCOPE ----------


@router.get("/crypto-policies/system/audit")
async def list_system_audit(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user=Depends(get_current_active_user),
    db=Depends(get_database),
):
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
    current_user=Depends(get_current_active_user),
    db=Depends(get_database),
):
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
    current_user=Depends(get_current_active_user),
    db=Depends(get_database),
):
    _require_admin(current_user)
    target_version = int(body.get("target_version"))
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
    return policy.model_dump(by_alias=True)


@router.delete("/crypto-policies/system/audit")
async def prune_system_audit(
    before: str = Query(..., description="Delete entries older than this ISO date"),
    current_user=Depends(get_current_active_user),
    db=Depends(get_database),
):
    _require_admin(current_user)
    cutoff = _parse_datetime(before)
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
    current_user=Depends(get_current_active_user),
    db=Depends(get_database),
):
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
    current_user=Depends(get_current_active_user),
    db=Depends(get_database),
):
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
    current_user=Depends(get_current_active_user),
    db=Depends(get_database),
):
    await check_project_access(project_id, current_user, db, required_role="owner")
    target_version = int(body.get("target_version"))
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
    current_user=Depends(get_current_active_user),
    db=Depends(get_database),
):
    await check_project_access(project_id, current_user, db, required_role="owner")
    cutoff = _parse_datetime(before)
    deleted = await PolicyAuditRepository(db).delete_older_than(
        policy_scope="project",
        project_id=project_id,
        cutoff=cutoff,
    )
    return {"deleted": deleted}


# ---------- HELPERS ----------


def _parse_datetime(value: str) -> datetime:
    """Parse an ISO-8601 datetime string, tolerating space-encoded '+' from URLs."""
    # When '+00:00' is embedded in a raw URL, the '+' becomes a space in the
    # query string. Restore it before parsing.
    value = value.replace(" ", "+")
    return datetime.fromisoformat(value)


def _require_admin(user) -> None:
    perms = getattr(user, "permissions", frozenset()) or frozenset()
    if "system:manage" not in perms:
        raise HTTPException(status_code=403, detail="system:manage permission required")


async def _revert_policy(
    *,
    db,
    actor,
    policy_scope: str,
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
    if policy_scope == "system":
        current = await policy_repo.get_system_policy()
    else:
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
