import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal

from fastapi import HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BeforeValidator, ValidationError

from app.api.deps import SystemManagerDep, CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access, ensure_crypto_overrides_writable
from app.api.v1.helpers.responses import (
    RESP_400_403,
    RESP_400_403_404,
    RESP_403,
    RESP_403_404,
)
from app.api.v1.helpers.users import resolve_usernames
from app.core import ensure_utc
from app.core.config import settings
from app.core.constants import MAX_POLICY_AUDIT_PAGE, PROJECT_ROLE_ADMIN
from app.models.crypto_policy import CryptoPolicy
from app.models.policy_audit_entry import PolicyAuditEntry, PolicyType
from app.models.user import User
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.crypto_policy import CryptoPolicyPutRequest
from app.models.policy_audit_entry import PolicyAuditAction
from app.schemas.policy_audit import PolicyRevertRequest
from app.services.crypto_policy.seeder import write_policy


router = CustomAPIRouter(tags=["policy-audit"])

# An unencoded '+HH:MM' offset arrives with its '+' decoded to a space.
_SPACE_DECODED_OFFSET = re.compile(r"(:\d\d(?:\.\d+)?) (\d\d:?\d\d)$")
PruneCutoff = Annotated[
    datetime,
    BeforeValidator(lambda v: _SPACE_DECODED_OFFSET.sub(r"\1+\2", v) if isinstance(v, str) else v),
    Query(description="Delete entries older than this ISO-8601 datetime"),
]


async def _with_actor_names(db: AsyncIOMotorDatabase, entries: list[PolicyAuditEntry]) -> list[dict[str, Any]]:
    rows = [entry.model_dump(by_alias=True) for entry in entries]
    return await resolve_usernames(db, rows, "actor_display_name", id_field="actor_user_id")


async def _list_entries(
    db: AsyncIOMotorDatabase,
    *,
    policy_scope: Literal["system", "project"],
    project_id: str | None,
    policy_type: PolicyType,
    skip: int,
    limit: int,
) -> dict[str, Any]:
    entries = await PolicyAuditRepository(db).list(
        policy_scope=policy_scope, project_id=project_id, policy_type=policy_type, skip=skip, limit=limit
    )
    return {"entries": await _with_actor_names(db, entries)}


async def _get_entry(
    db: AsyncIOMotorDatabase,
    *,
    policy_scope: Literal["system", "project"],
    project_id: str | None,
    version: int,
    policy_type: PolicyType,
) -> PolicyAuditEntry:
    entry = await PolicyAuditRepository(db).get_by_version(
        policy_scope=policy_scope, project_id=project_id, version=version, policy_type=policy_type
    )
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Version {version} not found")
    return entry


@router.get("/crypto-policies/system/audit", responses=RESP_403)
async def list_system_audit(
    current_user: SystemManagerDep,
    db: DatabaseDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_POLICY_AUDIT_PAGE),
) -> dict[str, Any]:
    return await _list_entries(db, policy_scope="system", project_id=None, policy_type="crypto", skip=skip, limit=limit)


@router.get("/crypto-policies/system/audit/{version}", responses=RESP_403_404)
async def get_system_audit_entry(
    version: int,
    current_user: SystemManagerDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    entry = await _get_entry(db, policy_scope="system", project_id=None, version=version, policy_type="crypto")
    return (await _with_actor_names(db, [entry]))[0]


@router.post("/crypto-policies/system/revert", responses=RESP_400_403_404)
async def revert_system_policy(
    current_user: SystemManagerDep,
    db: DatabaseDep,
    body: PolicyRevertRequest,
) -> dict[str, Any]:
    policy = await _revert_policy(
        db=db,
        actor=current_user,
        policy_scope="system",
        project_id=None,
        target_version=body.target_version,
        comment=body.comment,
    )
    return policy.model_dump(by_alias=True)


@router.delete("/crypto-policies/system/audit", responses=RESP_400_403)
async def prune_system_audit(
    current_user: SystemManagerDep,
    db: DatabaseDep,
    before: PruneCutoff,
) -> dict[str, Any]:
    _enforce_min_prune_cutoff(before)
    deleted = await PolicyAuditRepository(db).delete_older_than(
        policy_scope="system",
        project_id=None,
        cutoff=before,
        policy_type="crypto",
    )
    return {"deleted": deleted}


@router.get("/projects/{project_id}/crypto-policy/audit", responses=RESP_403_404)
async def list_project_audit(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_POLICY_AUDIT_PAGE),
) -> dict[str, Any]:
    await check_project_access(project_id, current_user, db)
    return await _list_entries(
        db, policy_scope="project", project_id=project_id, policy_type="crypto", skip=skip, limit=limit
    )


@router.get("/projects/{project_id}/crypto-policy/audit/{version}", responses=RESP_403_404)
async def get_project_audit_entry(
    project_id: str,
    version: int,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    await check_project_access(project_id, current_user, db)
    entry = await _get_entry(db, policy_scope="project", project_id=project_id, version=version, policy_type="crypto")
    return (await _with_actor_names(db, [entry]))[0]


@router.post("/projects/{project_id}/crypto-policy/revert", responses=RESP_400_403_404)
async def revert_project_policy(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    body: PolicyRevertRequest,
) -> dict[str, Any]:
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
    await ensure_crypto_overrides_writable(db)
    policy = await _revert_policy(
        db=db,
        actor=current_user,
        policy_scope="project",
        project_id=project_id,
        target_version=body.target_version,
        comment=body.comment,
    )
    return policy.model_dump(by_alias=True)


@router.delete("/projects/{project_id}/crypto-policy/audit", responses=RESP_400_403_404)
async def prune_project_audit(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    before: PruneCutoff,
) -> dict[str, Any]:
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
    _enforce_min_prune_cutoff(before)
    deleted = await PolicyAuditRepository(db).delete_older_than(
        policy_scope="project",
        project_id=project_id,
        cutoff=before,
        policy_type="crypto",
    )
    return {"deleted": deleted}


@router.get("/projects/{project_id}/license-policy/audit", responses=RESP_403_404)
async def list_project_license_audit(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_POLICY_AUDIT_PAGE),
) -> dict[str, Any]:
    """List license-policy audit entries for a project (viewer+ role)."""
    await check_project_access(project_id, current_user, db)
    return await _list_entries(
        db, policy_scope="project", project_id=project_id, policy_type="license", skip=skip, limit=limit
    )


@router.get("/projects/{project_id}/license-policy/audit/{version}", responses=RESP_403_404)
async def get_project_license_audit_entry(
    project_id: str,
    version: int,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Fetch a single license-policy audit entry by version."""
    await check_project_access(project_id, current_user, db)
    entry = await _get_entry(db, policy_scope="project", project_id=project_id, version=version, policy_type="license")
    return (await _with_actor_names(db, [entry]))[0]


# No license-policy revert/prune: overwriting license settings needs a merge with peer analyzer settings.


def _enforce_min_prune_cutoff(cutoff: datetime) -> None:
    """Reject prune requests whose cutoff is too recent, preserving forensic history."""
    days = settings.POLICY_AUDIT_MIN_PRUNE_DAYS
    min_age_boundary = datetime.now(timezone.utc) - timedelta(days=days)
    if ensure_utc(cutoff) > min_age_boundary:
        raise HTTPException(
            status_code=400,
            detail=(f"before must be at least {days} days in the past to preserve forensic history"),
        )


async def _revert_policy(
    *,
    db: AsyncIOMotorDatabase,
    actor: User,
    policy_scope: Literal["system", "project"],
    project_id: str | None,
    target_version: int,
    comment: str | None,
) -> CryptoPolicy:
    target_entry = await _get_entry(
        db, policy_scope=policy_scope, project_id=project_id, version=target_version, policy_type="crypto"
    )

    try:
        rules = CryptoPolicyPutRequest(rules=target_entry.snapshot.get("rules", [])).rules
    except ValidationError as exc:
        reasons = "; ".join(
            f"{'.'.join(map(str, error['loc'])) or 'rules'}: {error['msg'].removeprefix('Value error, ')}"
            for error in exc.errors()
        )
        raise HTTPException(
            status_code=422, detail=f"Version {target_version} holds rules a write would refuse: {reasons}"
        ) from exc

    policy = await write_policy(
        db,
        scope=policy_scope,
        project_id=project_id,
        rules=rules,
        action=PolicyAuditAction.REVERT,
        actor=actor,
        comment=comment,
        reverted_from_version=target_version,
    )
    if policy is None:
        raise HTTPException(status_code=500, detail="Crypto policy write returned no policy")
    return policy
