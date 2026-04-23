"""
Admin + project-scoped crypto policy endpoints.
"""

from typing import Annotated

from fastapi import Body, Depends, HTTPException, status

from app.api.deps import CurrentUserDep, DatabaseDep, PermissionChecker
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
from app.core.permissions import Permissions
from app.models.crypto_policy import CryptoPolicy
from app.models.user import User
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.crypto_policy import CryptoRule
from app.schemas.policy_audit import PolicyAuditAction
from app.services.audit.history import record_policy_change
from app.services.crypto_policy.resolver import CryptoPolicyResolver

router = CustomAPIRouter(tags=["crypto-policies"])

# Admin dependency — requires system:manage permission
AdminUserDep = Annotated[User, Depends(PermissionChecker(Permissions.SYSTEM_MANAGE))]


@router.get("/crypto-policies/system")
async def get_system_policy(
    current_user: AdminUserDep,
    db: DatabaseDep,
):
    """Get the system-level crypto policy. Admin only."""
    policy = await CryptoPolicyRepository(db).get_system_policy()
    if policy is None:
        raise HTTPException(status_code=404, detail="System policy not seeded")
    return policy.model_dump(by_alias=True)


@router.put("/crypto-policies/system")
async def put_system_policy(
    body: dict = Body(...),
    current_user: AdminUserDep = None,
    db: DatabaseDep = None,
):
    """Replace the system-level crypto policy, bumping the version. Admin only."""
    rules = [CryptoRule.model_validate(r) for r in body.get("rules") or []]
    comment = body.get("comment")
    repo = CryptoPolicyRepository(db)
    existing = await repo.get_system_policy()
    new_version = (existing.version + 1) if existing else 1
    updated_by = getattr(current_user, "id", None)
    if updated_by is not None:
        updated_by = str(updated_by)
    policy = CryptoPolicy(
        scope="system",
        rules=rules,
        version=new_version,
        updated_by=updated_by,
    )
    action = PolicyAuditAction.UPDATE if existing else PolicyAuditAction.CREATE
    await record_policy_change(
        db,
        policy_scope="system",
        project_id=None,
        old_policy=existing,
        new_policy=policy,
        action=action,
        actor=current_user,
        comment=comment,
    )
    await repo.upsert_system_policy(policy)
    return policy.model_dump(by_alias=True)


@router.get("/projects/{project_id}/crypto-policy")
async def get_project_policy(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
):
    """Get the project override policy. Returns a stub with empty rules if none exists."""
    await check_project_access(project_id, current_user, db, required_role="viewer")
    policy = await CryptoPolicyRepository(db).get_project_policy(project_id)
    if policy is None:
        return {"scope": "project", "project_id": project_id, "rules": [], "version": 0}
    return policy.model_dump(by_alias=True)


@router.put("/projects/{project_id}/crypto-policy")
async def put_project_policy(
    project_id: str,
    body: dict = Body(...),
    current_user: CurrentUserDep = None,
    db: DatabaseDep = None,
):
    """Create or replace the project override policy. Project owner or admin only."""
    await check_project_access(project_id, current_user, db, required_role="admin")
    rules = [CryptoRule.model_validate(r) for r in body.get("rules") or []]
    comment = body.get("comment")
    repo = CryptoPolicyRepository(db)
    existing = await repo.get_project_policy(project_id)
    new_version = (existing.version + 1) if existing else 1
    updated_by = getattr(current_user, "id", None)
    if updated_by is not None:
        updated_by = str(updated_by)
    policy = CryptoPolicy(
        scope="project",
        project_id=project_id,
        rules=rules,
        version=new_version,
        updated_by=updated_by,
    )
    action = PolicyAuditAction.UPDATE if existing else PolicyAuditAction.CREATE
    await record_policy_change(
        db,
        policy_scope="project",
        project_id=project_id,
        old_policy=existing,
        new_policy=policy,
        action=action,
        actor=current_user,
        comment=comment,
    )
    await repo.upsert_project_policy(policy)
    return policy.model_dump(by_alias=True)


@router.delete(
    "/projects/{project_id}/crypto-policy",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_project_policy(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
):
    """Delete the project override policy. Project owner or admin only."""
    await check_project_access(project_id, current_user, db, required_role="admin")
    repo = CryptoPolicyRepository(db)
    old_policy = await repo.get_project_policy(project_id)
    new_policy = CryptoPolicy(
        scope="project",
        project_id=project_id,
        rules=[],
        version=(old_policy.version + 1) if old_policy else 1,
    )
    await record_policy_change(
        db,
        policy_scope="project",
        project_id=project_id,
        old_policy=old_policy,
        new_policy=new_policy,
        action=PolicyAuditAction.DELETE,
        actor=current_user,
        comment=None,
    )
    await repo.delete_project_policy(project_id)


@router.get("/projects/{project_id}/crypto-policy/effective")
async def get_effective_policy(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
):
    """Get the effective merged policy for a project (system defaults merged with overrides)."""
    await check_project_access(project_id, current_user, db, required_role="viewer")
    effective = await CryptoPolicyResolver(db).resolve(project_id)
    return {
        "system_version": effective.system_version,
        "override_version": effective.override_version,
        "rules": [r.model_dump() for r in effective.rules],
    }
