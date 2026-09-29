"""Admin + project-scoped crypto policy endpoints."""

from typing import Any

from fastapi import HTTPException, status

from app.api.deps import CurrentUserDep, DatabaseDep, SystemManagerDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_500
from app.core.constants import PROJECT_ROLE_ADMIN, SETTINGS_MODE_GLOBAL
from app.models.crypto_policy import CryptoPolicy
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.crypto_policy import CryptoPolicyPutRequest
from app.schemas.policy_audit import PolicyAuditAction
from app.services.audit.history import record_policy_change
from app.services.crypto_policy.resolver import CryptoPolicyResolver
from app.services.crypto_policy.seeder import seed_crypto_policies

router = CustomAPIRouter(tags=["crypto-policies"])


@router.get("/crypto-policies/system", responses=RESP_500)
async def get_system_policy(
    current_user: SystemManagerDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Get the system-level crypto policy. Seeds defaults on first access if missing."""
    repo = CryptoPolicyRepository(db)
    policy = await repo.get_system_policy()
    if policy is None:
        await seed_crypto_policies(db)
        policy = await repo.get_system_policy()
    if policy is None:
        raise HTTPException(status_code=500, detail="Failed to initialize system policy")
    return policy.model_dump(by_alias=True)


@router.put("/crypto-policies/system")
async def put_system_policy(
    current_user: SystemManagerDep,
    db: DatabaseDep,
    body: CryptoPolicyPutRequest,
) -> dict[str, Any]:
    """Replace the system-level crypto policy, bumping the version. Admin only."""
    rules = body.rules
    comment = body.comment
    repo = CryptoPolicyRepository(db)
    existing = await repo.get_system_policy()
    new_version = (existing.version + 1) if existing else 1
    policy = CryptoPolicy(
        scope="system",
        rules=rules,
        version=new_version,
        updated_by=current_user.id,
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
) -> dict[str, Any]:
    """Get the project override policy. Returns a stub with empty rules if none exists."""
    await check_project_access(project_id, current_user, db)
    policy = await CryptoPolicyRepository(db).get_project_policy(project_id)
    if policy is None:
        return {"scope": "project", "project_id": project_id, "rules": [], "version": 0}
    return policy.model_dump(by_alias=True)


@router.put("/projects/{project_id}/crypto-policy")
async def put_project_policy(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    body: CryptoPolicyPutRequest,
) -> dict[str, Any]:
    """Create or replace the project override policy. Project owner or admin only."""
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
    settings = await SystemSettingsRepository(db).get()
    if settings.crypto_policy_mode == SETTINGS_MODE_GLOBAL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="System enforces a global crypto policy; project overrides are disabled.",
        )
    rules = body.rules
    comment = body.comment
    repo = CryptoPolicyRepository(db)
    existing = await repo.get_project_policy(project_id)
    new_version = (existing.version + 1) if existing else 1
    policy = CryptoPolicy(
        scope="project",
        project_id=project_id,
        rules=rules,
        version=new_version,
        updated_by=current_user.id,
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
) -> None:
    """Delete the project override policy. Project owner or admin only."""
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
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
) -> dict[str, Any]:
    """Get the effective merged policy for a project (system defaults merged with overrides)."""
    await check_project_access(project_id, current_user, db)
    effective = await CryptoPolicyResolver(db).resolve(project_id)
    return {
        "system_version": effective.system_version,
        "override_version": effective.override_version,
        "override_locked": effective.override_locked,
        "rules": [r.model_dump() for r in effective.rules],
        "system_rules": [r.model_dump() for r in effective.system_rules],
    }
