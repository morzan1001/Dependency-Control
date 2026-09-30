"""Admin + project-scoped crypto policy endpoints."""

from typing import Any

from fastapi import HTTPException, status

from app.api.deps import CurrentUserDep, DatabaseDep, SystemManagerDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access, ensure_crypto_overrides_writable
from app.api.v1.helpers.responses import RESP_404
from app.core.constants import PROJECT_ROLE_ADMIN
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.crypto_policy import CryptoPolicyPutRequest
from app.schemas.policy_audit import PolicyAuditAction
from app.services.crypto_policy.resolver import CryptoPolicyResolver
from app.services.crypto_policy.seeder import write_policy

router = CustomAPIRouter(tags=["crypto-policies"])


@router.get("/crypto-policies/system", responses=RESP_404)
async def get_system_policy(
    current_user: SystemManagerDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Get the system-level crypto policy."""
    policy = await CryptoPolicyRepository(db).get_system_policy()
    if policy is None:
        raise HTTPException(status_code=404, detail="System crypto policy not found")
    return policy.model_dump(by_alias=True)


@router.put("/crypto-policies/system")
async def put_system_policy(
    current_user: SystemManagerDep,
    db: DatabaseDep,
    body: CryptoPolicyPutRequest,
) -> dict[str, Any]:
    """Replace the system-level crypto policy, bumping the version. Admin only."""
    policy = await write_policy(
        db,
        scope="system",
        project_id=None,
        rules=body.rules,
        action=PolicyAuditAction.UPDATE,
        actor=current_user,
        comment=body.comment,
    )
    if policy is None:
        raise HTTPException(status_code=500, detail="Crypto policy write returned no policy")
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
    await ensure_crypto_overrides_writable(db)
    policy = await write_policy(
        db,
        scope="project",
        project_id=project_id,
        rules=body.rules,
        action=PolicyAuditAction.UPDATE,
        actor=current_user,
        comment=body.comment,
    )
    if policy is None:
        raise HTTPException(status_code=500, detail="Crypto policy write returned no policy")
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
    await ensure_crypto_overrides_writable(db)
    await write_policy(
        db, scope="project", project_id=project_id, rules=None, action=PolicyAuditAction.DELETE, actor=current_user
    )


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
