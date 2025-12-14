from typing import Optional
from datetime import datetime
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError
from app.core import security
from app.core.config import settings
from app.schemas.token import TokenPayload
from app.models.user import User
from app.models.system import SystemSettings
from app.services.gitlab import GitLabService
from app.db.mongodb import get_database
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")

async def get_system_settings(db: AsyncIOMotorDatabase = Depends(get_database)) -> SystemSettings:
    settings_data = await db.system_settings.find_one({"_id": "current"})
    if settings_data:
        return SystemSettings(**settings_data)
    return SystemSettings()

async def get_current_user(
    db: AsyncIOMotorDatabase = Depends(get_database),
    token: str = Depends(oauth2_scheme)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        username: str = payload.get("sub")
        permissions: list[str] = payload.get("permissions", [])
        if username is None:
            raise credentials_exception
        token_data = TokenPayload(sub=username, permissions=permissions)
    except (JWTError, ValidationError):
        raise credentials_exception
    
    user = await db.users.find_one({"username": token_data.sub})
    if user is None:
        raise credentials_exception
        
    # Check if token was issued before last logout
    if "last_logout_at" in user and user["last_logout_at"]:
        iat = payload.get("iat")
        if iat:
            # iat is unix timestamp, last_logout_at is datetime
            last_logout_ts = user["last_logout_at"].timestamp()
            if iat < last_logout_ts:
                raise credentials_exception

    user_obj = User(**user)
    
    # If token has restricted permissions (e.g. only setup_2fa), override user permissions
    if token_data.permissions and "auth:setup_2fa" in token_data.permissions and len(token_data.permissions) == 1:
        user_obj.permissions = token_data.permissions
        
    return user_obj

async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_project_by_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    if "." not in x_api_key:
        raise HTTPException(status_code=403, detail="Invalid API Key format. Expected 'project_id.secret'")
    
    project_id, secret = x_api_key.split(".", 1)
    
    project_data = await db.projects.find_one({"_id": project_id})
    if not project_data:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    
    stored_hash = project_data.get("api_key_hash")
    if not stored_hash:
        raise HTTPException(status_code=403, detail="Project has no API key set")
        
    if not security.verify_password(secret, stored_hash):
        raise HTTPException(status_code=403, detail="Invalid API Key")
        
    from app.models.project import Project
    return Project(**project_data)

async def get_project_for_ingest(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    ci_job_token: Optional[str] = Header(None, alias="CI-Job-Token"),
    job_token: Optional[str] = Header(None, alias="Job-Token"),
    db: AsyncIOMotorDatabase = Depends(get_database),
    settings: SystemSettings = Depends(get_system_settings)
):
    from app.models.project import Project
    
    # 1. Try API Key
    if x_api_key:
        if "." not in x_api_key:
             raise HTTPException(status_code=403, detail="Invalid API Key format")
        project_id, secret = x_api_key.split(".", 1)
        project_data = await db.projects.find_one({"_id": project_id})
        if not project_data or not project_data.get("api_key_hash"):
             raise HTTPException(status_code=403, detail="Invalid API Key")
        if not security.verify_password(secret, project_data["api_key_hash"]):
             raise HTTPException(status_code=403, detail="Invalid API Key")
        return Project(**project_data)

    # 2. Try GitLab Token
    token = ci_job_token or job_token
    if token:
        if not settings.gitlab_integration_enabled:
             raise HTTPException(status_code=403, detail="GitLab integration is disabled")
        
        gitlab_service = GitLabService(settings)
        job_data = await gitlab_service.validate_job_token(token)
        
        if not job_data:
             raise HTTPException(status_code=403, detail="Invalid GitLab Token")
        
        gitlab_project = job_data.get("project")
        if not gitlab_project:
             raise HTTPException(status_code=403, detail="Could not retrieve project info from GitLab")
             
        gitlab_project_id = gitlab_project["id"]
        
        # Find project by gitlab_project_id
        project_data = await db.projects.find_one({"gitlab_project_id": gitlab_project_id})
        
        if project_data:
            return Project(**project_data)
            
        # Auto-create if enabled
        if settings.gitlab_auto_create_projects:
            # Try to find an owner
            owner_id = None
            
            # Try to match user by email
            gitlab_user = job_data.get("user")
            if gitlab_user and gitlab_user.get("email"):
                 user = await db.users.find_one({"email": gitlab_user["email"]})
                 if user:
                     owner_id = str(user["_id"])
            
            # Fallback to superuser
            if not owner_id:
                admin = await db.users.find_one({"is_superuser": True})
                if admin:
                    owner_id = str(admin["_id"])
            
            if not owner_id:
                 raise HTTPException(status_code=500, detail="Cannot auto-create project: No suitable owner found")

            new_project = Project(
                name=gitlab_project["path_with_namespace"],
                owner_id=owner_id,
                gitlab_project_id=gitlab_project_id,
                gitlab_project_path=gitlab_project["path_with_namespace"],
                default_branch=gitlab_project.get("default_branch")
            )
            
            # Sync Teams/Members if enabled
            if settings.gitlab_sync_teams:
                try:
                    members = await gitlab_service.get_project_members(gitlab_project_id, token)
                    if members:
                        from app.models.team import Team, TeamMember
                        from app.models.user import User
                        import secrets
                        
                        # Create or Update Team
                        team_name = f"GitLab: {gitlab_project['path_with_namespace']}"
                        team = await db.teams.find_one({"name": team_name})
                        
                        team_members = []
                        for member in members:
                            # Skip if no email (bot users?)
                            # GitLab API might not return email for all members depending on visibility
                            # If we can't match by email, we can't sync safely.
                            # Note: /members endpoint often doesn't return email unless you are admin.
                            # We might need to rely on username matching if email is missing, but that's risky.
                            # Let's assume we can get email or username.
                            
                            member_email = member.get("email")
                            member_username = member.get("username")
                            
                            user = None
                            if member_email:
                                user = await db.users.find_one({"email": member_email})
                            elif member_username:
                                user = await db.users.find_one({"username": member_username})
                                
                            if not user and member_email:
                                # Create new user
                                user = User(
                                    username=member_username or member_email.split("@")[0],
                                    email=member_email,
                                    hashed_password=security.get_password_hash(secrets.token_urlsafe(16)),
                                    is_active=True,
                                    auth_provider="gitlab"
                                )
                                await db.users.insert_one(user.dict(by_alias=True))
                                user = user.dict(by_alias=True)
                            
                            if user:
                                # Map GitLab access level to role
                                # 10: Guest, 20: Reporter, 30: Developer, 40: Maintainer, 50: Owner
                                access_level = member.get("access_level", 0)
                                role = "member"
                                if access_level >= 40:
                                    role = "admin"
                                
                                team_members.append(TeamMember(user_id=str(user["_id"]), role=role))

                        if team:
                            await db.teams.update_one(
                                {"_id": team["_id"]},
                                {"$set": {"members": [tm.dict() for tm in team_members], "updated_at": datetime.utcnow()}}
                            )
                            new_project.team_id = str(team["_id"])
                        elif team_members:
                            new_team = Team(
                                name=team_name,
                                description=f"Imported from GitLab Project {gitlab_project['path_with_namespace']}",
                                members=team_members
                            )
                            await db.teams.insert_one(new_team.dict(by_alias=True))
                            new_project.team_id = str(new_team.id)

                except Exception as e:
                    print(f"Error syncing GitLab teams: {e}")
                    # Continue creating project even if team sync fails

            await db.projects.insert_one(new_project.dict(by_alias=True))
            return new_project
            
        raise HTTPException(status_code=404, detail="Project not found and auto-creation disabled")

    raise HTTPException(status_code=401, detail="Missing authentication credentials")

