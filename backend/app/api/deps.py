from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError
from app.core import security
from app.core.config import settings
from app.schemas.token import TokenPayload
from app.models.user import User
from app.db.mongodb import get_database
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")

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
        if username is None:
            raise credentials_exception
        token_data = TokenPayload(sub=username)
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

    return User(**user)

async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_project_by_api_key(
    x_api_key: str = Header(...),
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

