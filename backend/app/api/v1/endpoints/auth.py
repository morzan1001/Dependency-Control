from datetime import timedelta, datetime
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Body, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from motor.motor_asyncio import AsyncIOMotorDatabase
from jose import jwt, JWTError
from pydantic import ValidationError
import pyotp
import httpx
import secrets
from urllib.parse import urlencode

from app.core import security
from app.core.config import settings
from app.db.mongodb import get_database
from app.schemas.token import Token, TokenPayload
from app.models.user import User
from app.schemas.user import UserCreate, User as UserSchema, UserSignup, UserPasswordReset
from app.api import deps
from app.services.notifications.email_provider import EmailProvider
from app.services.notifications.templates import get_verification_email_template
from app.models.system import SystemSettings

router = APIRouter()

async def get_system_settings(db: AsyncIOMotorDatabase) -> SystemSettings:
    data = await db.system_settings.find_one({"_id": "current"})
    if not data:
        return SystemSettings()
    return SystemSettings(**data)

@router.post("/login/access-token", response_model=Token, summary="Login to get access token")
async def login_access_token(
    db: AsyncIOMotorDatabase = Depends(get_database),
    form_data: OAuth2PasswordRequestForm = Depends(),
    otp: Optional[str] = Form(None)
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.
    
    - **username**: Email or username
    - **password**: User password
    - **otp**: One Time Password (if 2FA is enabled)
    """
    user = await db.users.find_one({"username": form_data.username})
    if not user or not security.verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )
    
    system_config = await get_system_settings(db)

    # Check Email Verification
    if system_config.enforce_email_verification and not user.get("is_verified", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check 2FA
    if user.get("totp_enabled", False):
        if not otp:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="2FA required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(otp, valid_window=1):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OTP code",
                headers={"WWW-Authenticate": "Bearer"},
            )
        permissions = user.get("permissions", [])
    elif system_config.enforce_2fa:
        # User has no 2FA but it is enforced -> Issue limited token for setup
        permissions = ["auth:setup_2fa"]
    else:
        permissions = user.get("permissions", [])
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
    access_token = security.create_access_token(
        user["username"], 
        permissions=permissions,
        expires_delta=access_token_expires
    )
    
    refresh_token = security.create_refresh_token(
        user["username"]
    )
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/signup", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
async def signup(
    user_in: UserSignup,
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Signup a new user.
    """
    system_config = await get_system_settings(db)
    signup_enabled = system_config.allow_public_registration
    
    if not signup_enabled:
        raise HTTPException(
            status_code=403,
            detail="Open registration is forbidden on this server",
        )

    user = await db.users.find_one({"username": user_in.username})
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system.",
        )
    
    user_email = await db.users.find_one({"email": user_in.email})
    if user_email:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )
    
    user_dict = user_in.dict()
    hashed_password = security.get_password_hash(user_dict.pop("password"))
    user_dict["hashed_password"] = hashed_password
    user_dict["is_active"] = True
    user_dict["permissions"] = [] # No permissions by default
    
    new_user = User(**user_dict)
    await db.users.insert_one(new_user.dict(by_alias=True))
    return new_user

@router.post("/login/refresh-token", response_model=Token, summary="Refresh access token")
async def refresh_token(
    refresh_token: str = Body(..., embed=True, description="The refresh token obtained during login"),
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Get a new access token using a valid refresh token.
    """
    try:
        payload = jwt.decode(
            refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
        
    if token_data.type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token type",
        )
        
    user = await db.users.find_one({"username": token_data.sub})
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )
        
    # Check if refresh token was issued before last logout
    if "last_logout_at" in user and user["last_logout_at"]:
        iat = payload.get("iat")
        if iat:
            last_logout_ts = user["last_logout_at"].timestamp()
            if iat < last_logout_ts:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Token revoked",
                )
        
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    permissions = user.get("permissions", [])

    access_token = security.create_access_token(
        user["username"], 
        permissions=permissions,
        expires_delta=access_token_expires
    )
    
    # Optionally rotate refresh token here
    new_refresh_token = security.create_refresh_token(
        user["username"]
    )
    
    return {
        "access_token": access_token, 
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@router.post("/signup", response_model=UserSchema, summary="Register a new user")
async def create_user(
    user_in: UserCreate,
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Create a new user in the system.
    """
    # Check if signup is enabled
    system_config = await get_system_settings(db)
    signup_enabled = system_config.allow_public_registration
    
    if not signup_enabled:
        raise HTTPException(
            status_code=403,
            detail="Signup is currently disabled.",
        )

    user = await db.users.find_one({"username": user_in.username})
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system.",
        )
    user_dict = user_in.dict()
    hashed_password = security.get_password_hash(user_dict.pop("password"))
    user_dict["hashed_password"] = hashed_password
    user_dict["is_verified"] = False
    
    new_user = User(**user_dict)
    await db.users.insert_one(new_user.dict(by_alias=True))
    
    # Send verification email if SMTP is configured
    if settings.SMTP_HOST:
        token = security.create_email_verification_token(new_user.email)
        
        email_provider = EmailProvider()
        link = f"{settings.FRONTEND_BASE_URL}/verify-email?token={token}"
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_dir, "../../../../.."))
        logo_path = os.path.join(project_root, "assets", "logo.png")
        
        html_content = get_verification_email_template(link, settings.PROJECT_NAME)
        await email_provider.send(
            destination=new_user.email,
            subject=f"Verify your email for {settings.PROJECT_NAME}",
            message=f"Please verify your email by clicking this link: {link}",
            html_message=html_content,
            logo_path=logo_path
        )

    return new_user

@router.post("/logout", summary="Logout user")
async def logout(
    current_user: User = Depends(deps.get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Logout the current user.
    Invalidates all tokens issued before this logout by updating the user's last_logout_at timestamp.
    """
    await db.users.update_one(
        {"_id": current_user.id},
        {"$set": {"last_logout_at": datetime.utcnow()}}
    )
    return {"message": "Successfully logged out"}

@router.post("/send-verification-email", summary="Send verification email")
async def send_verification_email(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Send a new verification email to the current user.
    """
    if current_user.is_verified:
        raise HTTPException(
            status_code=400,
            detail="Email already verified",
        )
        
    if not settings.SMTP_HOST:
        raise HTTPException(
            status_code=501,
            detail="Email server not configured",
        )
        
    token = security.create_email_verification_token(current_user.email)
    link = f"{settings.FRONTEND_BASE_URL}/verify-email?token={token}"
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "../../../../.."))
    logo_path = os.path.join(project_root, "assets", "logo.png")
    
    html_content = get_verification_email_template(link, settings.PROJECT_NAME)
    email_provider = EmailProvider()
    await email_provider.send(
        destination=current_user.email,
        subject=f"Verify your email for {settings.PROJECT_NAME}",
        message=f"Please verify your email by clicking this link: {link}",
        html_message=html_content,
        logo_path=logo_path
    )
    
    return {"message": "Verification email sent"}

@router.get("/verify-email", summary="Verify email address")
async def verify_email(
    token: str,
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Verify email address using the token sent via email.
    """
    email = security.verify_email_verification_token(token)
    if not email:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification token",
        )
        
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )
        
    if user.get("is_verified"):
        return {"message": "Email already verified"}
        
    await db.users.update_one(
        {"email": email},
        {"$set": {"is_verified": True}}
    )
    
    return {"message": "Email successfully verified"}

@router.post("/resend-verification", summary="Resend verification email (Public)")
async def resend_verification_email_public(
    email: str = Body(..., embed=True),
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Resend verification email to the user with the given email address.
    This endpoint is public to allow unverified users to request a new token.
    """
    user = await db.users.find_one({"email": email})
    if not user:
        # Return success even if user not found to prevent email enumeration
        return {"message": "If an account with this email exists, a verification email has been sent."}
        
    if user.get("is_verified"):
        return {"message": "Email already verified"}
        
    if not settings.SMTP_HOST:
        raise HTTPException(
            status_code=501,
            detail="Email server not configured",
        )
        
    token = security.create_email_verification_token(user["email"])
    link = f"{settings.FRONTEND_BASE_URL}/verify-email?token={token}"
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "../../../../.."))
    logo_path = os.path.join(project_root, "assets", "logo.png")
    
    html_content = get_verification_email_template(link, settings.PROJECT_NAME)
    email_provider = EmailProvider()
    await email_provider.send(
        destination=user["email"],
        subject=f"Verify your email for {settings.PROJECT_NAME}",
        message=f"Please verify your email by clicking this link: {link}",
        html_message=html_content,
        logo_path=logo_path,
        system_settings=system_config
    )
    
    return {"message": "If an account with this email exists, a verification email has been sent."}


@router.get("/login/oidc/authorize")
async def login_oidc_authorize(
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    system_config = await get_system_settings(db)
    if not system_config.oidc_enabled:
        raise HTTPException(status_code=400, detail="OIDC is not enabled")
    
    if not system_config.oidc_client_id or not system_config.oidc_authorization_endpoint:
        raise HTTPException(status_code=500, detail="OIDC is not properly configured")

    # Construct redirect URI (callback to backend)
    redirect_uri = str(request.url_for("login_oidc_callback"))
    
    # Generate state to prevent CSRF
    state = secrets.token_urlsafe(32)
    
    params = {
        "client_id": system_config.oidc_client_id,
        "response_type": "code",
        "scope": system_config.oidc_scopes,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    
    url = f"{system_config.oidc_authorization_endpoint}?{urlencode(params)}"
    return RedirectResponse(url)

@router.get("/login/oidc/callback")
async def login_oidc_callback(
    request: Request,
    code: str,
    state: Optional[str] = None,
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    system_config = await get_system_settings(db)
    if not system_config.oidc_enabled:
        raise HTTPException(status_code=400, detail="OIDC is not enabled")

    redirect_uri = str(request.url_for("login_oidc_callback"))
    
    token_data = {
        "client_id": system_config.oidc_client_id,
        "client_secret": system_config.oidc_client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    
    async with httpx.AsyncClient() as client:
        # Exchange code for token
        response = await client.post(system_config.oidc_token_endpoint, data=token_data)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve token from provider")
        
        tokens = response.json()
        access_token = tokens.get("access_token")
        
        # Get user info
        user_info_response = await client.get(
            system_config.oidc_userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if user_info_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve user info")
            
        user_info = user_info_response.json()
        
    email = user_info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email not provided by OIDC provider")
        
    # Find or create user
    user = await db.users.find_one({"email": email})
    if not user:
        # Create new user
        user_in = UserCreate(
            email=email,
            username=user_info.get("preferred_username", email.split("@")[0]),
            password=secrets.token_urlsafe(32), # Random password
            full_name=user_info.get("name"),
            is_active=True,
            is_verified=True, # Trusted provider
            auth_provider=system_config.oidc_provider_name
        )
        user_data = user_in.dict()
        user_data["hashed_password"] = security.get_password_hash(user_data["password"])
        del user_data["password"]
        user_data["created_at"] = datetime.utcnow()
        user_data["permissions"] = [] # Default permissions
        
        result = await db.users.insert_one(user_data)
        user = await db.users.find_one({"_id": result.inserted_id})
    
    # Check 2FA enforcement (same logic as login)
    permissions = user.get("permissions", [])
    if system_config.enforce_2fa and not user.get("totp_enabled", False):
        permissions = ["auth:setup_2fa"]
        
    # Create tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        user["username"], 
        permissions=permissions,
        expires_delta=access_token_expires
    )
    refresh_token = security.create_refresh_token(user["username"])
    
    # Redirect to frontend with tokens
    # We'll use a hash fragment to pass the tokens securely
    frontend_url = f"{settings.FRONTEND_BASE_URL}/login/callback#access_token={access_token}&refresh_token={refresh_token}"
    
    return RedirectResponse(frontend_url)


@router.post("/reset-password", summary="Reset password with token")
async def reset_password(
    reset_in: UserPasswordReset,
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Reset password using the token received via email.
    """
    email = security.verify_password_reset_token(reset_in.token)
    if not email:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )
        
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )
        
    hashed_password = security.get_password_hash(reset_in.new_password)
    
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"hashed_password": hashed_password}}
    )
    
    return {"message": "Password successfully reset"}


