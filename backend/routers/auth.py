# ============================================
# SentinelAI - Authentication Router
# ============================================
"""
Authentication endpoints:
- POST /api/auth/register - Register new organization + admin user
- POST /api/auth/login - Login and get JWT tokens
- POST /api/auth/refresh - Refresh access token
- GET /api/auth/me - Get current user info
"""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext
from jose import JWTError, jwt

from config import settings
from database import get_db
from models.user import User
from models.organization import Organization
from utils.crypto_utils import generate_api_key as _generate_api_key

logger = logging.getLogger(__name__)
router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


# --- Pydantic Schemas ---

class RegisterRequest(BaseModel):
    organization_name: str = Field(..., min_length=1, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    description: Optional[str] = None
    website: Optional[str] = None
    contact_email: Optional[EmailStr] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


class UserInfoResponse(BaseModel):
    id: str
    email: str
    role: str
    org_id: str
    org_name: str


# --- Helper Functions ---

def hash_api_key(api_key: str) -> str:
    """Hash an API key using SHA-256."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_api_key() -> str:
    """Generate a new random API key. Delegates to utils.crypto_utils."""
    # Bug #30 fixed: single canonical implementation lives in utils.crypto_utils.
    return _generate_api_key(prefix="sent")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict):
    """Create a JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_token(token: str, expected_type: str = "access") -> dict:
    """Verify and decode a JWT token, enforcing the expected token type."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        # Bug #23 fixed: refresh tokens must NOT be accepted as access tokens.
        # Callers pass the expected type so mismatches are caught explicitly.
        token_type = payload.get("type")
        if token_type != expected_type:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid token type: expected '{expected_type}', got '{token_type}'",
            )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get the current authenticated user from JWT access token."""
    # Bug #23 fixed: explicitly require type='access' — refresh tokens are rejected.
    payload = verify_token(credentials.credentials, expected_type="access")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    
    return user


async def get_current_user_optional(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Get current user if token provided, else None."""
    if not authorization:
        return None
    try:
        scheme, token = authorization.split(" ", 1)
        if scheme.lower() != "bearer":
            return None
        payload = verify_token(token)
        user_id = payload.get("sub")
        if not user_id:
            return None
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()
    except Exception:
        return None


# --- Endpoints ---

@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    Register a new organization with an admin user.
    Returns JWT access and refresh tokens.
    """
    # Check if email already exists
    result = await db.execute(select(User).where(User.email == request.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if organization name exists
    result = await db.execute(select(Organization).where(Organization.name == request.organization_name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Organization name already taken")
    
    # Generate API key for organization
    raw_api_key = generate_api_key()
    api_key_hash = hash_api_key(raw_api_key)
    
    # Create organization
    org = Organization(
        name=request.organization_name,
        api_key_hash=api_key_hash,
        description=request.description,
        website=request.website,
        contact_email=request.contact_email or request.email,
        plan="free",
    )
    db.add(org)
    await db.flush()  # Get org.id
    
    # Create admin user
    user = User(
        org_id=org.id,
        email=request.email,
        password_hash=get_password_hash(request.password),
        role="admin",
        is_active=True,
    )
    db.add(user)
    await db.flush()  # Get user.id
    
    # Update org with API key hash (already set)
    await db.commit()
    
    logger.info(f"New organization registered: {org.name} (id={org.id})")
    
    # Generate tokens
    token_data = {"sub": user.id, "org_id": org.id, "email": user.email, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user={
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "org_id": org.id,
            "org_name": org.name,
            "api_key": raw_api_key,  # Only shown once on registration
        },
    )


@router.post("/login", response_model=AuthResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Authenticate user and return JWT tokens.
    """
    # Find user by email
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")
    
    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    
    # Get organization
    result = await db.execute(select(Organization).where(Organization.id == user.org_id))
    org = result.scalar_one()
    
    logger.info(f"User logged in: {user.email} (org={org.name})")
    
    # Generate tokens
    token_data = {"sub": user.id, "org_id": user.org_id, "email": user.email, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user={
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "org_id": user.org_id,
            "org_name": org.name,
        },
    )


@router.post("/refresh", response_model=AuthResponse)
async def refresh(request: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """
    Refresh access token using a refresh token.
    """
    try:
        # Bug #23 fixed: use expected_type="refresh" when decoding the refresh token.
        payload = jwt.decode(request.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        user_id = payload.get("sub")
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        result = await db.execute(select(Organization).where(Organization.id == user.org_id))
        org = result.scalar_one()
        
        # Generate new tokens
        token_data = {"sub": user.id, "org_id": user.org_id, "email": user.email, "role": user.role}
        access_token = create_access_token(token_data)
        refresh_token = create_refresh_token(token_data)
        
        return AuthResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user={
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "org_id": user.org_id,
                "org_name": org.name,
            },
        )
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")


@router.get("/me", response_model=UserInfoResponse)
async def get_me(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Get current authenticated user information.
    """
    result = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
    org = result.scalar_one()
    
    return UserInfoResponse(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        org_id=current_user.org_id,
        org_name=org.name,
    )


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    # Bug #3 fixed: passwords are now in the request body (JSON), NOT query
    # params. Previously FastAPI routed plain function params as query strings,
    # causing credentials to appear in every server/proxy access log.
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Change the current user's password.
    Body: { "old_password": "...", "new_password": "..." }
    """
    if not verify_password(request.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect current password")
    
    current_user.password_hash = get_password_hash(request.new_password)
    await db.commit()
    
    logger.info(f"Password changed for user: {current_user.email}")