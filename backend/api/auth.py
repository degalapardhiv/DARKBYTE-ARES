from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import get_current_user
from backend.core.config import get_settings
from backend.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from backend.database.session import get_db
from backend.models.models import User
from backend.schemas.schemas import (
    LoginRequest,
    PasswordChange,
    ProfileUpdate,
    RegisterRequest,
    TokenResponse,
    UserOut,
)
from backend.services.audit import append_audit
from backend.services.cache import cache

router = APIRouter(prefix="/auth", tags=["Authentication"])

LOGIN_FAILURE_LIMIT = 6
LOGIN_FAILURE_WINDOW = 600


def _token_response(user: User) -> TokenResponse:
    token, expires_in = create_access_token(user.id, user.role)
    return TokenResponse(
        access_token=token,
        expires_in=expires_in,
        user=UserOut.model_validate(user),
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    settings = get_settings()
    if not settings.allow_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "registration_disabled",
                "message": "Self-service registration is disabled. Ask an administrator for an account.",
            },
        )
    email = payload.email.lower().strip()
    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "email_exists", "message": "An account with this email already exists."},
        )
    user = User(
        email=email,
        name=payload.name.strip(),
        password_hash=hash_password(payload.password),
        role="analyst",
        is_active=True,
        preferences={"notifications": True, "compactMode": False, "defaultEnvironment": "lab"},
        is_demo=settings.demo_mode,
    )
    db.add(user)
    await db.flush()
    user.last_login_at = datetime.now(UTC)
    await append_audit(
        db,
        action="auth.register",
        resource_type="user",
        resource_id=user.id,
        actor=user,
        details={"email": user.email, "role": user.role, "demo": settings.demo_mode},
        request=request,
    )
    await db.commit()
    await db.refresh(user)
    return _token_response(user)


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    email = payload.email.lower().strip()
    ip = request.client.host if request.client else "unknown"
    failure_key = f"login-fail:{email}:{ip}"
    failures = int(await cache.get(failure_key) or 0)
    if failures >= LOGIN_FAILURE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "login_throttled",
                "message": "Too many failed sign-in attempts. Wait 10 minutes and try again.",
            },
            headers={"Retry-After": str(LOGIN_FAILURE_WINDOW)},
        )

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        await cache.set(failure_key, failures + 1, ttl=LOGIN_FAILURE_WINDOW)
        await append_audit(
            db,
            action="auth.login",
            resource_type="user",
            resource_id=user.id if user else None,
            outcome="failure",
            details={"email": email, "reason": "invalid_credentials"},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_credentials", "message": "Email or password is incorrect."},
            headers={"WWW-Authenticate": "Bearer"},
        )

    await cache.delete(failure_key)
    user.last_login_at = datetime.now(UTC)
    await append_audit(
        db,
        action="auth.login",
        resource_type="user",
        resource_id=user.id,
        actor=user,
        details={"email": user.email, "role": user.role},
        request=request,
    )
    await db.commit()
    await db.refresh(user)
    return _token_response(user)


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)


@router.patch("/profile", response_model=UserOut)
async def update_profile(
    payload: ProfileUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    user.name = payload.name.strip()
    user.preferences = payload.preferences
    await append_audit(
        db,
        action="auth.profile_updated",
        resource_type="user",
        resource_id=user.id,
        actor=user,
        details={"fields": ["name", "preferences"]},
        request=request,
    )
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@router.post("/change-password")
async def change_password(
    payload: PasswordChange,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_password", "message": "The current password is incorrect."},
        )
    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "password_reused", "message": "Choose a password you have not used here before."},
        )
    user.password_hash = hash_password(payload.new_password)
    await append_audit(
        db,
        action="auth.password_changed",
        resource_type="user",
        resource_id=user.id,
        actor=user,
        details={"method": "self_service"},
        request=request,
    )
    await db.commit()
    return {"message": "Password updated. Existing sessions remain valid until they expire."}


@router.post("/logout")
async def logout(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    await append_audit(
        db,
        action="auth.logout",
        resource_type="user",
        resource_id=user.id,
        actor=user,
        request=request,
    )
    await db.commit()
    return {"message": "Signed out. Discard the local token."}
