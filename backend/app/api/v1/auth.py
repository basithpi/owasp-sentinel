from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, UnauthorizedError
from app.database import get_db
from app.dependencies import get_current_active_user
from app.models.user import User
from app.schemas.user import (
    APIKeyResponse,
    Token,
    TokenRefresh,
    UserCreate,
    UserLogin,
    UserResponse,
    UserUpdate,
)
from app.services.auth_service import AuthService

router = APIRouter()


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    service = AuthService(db)
    try:
        user = service.register_user(user_data)
    except ConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e.message)
    return service.create_tokens(user)


@router.post("/login", response_model=Token)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    service = AuthService(db)
    try:
        user = service.authenticate_user(credentials.email, credentials.password)
    except UnauthorizedError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return service.create_tokens(user)


@router.post("/refresh", response_model=Token)
def refresh_token(token_data: TokenRefresh, db: Session = Depends(get_db)):
    service = AuthService(db)
    try:
        return service.refresh_access_token(token_data.refresh_token)
    except (UnauthorizedError, NotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=e.message)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@router.put("/me", response_model=UserResponse)
def update_me(
    update_data: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(current_user, key, value)
    db.commit()
    db.refresh(current_user)
    return current_user


@router.post("/api-key/regenerate", response_model=APIKeyResponse)
def regenerate_api_key(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = AuthService(db)
    new_key = service.regenerate_api_key(current_user)
    return APIKeyResponse(api_key=new_key)
