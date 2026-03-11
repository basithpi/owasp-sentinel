import hashlib
import secrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, status
from sqlalchemy import select

from ...core.dependencies import AdminUser, CurrentUser, DB
from ...core.exceptions import NotFoundError
from ...models.setting import Setting
from ...schemas.setting import SettingResponse, SettingUpdate

router = APIRouter(prefix="/settings", tags=["Settings"])

_API_KEY_SETTING = "api_key"


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# /api-keys routes must be declared before generic routes to avoid conflicts
# ---------------------------------------------------------------------------


@router.get("/api-keys")
async def get_api_key_settings(
    db: DB,
    current_user: AdminUser,
) -> Dict[str, Any]:
    """Retrieve the current API key configuration (hash only, never the raw key)."""
    result = await db.execute(
        select(Setting).where(Setting.key == _API_KEY_SETTING)
    )
    setting = result.scalar_one_or_none()

    if setting is None or not setting.value:
        return {"api_key_configured": False, "api_key_prefix": None}

    raw_prefix = setting.value.get("prefix", "")
    return {
        "api_key_configured": True,
        "api_key_prefix": raw_prefix,
    }


@router.post(
    "/api-keys/regenerate",
    status_code=status.HTTP_201_CREATED,
)
async def regenerate_api_key(
    db: DB,
    current_user: AdminUser,
) -> Dict[str, Any]:
    """Generate a new UUID-based API key, store its hash, and return the raw key once."""
    new_key = f"sk-{secrets.token_hex(32)}"
    key_hash = _hash_api_key(new_key)
    prefix = new_key[:12]

    result = await db.execute(
        select(Setting).where(Setting.key == _API_KEY_SETTING)
    )
    setting = result.scalar_one_or_none()

    if setting is None:
        setting = Setting(
            key=_API_KEY_SETTING,
            value={"hash": key_hash, "prefix": prefix},
            category="security",
            description="Platform API key (SHA-256 hash stored)",
            updated_by=current_user.id,
        )
        db.add(setting)
    else:
        setting.value = {"hash": key_hash, "prefix": prefix}
        setting.updated_by = current_user.id

    await db.flush()

    return {
        "api_key": new_key,
        "prefix": prefix,
        "message": "Store this key securely — it will not be shown again.",
    }


@router.get("")
async def get_all_settings(
    db: DB,
    current_user: CurrentUser,
) -> Dict[str, List[SettingResponse]]:
    """Retrieve all platform settings grouped by category."""
    result = await db.execute(select(Setting).order_by(Setting.category, Setting.key))
    settings_list = result.scalars().all()

    grouped: Dict[str, List[SettingResponse]] = {}
    for setting in settings_list:
        category = setting.category or "general"
        if category not in grouped:
            grouped[category] = []
        grouped[category].append(SettingResponse.model_validate(setting))

    return grouped


@router.put("", response_model=List[SettingResponse])
async def update_settings(
    updates: Dict[str, Any],
    db: DB,
    current_user: AdminUser,
) -> List[SettingResponse]:
    """Update multiple settings by key. Creates missing settings automatically."""
    updated: List[Setting] = []

    for key, value in updates.items():
        result = await db.execute(select(Setting).where(Setting.key == key))
        setting = result.scalar_one_or_none()

        if setting is None:
            setting = Setting(
                key=key,
                value=value,
                updated_by=current_user.id,
            )
            db.add(setting)
        else:
            setting.value = value
            setting.updated_by = current_user.id

        updated.append(setting)

    await db.flush()
    for s in updated:
        await db.refresh(s)

    return [SettingResponse.model_validate(s) for s in updated]
