from __future__ import annotations

from typing import Any

from ckan import model

from ckanext.auth import config as auth_config
from ckanext.auth.model import AuthPasskey


def is_totp_2fa_enabled() -> bool:
    return auth_config.is_totp_2fa_enabled()


def is_2fa_enabled() -> bool:
    return auth_config.is_2fa_enabled()


def get_2fa_method() -> str:
    return auth_config.get_2fa_method()


def is_2fa_dev_mode_enabled() -> bool:
    return auth_config.is_2fa_dev_mode()


def is_passkey_enabled() -> bool:
    return auth_config.is_passkey_enabled()


def get_user_passkeys(user_name: str) -> list[dict[str, Any]]:
    user = model.User.get(user_name)

    if not user:
        return []

    return [
        {
            "id": pk.id,
            "name": pk.name or "",
            "created": pk.created.strftime("%Y-%m-%d %H:%M") if pk.created else "",
        }
        for pk in AuthPasskey.get_for_user(user.id)
    ]
