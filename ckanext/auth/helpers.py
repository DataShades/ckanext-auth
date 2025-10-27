from __future__ import annotations

from ckanext.auth import config as auth_config


def is_totp_2fa_enabled() -> bool:
    return auth_config.is_totp_2fa_enabled()


def is_2fa_enabled() -> bool:
    return auth_config.is_2fa_enabled()


def get_2fa_method() -> str:
    return auth_config.get_2fa_method()


def is_2fa_dev_mode_enabled() -> bool:
    return auth_config.is_2fa_dev_mode()
