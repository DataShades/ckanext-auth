from __future__ import annotations

import ckan.plugins.toolkit as tk

CONF_2FA_ENABLED = "ckanext.auth.2fa_enabled"
CONF_2FA_METHOD = "ckanext.auth.2fa_method"
CONF_2FA_SUBJECT = "ckanext.auth.2fa_subject"
CONF_2FA_EMAIL_INTERVAL = "ckanext.auth.2fa_email_interval"
CONF_2FA_LOGIN_TIMEOUT = "ckanext.auth.2fa_login_timeout"
CONF_2FA_MAX_ATTEMPTS = "ckanext.auth.2fa_login_max_attempts"

METHOD_EMAIL = "email"
METHOD_AUTHENTICATOR = "authenticator"
ALLOWED_METHODS = [METHOD_EMAIL, METHOD_AUTHENTICATOR]


def is_2fa_enabled() -> bool:
    return tk.asbool(tk.config[CONF_2FA_ENABLED])


def get_2fa_method() -> str:
    return tk.config[CONF_2FA_METHOD]


def get_2fa_subject() -> str:
    return tk.config[CONF_2FA_SUBJECT]


def is_email_2fa_enabled() -> bool:
    return get_2fa_method() == METHOD_EMAIL


def is_totp_2fa_enabled() -> bool:
    return get_2fa_method() == METHOD_AUTHENTICATOR


def get_2fa_email_interval() -> int:
    return int(tk.config[CONF_2FA_EMAIL_INTERVAL])


def get_2fa_login_timeout() -> int:
    return int(tk.config[CONF_2FA_LOGIN_TIMEOUT])


def get_2fa_max_attempts() -> int:
    return int(tk.config[CONF_2FA_MAX_ATTEMPTS])
