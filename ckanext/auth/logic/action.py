from __future__ import annotations

import logging
from typing import Any, TypedDict

import ckan.model as model
import ckan.plugins.toolkit as tk
from ckan import types
from ckan.logic import validate
import ckan.lib.captcha as captcha

import ckanext.auth.exceptions as exceptions
import ckanext.auth.utils as utils
import ckanext.auth.config as auth_config
import ckanext.auth.logic.schema as schema
from ckanext.auth.model import UserSecret

log = logging.getLogger(__name__)


class LoginResponse(TypedDict, total=False):
    success: bool
    error: str | None
    valid: bool | None


@validate(schema.auth_2fa_user_login)
def auth_2fa_user_login(
    context: types.Context, data_dict: types.DataDict
) -> LoginResponse:
    tk.check_access("auth_2fa_user_login", context, data_dict)

    user = model.User.by_name(data_dict["login"])

    if not user:
        raise tk.ObjectNotFound("User not found")

    user_secret = UserSecret.get_for_user(user.name)

    if not user_secret:
        user_secret = UserSecret.create_for_user(user.name)

    if data_dict["mfa_type"] not in auth_config.ALLOWED_METHODS:
        raise ValueError("Invalid MFA type")

    try:
        success = user_secret.check_code(data_dict["code"])
    except exceptions.ReplayAttackException:
        return LoginResponse(
            success=False, error="The verification code has expired", valid=False
        )

    return LoginResponse(
        success=success,
        error=("The verification code is invalid" if not success else None),
        valid=success,
    )


@validate(schema.auth_2fa_user_login)
def auth_2fa_check_credentials(
    context: types.Context, data_dict: types.DataDict
) -> LoginResponse:
    tk.check_access("auth_2fa_user_login", context, data_dict)

    user = model.User.by_name(data_dict["login"])

    try:
        captcha.check_recaptcha(tk.request)
    except captcha.CaptchaError:
        log.info("2FA: Login failed for %s", data_dict["login"])
        return LoginResponse(success=False, error=tk._("Invalid reCAPTCHA"))

    if (
        not user
        or not user.is_active
        or not user.validate_password(data_dict["password"])
    ):
        log.info("2FA: Login failed for %s", data_dict["login"])

        utils.LoginManager.log_user_login_attempt(data_dict["login"])

        if (
            utils.LoginManager.get_user_login_attempts(data_dict["login"])
            > auth_config.get_2fa_max_attempts()
        ):
            utils.LoginManager.block_user_login(data_dict["login"])

        return LoginResponse(success=False, error=tk._("Invalid login or password"))

    if utils.LoginManager.is_login_blocked(data_dict["login"]):
        log.info("2FA: User %s is blocked from logging in", data_dict["login"])
        return LoginResponse(success=False, error=tk._("Too many login attempts"))

    return LoginResponse(success=True, error=None)
