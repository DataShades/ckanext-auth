from __future__ import annotations

import logging
from typing import cast

import ckan.plugins as p
import ckan.model as model
import ckan.lib.mailer as ckan_mailer
import ckan.plugins.toolkit as tk
from ckan.lib.redis import connect_to_redis

from ckanext.auth import config as auth_config
from ckanext.auth.model import UserSecret
from datetime import timedelta

from ckan.views.user import next_page_or_default, rotate_token
from ckan.lib.authenticator import default_authenticate

import ckanext.auth.utils as utils
from ckanext.auth import config
from ckanext.auth.exceptions import ReplayAttackException

log = logging.getLogger(__name__)


class LoginManager:
    login_attempts_key = "ckanext-auth:login_attempts:{}"
    blocked_key = "ckanext-auth:blocked:{}"

    @classmethod
    def is_login_blocked(cls, user_id: str) -> bool:
        """Check if a user is blocked from logging in."""
        return bool(connect_to_redis().get(cls.blocked_key.format(user_id)))

    @classmethod
    def block_user_login(cls, user_id: str) -> None:
        """Block a user from logging in for a certain amount of time."""
        connect_to_redis().setex(
            cls.blocked_key.format(user_id),
            auth_config.get_2fa_login_timeout(),
            1,
        )

    @classmethod
    def log_user_login_attempt(cls, user_id: str) -> None:
        """Log a login attempt for a user."""
        redis = connect_to_redis()

        redis.incr(cls.login_attempts_key.format(user_id))

    @classmethod
    def get_user_login_attempts(cls, user_id: str) -> int:
        """Get the number of login attempts for a user."""
        return int(connect_to_redis().get(cls.login_attempts_key.format(user_id)) or 0)

    @classmethod
    def reset_for_user(cls, user_id: str) -> None:
        """Reset the login attempts for a user."""
        log.debug("2FA: Resetting login attempts for user %s", user_id)

        redis = connect_to_redis()

        redis.delete(cls.login_attempts_key.format(user_id))
        redis.delete(cls.blocked_key.format(user_id))

    @classmethod
    def reset_all(cls) -> None:
        """Reset the login attempts for all users."""
        log.debug("2FA: Resetting login attempts for all users")

        redis = connect_to_redis()

        for key in redis.keys(cls.login_attempts_key.format("*")):
            redis.delete(key)

        for key in redis.keys(cls.blocked_key.format("*")):
            redis.delete(key)


def send_verification_email_to_user(user_id: str) -> bool:
    user = model.User.get(user_id)

    if not user or not user.email:
        return False

    code = get_email_verification_code(user)
    data = {
        "verification_code": code,
        "site_url": tk.config["ckan.site_url"],
        "site_title": tk.config["ckan.site_title"],
        "user_name": user.display_name,
        "subject": tk._(config.get_2fa_subject()),
        "body": f"Your verification code is: {code}",
    }

    if p.plugin_loaded("mailcraft"):
        from ckanext.mailcraft.utils import get_mailer

        get_mailer().mail_recipients(
            subject=data["subject"],
            recipients=[user.email],
            body=data["body"],
            body_html=tk.render(
                "auth/emails/verification_code.html",
                extra_vars=data,
            ),
        )
    else:
        try:
            ckan_mailer.mail_user(
                recipient=user,
                subject=data["subject"],
                body=data["body"],
                body_html=tk.render(
                    "auth/emails/verification_code.html",
                    extra_vars=data,
                ),
            )
        except ckan_mailer.MailerException:
            return False

    return True


def get_email_verification_code(user: model.User) -> str:
    user_secret = UserSecret.get_for_user(user.name)

    if not user_secret:
        user_secret = UserSecret.create_for_user(user.name)

    return user_secret.get_code()


def regenerate_user_secret(user_id: str) -> str:
    """Regenerate the secret for a user.

    Args:
        user_id (str): The id of the user

    Returns:
        str: The new secret
    """

    user = model.User.get(user_id)

    if not user:
        raise tk.ObjectNotFound("User not found")

    user_secret = UserSecret.create_for_user(user.name)

    log.debug("2FA: Rotated the 2fa secret for user %s", user_id)

    return cast(str, user_secret.secret)


def login():
    if tk.current_user.is_authenticated:
        return tk.render("user/logout_first.html", {})

    if tk.request.method != "POST":
        return tk.render("user/login.html", {})

    user_obj = authenticate(
        {
            "login": tk.get_or_bust(tk.request.form, "login"),
            "password": tk.get_or_bust(tk.request.form, "password"),
            "check_captcha": False,
        }
    )

    if not user_obj:
        tk.h.flash_error(tk._("Login failed. Bad username or password."))
        return tk.render("user/login.html", {})

    if remember := tk.request.form.get("remember"):
        tk.login_user(
            user_obj, remember=True, duration=timedelta(milliseconds=int(remember))
        )
    else:
        tk.login_user(user_obj)

    rotate_token()

    return next_page_or_default(
        tk.request.args.get("next", tk.request.args.get("came_from"))
    )


def authenticate(identity: dict[str, str]) -> model.User | None:
    # Run through the CKAN auth sequence first, so we can hit the DB
    # in every case and make timing attacks a little more difficult.
    ckan_auth_result = default_authenticate(identity)

    if "login" not in identity:
        return None

    if utils.LoginManager.is_login_blocked(identity["login"]):
        return None

    if (
        utils.LoginManager.get_user_login_attempts(identity["login"])
        > config.get_2fa_max_attempts()
    ):
        utils.LoginManager.block_user_login(identity["login"])

    if not ckan_auth_result:
        return utils.LoginManager.log_user_login_attempt(identity["login"])

    if not config.is_2fa_enabled():
        utils.LoginManager.reset_for_user(identity["login"])
        return ckan_auth_result

    # if the CKAN authenticator has successfully authenticated
    # then check the TOTP parameter to see if it is valid
    if authenticate_totp(identity["login"]):
        utils.LoginManager.reset_for_user(identity["login"])
        return ckan_auth_result

    # This means that the login form has been submitted
    # with an invalid TOTP code, bypassing the ajax
    # login workflow.

    # The username and password were fine, but the 2fa
    # code was missing or invalid
    return None


def authenticate_totp(user_name: str) -> str | None:
    user_secret = UserSecret.get_for_user(user_name)

    # if there is no totp configured, don't allow auth
    # shouldn't happen, login flow should create a user secret
    if not user_secret:
        return log.debug(
            "2FA: Login attempted without MFA configured for: %s", user_name
        )

    if "code" not in tk.request.form:
        return log.debug("2FA: Could not get MFA credentials from a request")

    try:
        result = user_secret.check_code(tk.request.form["code"])
    except ReplayAttackException as e:
        return log.warning(
            "2FA: Detected a possible replay attack for user: %s, context: %s",
            user_name,
            e,
        )
    else:
        return user_name if result else None
