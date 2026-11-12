from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import request
import pyotp

from ckan import types

from ckanext.auth import config as auth_config
from ckanext.auth import utils
from ckanext.auth.model import UserSecret

log = logging.getLogger(__name__)

OTP_VERIFY_ACTION = "auth_2fa_user_login"
OTP_REQUEST_START_KEY = "ckanext_auth_otp_request_start"


def register_otp_logging(app: types.CKANApp) -> types.CKANApp:
    app.before_request(_capture_otp_request_start)
    app.after_request(_log_otp_request)
    return app


def _username_from_request() -> str:
    login = request.form.get("login")
    if not login:
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            login = body.get("login")

    if not isinstance(login, str) or not login:
        return "unknown"
    try:
        user = utils.get_user_by_username_or_email(login)
    except Exception:  # noqa: BLE001  # Logging must not affect the authentication response.
        log.debug("Unable to resolve username for an email OTP log event")
        return "unknown"
    return user.name if user else "unknown"


def _has_submitted_code() -> bool:
    if "code" in request.form:
        return True
    body = request.get_json(silent=True)
    return isinstance(body, dict) and "code" in body


def _submitted_code() -> str | None:
    if "code" in request.form:
        return request.form.get("code", "")
    body = request.get_json(silent=True)
    if isinstance(body, dict) and isinstance(body.get("code"), str):
        return body["code"]
    return None


def _is_send_request() -> bool:
    return request.endpoint == "auth.send_verification_code"


def _is_verify_request() -> bool:
    return bool(request.view_args and request.view_args.get("logic_function") == OTP_VERIFY_ACTION)


def _capture_otp_request_start() -> None:
    if not auth_config.is_email_2fa_enabled() or request.method != "POST":
        return
    if _is_send_request() or (_is_verify_request() and _has_submitted_code()):
        request.environ[OTP_REQUEST_START_KEY] = datetime.now(timezone.utc)


def _email_otp_interval_s() -> int | None:
    try:
        interval_s = auth_config.get_2fa_email_interval()
    except (KeyError, TypeError, ValueError):
        return None
    return interval_s if interval_s > 0 else None


def _previous_window_match(
    username: str,
    code: str | None,
    request_started_at: datetime,
    response_at: datetime,
) -> bool | None:
    """Diagnose whether a rejected code matches the preceding email TOTP window."""
    interval_s = _email_otp_interval_s()
    if not code or not username or username == "unknown" or interval_s is None:
        return None
    if int(request_started_at.timestamp()) // interval_s != int(response_at.timestamp()) // interval_s:
        return None

    try:
        user_secret = UserSecret.get_for_user(username)
        if not user_secret or not user_secret.secret:
            return None

        totp = pyotp.TOTP(user_secret.secret, interval=interval_s)
        current_counter = int(request_started_at.timestamp()) // interval_s
        previous_window_time = datetime.fromtimestamp(current_counter * interval_s - 1, timezone.utc)
        return bool(totp.verify(code.strip(), for_time=previous_window_time))
    except Exception:  # noqa: BLE001  # Diagnostics must never change the authentication response.
        log.debug("Unable to diagnose whether the OTP matched the previous time window")
        return None


def _log_otp_request(response: types.Response) -> types.Response:
    if not auth_config.is_email_2fa_enabled() or request.method != "POST":
        return response

    is_send = _is_send_request()
    is_verify = _is_verify_request() and _has_submitted_code()
    if not is_send and not is_verify:
        return response

    payload = response.get_json(silent=True)
    payload = payload if isinstance(payload, dict) else {}
    if is_send:
        outcome = "sent" if payload.get("success") is True else "failed"
        event = "send"
    else:
        result = payload.get("result")
        result = result if isinstance(result, dict) else {}
        if result.get("success") is True:
            outcome = "verified"
        elif result.get("error") == "The verification code has expired":
            outcome = "expired"
        elif result.get("success") is False:
            outcome = "invalid"
        else:
            outcome = "error"
        event = "verify"

    request_started_at = request.environ.get(OTP_REQUEST_START_KEY)
    has_request_start = isinstance(request_started_at, datetime)
    if not has_request_start:
        request_started_at = datetime.now(timezone.utc)
    response_at = datetime.now(timezone.utc)
    interval_s = _email_otp_interval_s()
    username = _username_from_request()
    request_time = (
        request_started_at.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if has_request_start
        else "unknown"
    )
    interval_text = interval_s if interval_s is not None else "unknown"
    fields = (event, username, outcome, response.status_code, request_time, interval_text)
    if is_verify:
        previous_match = None
        if outcome == "invalid" and has_request_start and interval_s is not None:
            previous_match = _previous_window_match(
                username,
                _submitted_code(),
                request_started_at,
                response_at,
            )
        previous_match_text = str(previous_match).lower() if previous_match is not None else "unknown"
        log.info(
            "2FA email OTP event=%s username=%s outcome=%s status=%s request_time=%s interval_s=%s "
            "previous_window_match=%s",
            *fields,
            previous_match_text,
        )
    else:
        log.info(
            "2FA email OTP event=%s username=%s outcome=%s status=%s request_time=%s interval_s=%s",
            *fields,
        )
    return response
