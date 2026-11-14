import logging
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from flask import Flask, Response, jsonify

from ckanext.auth import middleware
from ckanext.auth.model import UserSecret

OK = 200


@pytest.fixture
def otp_logging_app(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger=middleware.log.name)
    monkeypatch.setattr(middleware.log, "disabled", False)
    monkeypatch.setattr(middleware.auth_config, "is_email_2fa_enabled", lambda: True)
    monkeypatch.setattr(middleware.auth_config, "get_2fa_email_interval", lambda: 600)
    user = type("User", (), {"name": "alice"})()
    monkeypatch.setattr(middleware.utils, "get_user_by_username_or_email", lambda login: user)

    app = Flask(__name__)
    app.before_request(middleware._capture_otp_request_start)
    app.after_request(middleware._log_otp_request)

    @app.post("/mfa/send_verification_code", endpoint="auth.send_verification_code")
    def send_code():
        return jsonify(success=app.config.get("send_success", True))

    @app.post("/api/action/<logic_function>", endpoint="google_analytics.action")
    @app.post("/api/3/action/<logic_function>", endpoint="api.action")
    def action(logic_function):
        success = logic_function == "auth_2fa_success"
        error = None if success else "The verification code is invalid"
        return jsonify({"result": {"success": success, "error": error}})

    @app.post("/unrelated")
    def unrelated():
        return jsonify(success=True)

    return app


def test_send_and_wrapped_verify_log_metadata_without_secrets(otp_logging_app, monkeypatch, caplog):
    code = "sensitive-otp-value"
    monkeypatch.setattr(middleware, "_previous_window_match", lambda *args: True)

    with otp_logging_app.test_client() as client:
        client.post("/mfa/send_verification_code", data={"login": "alice@example.test"})
        client.post("/api/action/auth_2fa_user_login", data={"login": "alice", "code": code})

    records = caplog.text.splitlines()
    send_record = next(line for line in records if "event=send" in line)
    verify_record = next(line for line in records if "event=verify" in line)
    assert "event=send username=alice outcome=sent status=200 request_time=" in send_record
    assert "interval_s=600" in send_record
    assert "event=verify username=alice outcome=invalid status=200 request_time=" in verify_record
    assert "interval_s=600 previous_window_match=true" in verify_record
    assert "alice@example.test" not in caplog.text
    assert code not in caplog.text

    def invalid_interval():
        raise ValueError("invalid interval")

    monkeypatch.setattr(middleware.auth_config, "get_2fa_email_interval", invalid_interval)
    otp_logging_app.config["send_success"] = False
    with otp_logging_app.test_client() as client:
        response = client.post("/mfa/send_verification_code", data={"login": "alice"})

    assert response.status_code == OK
    assert response.get_json()["success"] is False
    assert "event=send username=alice outcome=failed status=200 request_time=" in caplog.text
    assert "interval_s=unknown" in caplog.text


def test_previous_window_diagnostic_is_read_only_and_boundary_safe(monkeypatch):
    interval_s = 600
    secret = pyotp.random_base32()
    stored_secret = type("StoredSecret", (), {"secret": secret})()
    lookups = []

    def get_secret(username):
        lookups.append(username)
        return stored_secret

    monkeypatch.setattr(UserSecret, "get_for_user", get_secret)
    start = datetime.fromtimestamp(100 * interval_s + 10, timezone.utc)
    previous_window_code = pyotp.TOTP(secret, interval=interval_s).at(
        datetime.fromtimestamp(100 * interval_s - 1, timezone.utc),
    )

    assert middleware._previous_window_match("alice", previous_window_code, start, start + timedelta(seconds=1)) is True
    assert middleware._previous_window_match(
        "alice",
        previous_window_code,
        start,
        datetime.fromtimestamp(101 * interval_s + 1, timezone.utc),
    ) is None
    assert lookups == ["alice"]


def test_unrelated_response_is_not_parsed_or_logged(otp_logging_app, caplog, monkeypatch):
    def unexpected_json_parse(self, *args, **kwargs):
        raise AssertionError("unrelated response was parsed as JSON")

    monkeypatch.setattr(Response, "get_json", unexpected_json_parse)
    with otp_logging_app.test_client() as client:
        response = client.post("/unrelated")

    assert response.status_code == OK
    assert "2FA email OTP" not in caplog.text


def test_logging_is_disabled_when_email_mfa_is_off(otp_logging_app, caplog, monkeypatch):
    monkeypatch.setattr(middleware.auth_config, "is_email_2fa_enabled", lambda: False)
    with otp_logging_app.test_client() as client:
        response = client.post("/api/action/auth_2fa_user_login", data={"login": "alice", "code": "secret"})

    assert response.status_code == OK
    assert "2FA email OTP" not in caplog.text
