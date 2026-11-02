from __future__ import annotations

from unittest import mock

import pyotp
import pytest

from ckan import model
from ckan.tests import factories

from ckanext.auth import config as auth_config
from ckanext.auth import utils
from ckanext.auth.model import UserSecret
from ckanext.auth.views.mfa import Configure2FA

PASSWORD = "correct123"
INIT_QR_CODE_URL = "/mfa/init_qr_code"
SEND_CODE_URL = "/mfa/send_verification_code"


@pytest.fixture
def owner():
    return factories.UserWithToken()


@pytest.fixture
def other_user():
    return factories.UserWithToken()


@pytest.fixture
def sysadmin_user():
    return factories.SysadminWithToken()


def _auth_headers(user):
    return {"Authorization": user["token"]}


def _configure_url(user):
    return f"/mfa/configure_2fa/{user['name']}"


def _regenerate_url(user):
    return f"/mfa/configure_mfa/{user['name']}/new"


def _complete_enrollment(user_name: str) -> UserSecret:
    """Create a secret and verify a code, as the first login does."""
    secret = UserSecret.create_for_user(user_name)
    secret.check_code(pyotp.TOTP(secret.secret).now())

    return secret


@pytest.mark.usefixtures("with_plugins", "clean_db", "with_request_context")
class TestConfigure2FAView:
    def test_secret_recreated_when_missing(self, user):
        """Visiting the configure page with no secret must recreate one and
        render the QR code instead of returning an empty context."""
        assert not UserSecret.get_for_user(user["name"])

        extra_vars = Configure2FA()._setup_totp_extra_vars(user["name"])

        assert extra_vars.get("totp_secret")
        assert extra_vars.get("provisioning_uri")
        assert UserSecret.get_for_user(user["name"])


@pytest.mark.ckan_config(auth_config.CONF_2FA_METHOD, auth_config.METHOD_AUTHENTICATOR)
@pytest.mark.usefixtures("with_plugins", "clean_db", "clean_redis")
class TestInitQrCode:
    def test_enrollment_returns_secret(self, app, owner):
        """A user who has never verified a code gets the enrollment data."""
        res = app.post(INIT_QR_CODE_URL, data={"login": owner["name"], "password": PASSWORD}, status=200)

        result = res.json["result"]
        secret = UserSecret.get_for_user(owner["name"])

        assert result["accessed"] is False
        assert result["secret"] == secret.secret
        assert result["provisioning_uri"] == secret.provisioning_uri

    def test_enrolled_user_gets_no_secret(self, app, owner):
        """The secret must not leave the server once a code was verified."""
        secret = _complete_enrollment(owner["name"]).secret

        res = app.post(INIT_QR_CODE_URL, data={"login": owner["name"], "password": PASSWORD}, status=200)

        assert res.json["result"] == {"accessed": True}
        assert secret not in res.body

    def test_login_by_email(self, app, owner):
        """The login form accepts an email as well as a user name."""
        email = model.User.get(owner["id"]).email

        res = app.post(INIT_QR_CODE_URL, data={"login": email, "password": PASSWORD}, status=200)

        assert res.json["result"]["secret"] == UserSecret.get_for_user(owner["name"]).secret

    @pytest.mark.parametrize("data", [{}, {"password": ""}, {"password": "wrong"}])
    def test_invalid_password_is_rejected(self, app, owner, data):
        """The login name alone must not disclose the secret or create one."""
        app.post(INIT_QR_CODE_URL, data={"login": owner["name"], **data}, status=403)

        assert not UserSecret.get_for_user(owner["name"])

    def test_inactive_user_is_rejected(self, app, owner):
        model.User.get(owner["id"]).state = model.State.DELETED
        model.Session.commit()

        app.post(INIT_QR_CODE_URL, data={"login": owner["name"], "password": PASSWORD}, status=403)

    def test_unknown_user_is_rejected(self, app):
        app.post(INIT_QR_CODE_URL, data={"login": "missing", "password": PASSWORD}, status=403)

    def test_invalid_password_counts_as_login_attempt(self, app, owner):
        """The endpoint must not be a password oracle outside the login limits."""
        app.post(INIT_QR_CODE_URL, data={"login": owner["name"], "password": "wrong"}, status=403)

        assert utils.LoginManager.get_user_login_attempts(owner["name"]) == 1

    @pytest.mark.ckan_config(auth_config.CONF_2FA_MAX_ATTEMPTS, 1)
    def test_too_many_attempts_block_the_login(self, app, owner):
        for _ in range(2):
            app.post(INIT_QR_CODE_URL, data={"login": owner["name"], "password": "wrong"}, status=403)

        assert utils.LoginManager.is_login_blocked(owner["name"])

    def test_blocked_login_is_rejected(self, app, owner):
        utils.LoginManager.block_user_login(owner["name"])

        app.post(INIT_QR_CODE_URL, data={"login": owner["name"], "password": PASSWORD}, status=403)

        assert not UserSecret.get_for_user(owner["name"])


@pytest.mark.ckan_config(auth_config.CONF_2FA_METHOD, auth_config.METHOD_EMAIL)
@pytest.mark.usefixtures("with_plugins", "clean_db", "clean_redis")
class TestInitQrCodeEmailMethod:
    def test_not_available(self, app, owner):
        """The same secret generates emailed codes, so it must never be exposed."""
        app.post(INIT_QR_CODE_URL, data={"login": owner["name"], "password": PASSWORD}, status=404)


@pytest.mark.usefixtures("with_plugins", "clean_db", "clean_redis")
class TestSendVerificationCode:
    @pytest.mark.ckan_config(auth_config.CONF_2FA_METHOD, auth_config.METHOD_AUTHENTICATOR)
    def test_cannot_reset_totp_enrollment(self, app, owner):
        """Rotating clears last_access, which would make init_qr_code hand a
        new secret to an attacker who only knows the password."""
        secret = _complete_enrollment(owner["name"]).secret

        app.post(SEND_CODE_URL, data={"login": owner["name"]}, status=404)

        user_secret = UserSecret.get_for_user(owner["name"])
        assert user_secret.secret == secret
        assert user_secret.last_access

        res = app.post(INIT_QR_CODE_URL, data={"login": owner["name"], "password": PASSWORD}, status=200)
        assert res.json["result"] == {"accessed": True}

    @pytest.mark.ckan_config(auth_config.CONF_2FA_METHOD, auth_config.METHOD_EMAIL)
    def test_email_method_still_sends_a_code(self, app, owner):
        with mock.patch("ckanext.auth.utils.send_verification_email_to_user", return_value=True) as send:
            res = app.post(SEND_CODE_URL, data={"login": owner["name"]}, status=200)

        assert res.json["success"] is True
        send.assert_called_once_with(owner["name"])


@pytest.mark.ckan_config(auth_config.CONF_2FA_METHOD, auth_config.METHOD_AUTHENTICATOR)
@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestConfigure2FAAccess:
    def test_owner_can_see_own_secret(self, app, owner):
        res = app.get(_configure_url(owner), headers=_auth_headers(owner), status=200)

        assert UserSecret.get_for_user(owner["name"]).secret in res.body

    def test_sysadmin_can_see_user_secret(self, app, owner, sysadmin_user):
        res = app.get(_configure_url(owner), headers=_auth_headers(sysadmin_user), status=200)

        assert UserSecret.get_for_user(owner["name"]).secret in res.body

    def test_other_user_cannot_see_secret(self, app, owner, other_user):
        secret = UserSecret.create_for_user(owner["name"]).secret

        res = app.get(_configure_url(owner), headers=_auth_headers(other_user), status=403)

        assert secret not in res.body

    def test_other_user_cannot_create_secret(self, app, owner, other_user):
        app.get(_configure_url(owner), headers=_auth_headers(other_user), status=403)
        app.post(_configure_url(owner), headers=_auth_headers(other_user), status=403)

        assert not UserSecret.get_for_user(owner["name"])

    def test_other_user_cannot_test_codes(self, app, owner, other_user):
        """The test form would otherwise be an oracle for the user's codes."""
        secret = UserSecret.create_for_user(owner["name"]).secret
        code = pyotp.TOTP(secret).now()

        app.post(_configure_url(owner), data={"code": code}, headers=_auth_headers(other_user), status=403)

    def test_missing_user(self, app, owner):
        app.get("/mfa/configure_2fa/missing", headers=_auth_headers(owner), status=404)


@pytest.mark.ckan_config(auth_config.CONF_2FA_METHOD, auth_config.METHOD_AUTHENTICATOR)
@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestRegenerateSecret:
    def test_owner_can_regenerate(self, app, owner):
        secret = UserSecret.create_for_user(owner["name"]).secret

        app.post(_regenerate_url(owner), headers=_auth_headers(owner), status=200)

        assert UserSecret.get_for_user(owner["name"]).secret != secret

    def test_sysadmin_can_regenerate(self, app, owner, sysadmin_user):
        secret = UserSecret.create_for_user(owner["name"]).secret

        app.post(_regenerate_url(owner), headers=_auth_headers(sysadmin_user), status=200)

        assert UserSecret.get_for_user(owner["name"]).secret != secret

    def test_other_user_cannot_regenerate(self, app, owner, other_user):
        """Regenerating clears last_access, so it must not be possible to reset
        someone else's enrollment."""
        secret = _complete_enrollment(owner["name"]).secret

        app.post(_regenerate_url(owner), headers=_auth_headers(other_user), status=403)

        user_secret = UserSecret.get_for_user(owner["name"])
        assert user_secret.secret == secret
        assert user_secret.last_access

    def test_get_does_not_regenerate(self, app, owner):
        """A state-changing GET would bypass the CSRF protection."""
        secret = UserSecret.create_for_user(owner["name"]).secret

        res = app.get(_regenerate_url(owner), headers=_auth_headers(owner))

        assert res.status_code in (404, 405)
        assert UserSecret.get_for_user(owner["name"]).secret == secret
