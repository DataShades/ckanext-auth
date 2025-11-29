from __future__ import annotations

from typing import cast
from unittest import mock

import pytest

from ckan import model

from ckanext.auth import utils

CODE_LENGTH = 6
SECRET_LENGTH = 32


@pytest.mark.usefixtures("with_plugins", "clean_db", "with_request_context")
class TestSendVerificationCodeToUser:
    @mock.patch("ckan.lib.mailer.mail_user")
    def test_send_verification_code_to_user(self, mocker, user):
        mocker.return_value = True
        assert utils.send_verification_email_to_user(user["id"])

    def test_user_does_not_exist(self):
        assert not utils.send_verification_email_to_user("xxx")

    @mock.patch("ckan.lib.mailer.mail_user")
    def test_send_verification_code_to_user_with_email(self, mocker, user):
        mocker.return_value = True
        assert utils.send_verification_email_to_user(user["email"])

@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestGetEmailVerificationCode:
    def test_get_email_verification_code(self, user):
        user_obj = cast(model.User, model.User.get(user["id"]))
        code = utils.get_email_verification_code(user_obj)

        assert code
        assert isinstance(code, str)
        assert len(code) == CODE_LENGTH
        assert code.isdigit()


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestRegenerateUserSecret:
    def test_regenerate_user_secret(self, user):
        secret = utils.regenerate_user_secret(user["id"])

        assert secret
        assert isinstance(secret, str)
        assert len(secret) == SECRET_LENGTH
        assert secret.isalnum()


@pytest.mark.usefixtures("with_plugins", "clean_db", "clean_redis")
class TestLoginManager:
    def test_no_login_attemps(self, user):
        assert utils.LoginManager.get_user_login_attempts(user["id"]) == 0

    def test_one_login_attempt(self, user):
        utils.LoginManager.log_user_login_attempt(user["id"])
        assert utils.LoginManager.get_user_login_attempts(user["id"]) == 1

    def test_block_user_login(self, user):
        utils.LoginManager.block_user_login(user["id"])
        assert utils.LoginManager.is_login_blocked(user["id"])

    def test_reset_for_user(self, user):
        utils.LoginManager.block_user_login(user["id"])
        assert utils.LoginManager.is_login_blocked(user["id"])

        utils.LoginManager.reset_for_user(user["id"])
        assert not utils.LoginManager.is_login_blocked(user["id"])
