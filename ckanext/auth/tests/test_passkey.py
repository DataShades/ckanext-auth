from unittest import mock
from typing import cast

import pytest

import ckan.plugins.toolkit as tk
from ckan.tests import factories
from ckan import model

from webauthn.helpers import bytes_to_base64url

from ckanext.auth.model import AuthPasskey
from ckanext.auth import passkey as passkey_utils


@pytest.fixture
def user_obj(user):
    return model.User.get(user["id"])


@pytest.fixture
def passkey_record(user):
    return AuthPasskey.create(
        user_id=user["id"],
        credential_id=b"test_cred_id",
        public_key=b"test_pub_key",
        sign_count=0,
        name="Test Passkey",
    )


def _auth_data(raw_credential_id: bytes) -> dict:
    cid = bytes_to_base64url(raw_credential_id)
    placeholder = bytes_to_base64url(b"x")
    return {
        "id": cid,
        "rawId": cid,
        "response": {
            "clientDataJSON": placeholder,
            "authenticatorData": placeholder,
            "signature": placeholder,
            "userHandle": None,
        },
    }


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestBeginPasskeyRegistration:
    def test_returns_options(self, user_obj):
        mock_redis = mock.MagicMock()
        mock_options = mock.MagicMock()
        mock_options.challenge = b"challenge"

        with (
            mock.patch("ckanext.auth.passkey.connect_to_redis", return_value=mock_redis),
            mock.patch(
                "ckanext.auth.passkey.webauthn.generate_registration_options",
                return_value=mock_options,
            ),
            mock.patch(
                "ckanext.auth.passkey.webauthn.options_to_json",
                return_value='{"challenge": "abc"}',
            ),
        ):
            result = passkey_utils.begin_passkey_registration(user_obj)

        assert result == {"challenge": "abc"}
        mock_redis.setex.assert_called_once()

    def test_excludes_existing_credentials(self, user_obj, passkey_record):
        mock_redis = mock.MagicMock()
        mock_options = mock.MagicMock()
        mock_options.challenge = b"challenge"
        captured = {}

        def fake_generate(**kwargs):
            captured.update(kwargs)
            return mock_options

        with (
            mock.patch("ckanext.auth.passkey.connect_to_redis", return_value=mock_redis),
            mock.patch(
                "ckanext.auth.passkey.webauthn.generate_registration_options",
                side_effect=fake_generate,
            ),
            mock.patch("ckanext.auth.passkey.webauthn.options_to_json", return_value="{}"),
        ):
            passkey_utils.begin_passkey_registration(user_obj)

        exclude = captured["exclude_credentials"]
        assert len(exclude) == 1
        assert exclude[0].id == b"test_cred_id"


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestCompletePasskeyRegistration:
    def test_raises_when_challenge_missing(self, user_obj):
        mock_redis = mock.MagicMock()
        mock_redis.get.return_value = None

        with (
            mock.patch("ckanext.auth.passkey.connect_to_redis", return_value=mock_redis),
            pytest.raises(tk.ValidationError),
        ):
            passkey_utils.complete_passkey_registration(user_obj, {}, "My Key")

    def test_raises_on_verification_failure(self, user_obj):
        mock_redis = mock.MagicMock()
        mock_redis.get.return_value = bytes_to_base64url(b"challenge").encode()
        placeholder = bytes_to_base64url(b"x")
        data = {
            "id": placeholder,
            "rawId": placeholder,
            "response": {
                "clientDataJSON": placeholder,
                "attestationObject": placeholder,
            },
        }

        with (
            mock.patch("ckanext.auth.passkey.connect_to_redis", return_value=mock_redis),
            mock.patch(
                "ckanext.auth.passkey.webauthn.verify_registration_response",
                side_effect=Exception("bad credential"),
            ),
            pytest.raises(tk.ValidationError),
        ):
            passkey_utils.complete_passkey_registration(user_obj, data, "My Key")

    def test_creates_passkey_on_success(self, user_obj):
        mock_redis = mock.MagicMock()
        mock_redis.get.return_value = bytes_to_base64url(b"challenge").encode()
        placeholder = bytes_to_base64url(b"x")
        data = {
            "id": placeholder,
            "rawId": placeholder,
            "response": {
                "clientDataJSON": placeholder,
                "attestationObject": placeholder,
            },
        }
        mock_verification = mock.MagicMock()
        mock_verification.credential_id = b"new_cred_id"
        mock_verification.credential_public_key = b"new_pub_key"
        mock_verification.sign_count = 0

        with (
            mock.patch("ckanext.auth.passkey.connect_to_redis", return_value=mock_redis),
            mock.patch(
                "ckanext.auth.passkey.webauthn.verify_registration_response",
                return_value=mock_verification,
            ),
        ):
            result = passkey_utils.complete_passkey_registration(user_obj, data, "My Key")

        assert result.user_id == user_obj.id
        assert result.name == "My Key"
        assert AuthPasskey.get_by_credential_id(b"new_cred_id") is not None


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestDeletePasskey:
    def test_deletes_passkey(self, user, passkey_record):
        passkey_utils.delete_passkey(passkey_record.id, user["id"])

        assert AuthPasskey.get_by_credential_id(b"test_cred_id") is None

    def test_raises_when_not_found(self, user):
        with pytest.raises(tk.ObjectNotFound):
            passkey_utils.delete_passkey("nonexistent-id", user["id"])

    def test_raises_when_not_owner(self, user, passkey_record):
        other_user = factories.User()

        with pytest.raises(tk.NotAuthorized):
            passkey_utils.delete_passkey(passkey_record.id, other_user["id"])


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestBeginPasskeyLogin:
    def test_returns_options_and_stores_challenge(self):
        mock_options = mock.MagicMock()
        mock_options.challenge = b"login_challenge"
        mock_session = {}

        with (
            mock.patch("ckanext.auth.passkey.session", mock_session),
            mock.patch(
                "ckanext.auth.passkey.webauthn.generate_authentication_options",
                return_value=mock_options,
            ),
            mock.patch(
                "ckanext.auth.passkey.webauthn.options_to_json",
                return_value='{"allowCredentials": []}',
            ),
        ):
            result = passkey_utils.begin_passkey_login()

        assert result == {"allowCredentials": []}
        assert passkey_utils.AUTH_CHALLENGE_SESSION_KEY in mock_session


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestCompletePasskeyLogin:
    def test_raises_when_no_challenge(self):
        with mock.patch("ckanext.auth.passkey.session", {}), pytest.raises(tk.ValidationError):
            passkey_utils.complete_passkey_login({})

    def test_raises_when_credential_not_found(self):
        mock_session = {passkey_utils.AUTH_CHALLENGE_SESSION_KEY: bytes_to_base64url(b"challenge")}
        data = _auth_data(b"unknown_cred_id")

        with mock.patch("ckanext.auth.passkey.session", mock_session), pytest.raises(tk.ObjectNotFound):
            passkey_utils.complete_passkey_login(data)

    def test_raises_on_verification_failure(self, passkey_record):
        mock_session = {passkey_utils.AUTH_CHALLENGE_SESSION_KEY: bytes_to_base64url(b"challenge")}
        data = _auth_data(b"test_cred_id")

        with (
            mock.patch("ckanext.auth.passkey.session", mock_session),
            mock.patch(
                "ckanext.auth.passkey.webauthn.verify_authentication_response",
                side_effect=Exception("bad sig"),
            ),
            pytest.raises(tk.ValidationError),
        ):
            passkey_utils.complete_passkey_login(data)

    def test_returns_user_and_updates_sign_count(self, user, passkey_record):
        mock_verification = mock.MagicMock()
        mock_verification.new_sign_count = 5
        mock_session = {passkey_utils.AUTH_CHALLENGE_SESSION_KEY: bytes_to_base64url(b"challenge")}
        data = _auth_data(b"test_cred_id")

        with (
            mock.patch("ckanext.auth.passkey.session", mock_session),
            mock.patch(
                "ckanext.auth.passkey.webauthn.verify_authentication_response",
                return_value=mock_verification,
            ),
        ):
            result = passkey_utils.complete_passkey_login(data)

        assert result.id == user["id"]
        updated = cast(AuthPasskey, AuthPasskey.get_by_credential_id(b"test_cred_id"))
        assert updated.sign_count == 5  # noqa PLR2004

    def test_raises_when_user_inactive(self, user, passkey_record):
        user_obj = cast(model.User, model.User.get(user["id"]))
        user_obj.state = model.State.DELETED
        model.Session.commit()

        mock_verification = mock.MagicMock()
        mock_verification.new_sign_count = 0
        mock_session = {passkey_utils.AUTH_CHALLENGE_SESSION_KEY: bytes_to_base64url(b"challenge")}
        data = _auth_data(b"test_cred_id")

        with (
            mock.patch("ckanext.auth.passkey.session", mock_session),
            mock.patch(
                "ckanext.auth.passkey.webauthn.verify_authentication_response",
                return_value=mock_verification,
            ),
            pytest.raises(tk.ObjectNotFound),
        ):
            passkey_utils.complete_passkey_login(data)
