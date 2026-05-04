from __future__ import annotations

from typing import cast
from urllib import parse

import pytest

import ckan.plugins.toolkit as tk

from ckanext.auth.model import AuthPasskey, UserSecret

CODE_LENGTH = 6


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestUserSecretModel:
    def test_get_secret_for_user_missing(self, user):
        assert not UserSecret.get_for_user(user["name"])

    def test_create_for_user(self, user):
        secret = UserSecret.create_for_user(user["name"])

        assert secret.user_id == user["id"]
        assert secret.secret
        assert secret.last_access is None

    def test_get_secret_for_user(self, user):
        """The secret can be retrieved by user name or user ID."""
        secret = UserSecret.create_for_user(user["name"])

        assert UserSecret.get_for_user(user["name"]) == secret
        assert UserSecret.get_for_user(user["id"]) == secret

    def test_calling_create_again_rotates_the_secret(self, user):
        secret = UserSecret.create_for_user(user["name"])
        old_secret = secret.secret
        secret = UserSecret.create_for_user(user["name"])
        assert secret.secret != old_secret

    def test_create_for_missing_user(self):
        with pytest.raises(tk.ObjectNotFound):
            UserSecret.create_for_user("missing")

    def test_get_code(self, user):
        secret = UserSecret.create_for_user(user["name"])

        code = secret.get_code()

        assert code
        assert len(code) == CODE_LENGTH
        assert code.isdigit()

    def test_check_code(self, user):
        secret = UserSecret.create_for_user(user["name"])
        code = secret.get_code()

        assert secret.check_code(code)
        assert not secret.check_code("invalid")

    def test_check_code_updated_last_access(self, user):
        secret = UserSecret.create_for_user(user["name"])
        code = secret.get_code()

        assert not secret.last_access
        secret.check_code(code)
        assert secret.last_access

    def test_check_code_verify_only_once(self, user):
        """We use it for test verify on the user 2MA configure page."""
        secret = UserSecret.create_for_user(user["name"])
        code = secret.get_code()

        assert not secret.last_access
        assert secret.check_code(code, verify_only=True)
        assert not secret.last_access

    def test_provisioning_uri(self, user):
        secret = UserSecret.create_for_user(user["name"])

        assert secret.provisioning_uri
        assert "otpauth://totp" in secret.provisioning_uri
        assert user["name"] in secret.provisioning_uri
        assert cast(str, secret.secret) in secret.provisioning_uri
        assert parse.quote_plus(tk.config["ckan.site_url"]) in secret.provisioning_uri


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestAuthPasskeyModel:
    def test_create(self, user):
        passkey = AuthPasskey.create(
            user_id=user["id"],
            credential_id=b"cred_id",
            public_key=b"pub_key",
            sign_count=0,
            name="My Passkey",
        )

        assert passkey.id
        assert passkey.user_id == user["id"]
        assert passkey.credential_id == b"cred_id"
        assert passkey.public_key == b"pub_key"
        assert passkey.sign_count == 0
        assert passkey.name == "My Passkey"
        assert passkey.created is not None

    def test_get_by_credential_id(self, user):
        created = AuthPasskey.create(
            user_id=user["id"],
            credential_id=b"cred_id",
            public_key=b"pub_key",
            sign_count=0,
            name="Key",
        )

        found = AuthPasskey.get_by_credential_id(b"cred_id")

        assert found is not None
        assert found.id == created.id

    def test_get_by_credential_id_missing(self):
        assert AuthPasskey.get_by_credential_id(b"nonexistent") is None

    def test_get_for_user(self, user):
        AuthPasskey.create(user_id=user["id"], credential_id=b"cid_a", public_key=b"pk", sign_count=0, name="A")
        AuthPasskey.create(user_id=user["id"], credential_id=b"cid_b", public_key=b"pk", sign_count=0, name="B")

        passkeys = AuthPasskey.get_for_user(user["id"])

        assert len(passkeys) == 2  # noqa PLR2004

    def test_get_for_user_empty(self, user):
        assert AuthPasskey.get_for_user(user["id"]) == []

    def test_delete(self, user):
        passkey = AuthPasskey.create(
            user_id=user["id"],
            credential_id=b"cred_del",
            public_key=b"pk",
            sign_count=0,
            name="Delete Me",
        )

        passkey.delete()

        assert AuthPasskey.get_by_credential_id(b"cred_del") is None
