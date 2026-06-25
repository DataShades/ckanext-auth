from __future__ import annotations

import pytest

from ckanext.auth.model import UserSecret
from ckanext.auth.views.mfa import Configure2FA


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
