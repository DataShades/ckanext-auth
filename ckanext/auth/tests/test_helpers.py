from __future__ import annotations

import pytest

from ckanext.auth import helpers, config


class TestIs2FAEnabled:
    def test_enabled_by_default(self):
        assert helpers.is_2fa_enabled()

    @pytest.mark.ckan_config(config.CONF_2FA_ENABLED, False)
    def test_disabled(self):
        assert not helpers.is_2fa_enabled()


class TestGet2FAMethod:
    @pytest.mark.ckan_config(
        config.CONF_2FA_METHOD, config.METHOD_AUTHENTICATOR
    )
    def test_set_authenticator_method(self):
        assert helpers.get_2fa_method() == config.METHOD_AUTHENTICATOR

    @pytest.mark.ckan_config(config.CONF_2FA_METHOD, config.METHOD_EMAIL)
    def test_set_email_method(self):
        assert helpers.get_2fa_method() == config.METHOD_EMAIL

    def test_default_is_email(self):
        assert helpers.get_2fa_method() == config.METHOD_EMAIL


class TestIsTOTP2FAEnabled:
    def test_not_enabled_by_default(self):
        assert not helpers.is_totp_2fa_enabled()

    @pytest.mark.ckan_config(
        config.CONF_2FA_METHOD, config.METHOD_AUTHENTICATOR
    )
    def test_enabled(self):
        assert helpers.is_totp_2fa_enabled()


class TestIsDevModeEnabled:
    def test_not_enabled_by_default(self):
        assert not helpers.is_2fa_dev_mode_enabled()

    @pytest.mark.ckan_config(config.CONF_2FA_DEV_MODE, True)
    def test_enabled(self):
        assert helpers.is_2fa_dev_mode_enabled()
