from __future__ import annotations

from ckan import types
from ckan.logic.schema import validator_args

from ckanext.auth import config as auth_config


@validator_args
def auth_2fa_user_login(
    not_missing: types.Validator,
    unicode_safe: types.Validator,
    one_of: types.ValidatorFactory,
) -> types.Schema:
    return {
        "login": [not_missing, unicode_safe],
        "password": [not_missing, unicode_safe],
        "code": [not_missing, unicode_safe],
        "mfa_type": [not_missing, unicode_safe, one_of(auth_config.ALLOWED_METHODS)],
    }
