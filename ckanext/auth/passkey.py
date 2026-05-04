from __future__ import annotations

import json
import logging
from typing import Any

import webauthn
from flask import session
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

import ckan.plugins.toolkit as tk
from ckan import model
from ckan.lib.redis import connect_to_redis

import ckanext.auth.config as auth_config
from ckanext.auth.model import AuthPasskey

log = logging.getLogger(__name__)

REG_CHALLENGE_KEY = "ckanext-auth:passkey_reg_challenge:{}"
CHALLENGE_TTL = 300  # 5 minutes
AUTH_CHALLENGE_SESSION_KEY = "passkey_auth_challenge"


def begin_passkey_registration(user: model.User) -> dict[str, Any]:
    existing = AuthPasskey.get_for_user(user.id)
    exclude_credentials = [PublicKeyCredentialDescriptor(id=pk.credential_id) for pk in existing]

    options = webauthn.generate_registration_options(
        rp_id=auth_config.get_passkey_rp_id(),
        rp_name=auth_config.get_passkey_rp_name(),
        user_id=user.id.encode(),
        user_name=user.name,
        user_display_name=user.display_name or user.name,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    connect_to_redis().setex(
        REG_CHALLENGE_KEY.format(user.id),
        CHALLENGE_TTL,
        bytes_to_base64url(options.challenge),
    )

    return json.loads(webauthn.options_to_json(options))


def complete_passkey_registration(user: model.User, data: dict[str, Any], name: str) -> AuthPasskey:
    redis = connect_to_redis()
    raw_challenge: str | None = redis.get(REG_CHALLENGE_KEY.format(user.id))  # type: ignore

    if not raw_challenge:
        raise tk.ValidationError({"credential": ["Registration session expired or not found"]})

    challenge = base64url_to_bytes(raw_challenge.decode() if isinstance(raw_challenge, bytes) else raw_challenge)

    credential = RegistrationCredential(
        id=data["id"],
        raw_id=base64url_to_bytes(data["rawId"]),
        response=AuthenticatorAttestationResponse(
            client_data_json=base64url_to_bytes(data["response"]["clientDataJSON"]),
            attestation_object=base64url_to_bytes(data["response"]["attestationObject"]),
        ),
    )

    try:
        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=auth_config.get_passkey_rp_id(),
            expected_origin=tk.config["ckan.site_url"].rstrip("/"),
        )
    except Exception as e:
        log.warning("Passkey registration verification failed for user %s: %s", user.id, e)
        raise tk.ValidationError({"credential": [str(e)]}) from e

    redis.delete(REG_CHALLENGE_KEY.format(user.id))

    return AuthPasskey.create(
        user_id=user.id,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        name=name,
    )


def delete_passkey(passkey_id: str, current_user_id: str) -> None:
    passkey = model.Session.query(AuthPasskey).filter(AuthPasskey.id == passkey_id).first()

    if not passkey:
        raise tk.ObjectNotFound("Passkey not found")

    if passkey.user_id != current_user_id:
        raise tk.NotAuthorized("Not authorized to delete this passkey")

    passkey.delete()


def begin_passkey_login() -> dict[str, Any]:
    options = webauthn.generate_authentication_options(
        rp_id=auth_config.get_passkey_rp_id(),
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    session[AUTH_CHALLENGE_SESSION_KEY] = bytes_to_base64url(options.challenge)
    return json.loads(webauthn.options_to_json(options))


def complete_passkey_login(data: dict[str, Any]) -> model.User:
    challenge_b64 = session.pop(AUTH_CHALLENGE_SESSION_KEY, None)

    if not challenge_b64:
        raise tk.ValidationError({"credential": ["Authentication session expired or not found"]})

    challenge = base64url_to_bytes(challenge_b64)
    raw_credential_id = base64url_to_bytes(data["rawId"])
    passkey = AuthPasskey.get_by_credential_id(raw_credential_id)

    if not passkey:
        raise tk.ObjectNotFound("No passkey registered for this credential")

    credential = AuthenticationCredential(
        id=data["id"],
        raw_id=raw_credential_id,
        response=AuthenticatorAssertionResponse(
            client_data_json=base64url_to_bytes(data["response"]["clientDataJSON"]),
            authenticator_data=base64url_to_bytes(data["response"]["authenticatorData"]),
            signature=base64url_to_bytes(data["response"]["signature"]),
            user_handle=(
                base64url_to_bytes(data["response"]["userHandle"]) if data["response"].get("userHandle") else None
            ),
        ),
    )

    try:
        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=auth_config.get_passkey_rp_id(),
            expected_origin=tk.config["ckan.site_url"].rstrip("/"),
            credential_public_key=passkey.public_key,
            credential_current_sign_count=passkey.sign_count,
        )
    except Exception as e:
        log.warning("Passkey authentication failed for credential %s: %s", data.get("id"), e)
        raise tk.ValidationError({"credential": [str(e)]}) from e

    passkey.sign_count = verification.new_sign_count
    model.Session.commit()

    user = model.Session.query(model.User).filter(model.User.id == passkey.user_id).first()

    if not user or user.state != model.State.ACTIVE:
        raise tk.ObjectNotFound("User not found or inactive")

    return user
