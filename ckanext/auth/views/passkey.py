from __future__ import annotations

import logging

from flask import Blueprint, Response, jsonify, request

from ckan import types
from ckan.plugins import toolkit as tk
from ckan.views.user import rotate_token

from ckanext.auth import passkey as passkey_utils
import ckanext.auth.config as auth_config
from ckanext.auth import utils
from ckanext.auth.model import AuthPasskey

log = logging.getLogger(__name__)
passkey = Blueprint("auth_passkey", __name__, url_prefix="/passkey")


@passkey.route("/register/begin", methods=["POST"])
@utils.require_login
def passkey_register_begin() -> Response:
    if not auth_config.is_passkey_enabled():
        return tk.abort(404)

    try:
        options = passkey_utils.begin_passkey_registration(tk.current_user)
    except (OSError, RuntimeError, ValueError) as e:
        return jsonify({"success": False, "error": str(e), "result": None})

    return jsonify({"success": True, "error": None, "result": options})


@passkey.route("/register/complete", methods=["POST"])
@utils.require_login
def passkey_register_complete() -> Response:
    if not auth_config.is_passkey_enabled():
        return tk.abort(404)

    data = request.get_json(silent=True) or {}
    name = data.pop("name", "")

    try:
        passkey = passkey_utils.complete_passkey_registration(tk.current_user, data, name)
    except tk.ValidationError as e:
        return jsonify({"success": False, "error": e.error_dict, "result": None})
    except (KeyError, ValueError) as e:
        return jsonify({"success": False, "error": str(e), "result": None})

    return jsonify(
        {
            "success": True,
            "error": None,
            "result": {"id": passkey.id, "name": passkey.name},
        }
    )


@passkey.route("/login/begin", methods=["POST"])
def passkey_login_begin() -> Response:
    if not auth_config.is_passkey_enabled():
        return tk.abort(404)

    try:
        options = passkey_utils.begin_passkey_login()
    except (OSError, RuntimeError, ValueError) as e:
        return jsonify({"success": False, "error": str(e), "result": None})

    return jsonify({"success": True, "error": None, "result": options})


@passkey.route("/login/complete", methods=["POST"])
def passkey_login_complete() -> Response:
    if not auth_config.is_passkey_enabled():
        return tk.abort(404)

    data = request.get_json(silent=True) or {}

    try:
        user = passkey_utils.complete_passkey_login(data)
    except tk.ValidationError as e:
        return jsonify({"success": False, "error": e.error_dict, "result": None})
    except tk.ObjectNotFound as e:
        return jsonify({"success": False, "error": str(e), "result": None})
    except (KeyError, ValueError) as e:
        return jsonify({"success": False, "error": str(e), "result": None})

    tk.login_user(user)
    rotate_token()

    return jsonify(
        {
            "success": True,
            "error": None,
            "result": {"next": tk.url_for("home.index")},
        }
    )


@passkey.route("/<passkey_id>", methods=["DELETE"])
@utils.require_login
def passkey_delete(passkey_id: str) -> Response:
    if not auth_config.is_passkey_enabled():
        return tk.abort(404)

    try:
        passkey_utils.delete_passkey(passkey_id, tk.current_user.id)
    except tk.ObjectNotFound as e:
        return jsonify({"success": False, "error": str(e), "result": None})
    except tk.NotAuthorized:
        return tk.abort(403)

    return jsonify({"success": True, "error": None, "result": None})


@passkey.route("/list/<id>", methods=["GET"])
@utils.require_login
def passkeys(id: str) -> str | Response:
    if not auth_config.is_passkey_enabled():
        return tk.abort(404)

    try:
        user_dict = tk.get_action("user_show")(
            types.Context(
                user=tk.current_user.name,
                for_view=True,
            ),
            {"id": id, "include_num_followers": True},
        )
    except tk.ObjectNotFound:
        return tk.abort(404, tk._("User not found"))

    if user_dict["name"] != tk.current_user.name and not tk.current_user.sysadmin:
        return tk.abort(403, tk._("Not authorized to see this page"))

    return tk.render(
        "user/passkeys.html",
        {
            "user_dict": user_dict,
            "is_myself": user_dict["name"] == tk.current_user.name,
            "is_sysadmin": tk.current_user.sysadmin,
            "am_following": False,
            "passkeys": [
                {
                    "id": pk.id,
                    "name": pk.name or "",
                    "created": (pk.created.strftime("%Y-%m-%d %H:%M") if pk.created else ""),
                }
                for pk in AuthPasskey.get_for_user(user_dict["id"])
            ],
        },
    )
