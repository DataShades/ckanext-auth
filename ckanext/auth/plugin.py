from __future__ import annotations

import logging

from flask import Response

import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
from ckan import types, model
from ckan.common import session

import ckanext.auth.utils as utils

log = logging.getLogger(__name__)


@tk.blanket.actions
@tk.blanket.auth_functions
@tk.blanket.helpers
@tk.blanket.blueprints
@tk.blanket.config_declarations
@tk.blanket.cli
class AuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ISignal)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, "templates")
        tk.add_resource("assets", "auth")

    # ISignal

    def get_signal_subscriptions(self) -> types.SignalMapping:
        return {
            tk.signals.ckanext.signal("ap_main:collect_config_sections"): [
                self.collect_config_sections_subs,
            ],
            tk.signals.ckanext.signal("ap_main:collect_config_schemas"): [
                self.collect_config_schemas_subs,
            ],
        }

    @staticmethod
    def collect_config_sections_subs(sender: None):
        return {
            "name": "Auth",
            "configs": [
                {
                    "name": "Configuration",
                    "blueprint": "auth_admin.config",
                    "info": "Auth settings",
                },
            ],
        }

    @staticmethod
    def collect_config_schemas_subs(sender: None):
        return ["ckanext.auth:config_schema.yaml"]

    # IAuthenticator

    def login(self):
        return utils.login()

    def identify(self) -> Response | None:
        if tk.current_user.is_authenticated:
            return

        user_id = session.get("_user_id")

        if not user_id:
            return

        user = model.User.get(user_id)

        if not user:
            return log.debug("No user found in database for user id %s", user_id)

        tk.g.user = user.name
        tk.g.userobj = user
