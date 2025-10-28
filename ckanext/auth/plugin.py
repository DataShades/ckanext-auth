from __future__ import annotations

import logging
from typing import Any

from flask import Response

import ckan.plugins.toolkit as tk
from ckan import plugins as p
from ckan import types
from ckan.common import CKANConfig

from ckanext.auth import utils

log = logging.getLogger(__name__)


@tk.blanket.actions
@tk.blanket.auth_functions
@tk.blanket.helpers
@tk.blanket.blueprints
@tk.blanket.config_declarations
@tk.blanket.cli
class AuthPlugin(p.SingletonPlugin):
    p.implements(p.IConfigurer)
    p.implements(p.ISignal)
    p.implements(p.IAuthenticator, inherit=True)

    # IConfigurer

    def update_config(self, config_: CKANConfig) -> None:
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
    def collect_config_sections_subs(sender: None) -> dict[str, Any]:
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
    def collect_config_schemas_subs(sender: None) -> list[str]:
        return ["ckanext.auth:config_schema.yaml"]

    # IAuthenticator

    def login(self) -> str | Response:
        return utils.login()
