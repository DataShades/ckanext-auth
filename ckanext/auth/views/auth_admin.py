from __future__ import annotations

import logging

from flask import Blueprint

from ckan.plugins import plugin_loaded
from ckan.plugins import toolkit as tk

log = logging.getLogger(__name__)

auth_admin = Blueprint("auth_admin", __name__)


if plugin_loaded("admin_panel"):
    from ckanext.ap_main.utils import ap_before_request
    from ckanext.ap_main.views.generics import ApConfigurationPageView

    auth_admin.before_request(ap_before_request)

    auth_admin.add_url_rule(
        "/admin-panel/auth/config",
        view_func=ApConfigurationPageView.as_view(
            "config",
            "ckanext_auth_config",
            page_title=tk._("Auth config"),
        ),
    )
