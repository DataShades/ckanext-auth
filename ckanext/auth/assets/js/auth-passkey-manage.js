ckan.module("auth-passkey-manage", function ($, _) {
    'use strict';

    return {
        initialize() {
            $.proxyAll(this, /_/);
            this.errorEl = this.el.find(".passkey-delete-error");
            this.el.on("click", ".passkey-delete-btn", this._onDelete);
        },

        _onDelete: async function (e) {
            e.preventDefault();

            const btn = $(e.currentTarget);
            const passkeyId = btn.data("passkey-id");

            btn.prop("disabled", true);
            this.errorEl.hide();

            if (!confirm(this._("Are you sure you want to delete this passkey?"))) {
                btn.prop("disabled", false);
                return;
            }

            try {
                const resp = await $.ajax({
                    url: ckan.url("/passkey/" + passkeyId),
                    method: "DELETE",
                    dataType: "json",
                });

                if (!resp.success) {
                    return this._showError(resp.error);
                }

                btn.closest("tr").remove();

                if (this.el.find(".passkey-list tbody tr").length === 0) {
                    this.el.find(".passkey-list").hide();
                    this.el.find(".passkey-empty").show();
                }

            } catch (err) {
                this._showError(err.message || _("Failed to remove passkey."));
                btn.prop("disabled", false);
            }
        },

        _showError: function (message) {
            const text = typeof message === "object" ? JSON.stringify(message) : message;
            this.errorEl.text(text).show();
        },
    };
});
