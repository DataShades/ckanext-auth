ckan.module("auth-passkey-login", function ($) {
    'use strict';

    return {
        initialize() {
            // Check if browser supports passkeys
            if (!window.PublicKeyCredential) {
                this.el.hide();
                return;
            }

            $.proxyAll(this, /_/);

            this.errorContainer = $("#mfa-error-container");
            this.el.on("click", this._onPasskeyLogin);
        },

        _onPasskeyLogin: async function (e) {
            e.preventDefault();

            this.el.prop("disabled", true);
            this.errorContainer.hide();

            try {
                const beginResp = await $.ajax({
                    url: ckan.url("/passkey/login/begin"),
                    method: "POST",
                    headers: this._csrfHeaders(),
                    dataType: "json",
                });

                if (!beginResp.success) {
                    return this._showError(beginResp.error);
                }

                const opts = beginResp.result;
                const publicKeyOptions = {
                    challenge: this._toBytes(opts.challenge),
                    rpId: opts.rpId,
                    timeout: opts.timeout || 60000,
                    userVerification: opts.userVerification || "preferred",
                    allowCredentials: (opts.allowCredentials || []).map(c => ({
                        id: this._toBytes(c.id),
                        type: c.type,
                    })),
                };

                const credential = await navigator.credentials.get({ publicKey: publicKeyOptions });

                const completeResp = await $.ajax({
                    url: ckan.url("/passkey/login/complete"),
                    method: "POST",
                    headers: this._csrfHeaders(),
                    contentType: "application/json",
                    data: JSON.stringify({
                        id: credential.id,
                        rawId: this._toBase64url(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON: this._toBase64url(credential.response.clientDataJSON),
                            authenticatorData: this._toBase64url(credential.response.authenticatorData),
                            signature: this._toBase64url(credential.response.signature),
                            userHandle: credential.response.userHandle
                                ? this._toBase64url(credential.response.userHandle)
                                : null,
                        },
                    }),
                    dataType: "json",
                });

                if (!completeResp.success) {
                    return this._showError(completeResp.error);
                }

                window.location.href = completeResp.result.next || "/";

            } catch (err) {
                if (err.name !== "NotAllowedError") {
                    this._showError(this._requestError(err, this._("Passkey authentication failed.")));
                }
            } finally {
                this.el.prop("disabled", false);
            }
        },

        _toBytes: function (base64url) {
            const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
            const binary = atob(base64);
            return Uint8Array.from(binary, c => c.charCodeAt(0));
        },

        _toBase64url: function (buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = "";
            bytes.forEach(b => { binary += String.fromCharCode(b); });
            return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
        },

        _csrfHeaders: function () {
            const field = $("meta[name=csrf_field_name]").attr("content");
            return { "X-CSRFToken": $(`meta[name=${field}]`).attr("content") };
        },

        _requestError: function (err, fallback) {
            if (err.message) {
                return err.message;
            }
            return err.status ? `${fallback} (HTTP ${err.status})` : fallback;
        },

        _showError: function (message) {
            const text = typeof message === "object" ? JSON.stringify(message) : message;
            this.errorContainer.find(".mfa-error-message").text(text);
            this.errorContainer.show();
        },
    };
});
