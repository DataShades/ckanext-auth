ckan.module("auth-passkey-register", function ($, _) {
    'use strict';

    return {
        initialize() {
          // Check if browser supports passkeys
            if (!window.PublicKeyCredential) {
                this.el.hide();
                return;
            }

            $.proxyAll(this, /_/);

            this.errorEl = this.el.find(".passkey-error");
            this.nameInput = this.el.find(".passkey-name-input");
            this.registerBtn = this.el.find(".passkey-register-btn");
            this.registerBtn.on("click", this._onRegister);
        },

        _onRegister: async function (e) {
            e.preventDefault();

            const name = this.nameInput.val().trim();
            this.registerBtn.prop("disabled", true);
            this.errorEl.hide();

            try {
                const beginResp = await $.ajax({
                    url: ckan.url("/passkey/register/begin"),
                    method: "POST",
                    dataType: "json",
                });

                if (!beginResp.success) {
                    return this._showError(beginResp.error);
                }

                const opts = beginResp.result;
                const publicKeyOptions = {
                    challenge: this._toBytes(opts.challenge),
                    rp: opts.rp,
                    user: {
                        id: this._toBytes(opts.user.id),
                        name: opts.user.name,
                        displayName: opts.user.displayName,
                    },
                    pubKeyCredParams: opts.pubKeyCredParams,
                    timeout: opts.timeout || 60000,
                    excludeCredentials: (opts.excludeCredentials || []).map(c => ({
                        id: this._toBytes(c.id),
                        type: c.type,
                    })),
                    authenticatorSelection: opts.authenticatorSelection,
                    attestation: opts.attestation || "none",
                };

                const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });

                const completeResp = await $.ajax({
                    url: ckan.url("/passkey/register/complete"),
                    method: "POST",
                    contentType: "application/json",
                    data: JSON.stringify({
                        name: name,
                        id: credential.id,
                        rawId: this._toBase64url(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON: this._toBase64url(credential.response.clientDataJSON),
                            attestationObject: this._toBase64url(credential.response.attestationObject),
                        },
                    }),
                    dataType: "json",
                });

                if (!completeResp.success) {
                    return this._showError(completeResp.error);
                }

                window.location.reload();

            } catch (err) {
                if (err.name !== "NotAllowedError") {
                    this._showError(err.message || _("Passkey registration failed."));
                }
            } finally {
                this.registerBtn.prop("disabled", false);
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

        _showError: function (message) {
            const text = typeof message === "object" ? JSON.stringify(message) : message;
            this.errorEl.text(text).show();
        },
    };
});
