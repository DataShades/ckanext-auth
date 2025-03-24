ckan.module("auth-login-form", function () {
    'use strict';

    return {
        options: {
            enabled: true,
            mfaMethod: null,
            qrCodeSize: 300,
        },

        initialize() {
            $.proxyAll(this, /_/);

            if (!this.options.enabled) {
                return;
            }

            this.isEmailMfa = this.options.mfaMethod === "email";
            this.isTOTPMfa = !this.isEmailMfa;
            this.resendDisabled = false;
            this.mfaEmailSent = false;

            this.form = this.el;
            this.nextBtn = $("#mfa-next");
            this.submitBtn = this.form.find("#mfa-submit");
            this.loginForm = $("#login-form");
            this.resendCodeBtn = $("#resend-mfa");
            this.mfaForm = $("#mfa-form");
            this.mfaSetup = $("#mfa-qr-code");
            this.errorContainer = $("#mfa-error-container");

            // Bind events
            this.form.on("submit", this._onFormSubmit);
            this.submitBtn.on("click", this._onSubmitBtnClick);
            this.resendCodeBtn.on("click", this._onResendCodeClick);
        },

        _onFormSubmit: function (e) {
            e.preventDefault();

            this.nextBtn.prop("disabled", true);

            $.ajax({
                url: "/api/action/auth_2fa_check_credentials",
                method: "POST",
                data: this.form.serialize(),
                success: (resp) => {
                    if (resp.result.success) {
                        this._initMfaForm();
                    } else {
                        this._showError(resp.result.error);
                        grecaptcha.reset();
                    }
                },
                error: (resp) => {
                    console.error(resp);
                    grecaptcha.reset();
                },
                complete: () => {
                    this.nextBtn.prop("disabled", false);
                }
            });
        },

        _initMfaForm: function () {
            this.errorContainer.hide();
            this.loginForm.hide();
            this.mfaForm.show();

            if (this.isEmailMfa) {
                this._setResendCountdown();
                this._sendVerificationCode();
            } else {
                this._initQrCode();
            };
        },

        _setResendCountdown: function () {
            let countdownTime = 120; // 2 minutes
            let counterSpan = this.resendCodeBtn.find("span");

            this.resendDisabled = true;
            this.resendCodeBtn.prop("disabled", true);

            const countdownInterval = setInterval(() => {
                if (countdownTime <= 0) {
                    clearInterval(countdownInterval);
                    this.resendCodeBtn.prop("disabled", false);
                    counterSpan.text("");
                    this.resendDisabled = false;
                } else {
                    const minutes = Math.floor(countdownTime / 60);
                    const seconds = countdownTime % 60;
                    counterSpan.text(`(${minutes}:${seconds < 10 ? '0' : ''}${seconds})`);
                    countdownTime--;
                }
            }, 1000);
        },

        _onResendCodeClick: function (e) {
            e.preventDefault();

            if (this.resendDisabled || !this.mfaEmailSent) {
                return;
            }

            this._sendVerificationCode();
        },

        _sendVerificationCode: function () {
            $.ajax({
                url: "/mfa/send_verification_code",
                method: "POST",
                data: this.form.serialize(),
                success: (_) => {
                    this.errorContainer.hide();
                    this.mfaEmailSent = true;
                },
                error: (resp) => {
                    console.error(resp);
                },
                complete: () => {
                    this.submitBtn.prop("disabled", false);
                }
            });
        },


        _initQrCode: function () {
            $.ajax({
                url: "/mfa/init_qr_code",
                method: "POST",
                data: this.form.serialize(),
                success: (resp) => {
                    this.errorContainer.hide();

                    if (!resp.result.accessed) {
                        this.mfaSetup.show();

                        new QRious({
                            element: document.getElementById("mfa-qr-code-container"),
                            size: this.options.qrCodeSize,
                            value: resp.result.provisioning_uri
                        })

                        $("#mfa-secret").text(resp.result.secret);
                    };
                },
                error: (resp) => {
                    console.error(resp);
                },
                complete: () => {
                    this.submitBtn.prop("disabled", false);
                }
            });
        },

        /**
         * This function will actually submit the form and login the user
         * if the verification is successful.
         *
         * There's an additional authentication check on the backend,
         * in case if the user is trying to bypass the front end verification
         * and submit the form without the verification code.
         *
         * @param {Event} e - Event object
         */
        _onSubmitBtnClick: function (e) {
            e.preventDefault();

            this.submitBtn.prop("disabled", true);

            $.ajax({
                url: this.sandbox.url("/api/action/auth_2fa_user_login"),
                method: "POST",
                data: this.form.serialize(),
                success: (resp) => {
                    if (!resp.result.success) {
                        return this._showError(resp.result.error);
                    }

                    if (resp.result.valid) {
                        this.form.off("submit", this._onFormSubmit);
                        this.form.submit();
                    };
                },
                error: (resp) => {
                    console.error(resp);
                },
                complete: () => {
                    this.submitBtn.prop("disabled", false);
                }
            });
        },

        /**
         * Show error message to the user.
         *
         * @param {String} message - Error message
         */
        _showError: function (message) {
            this.errorContainer.find(".mfa-error-message").text(message);
            this.errorContainer.show();
        },
    }
})
