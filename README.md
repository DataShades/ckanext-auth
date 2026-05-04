[![Tests](https://github.com/DataShades/ckanext-auth/actions/workflows/test.yml/badge.svg)](https://github.com/DataShades/ckanext-auth/actions/workflows/test.yml)

__This extension partially based on the [ckanext-security](https://github.com/data-govt-nz/ckanext-security)__

The extension provides a 2FA authentication mechanism and passkey (WebAuthn) support for CKAN.

There are two methods of 2FA available:
- TOTP (Time-based One-Time Password) with authenticator apps like Google Authenticator, Authy, etc.
- Email

In addition, users can register and log in with **passkeys** — a passwordless authentication method based on the WebAuthn standard (fingerprint, Face ID, hardware security keys, etc.).


## Requirements

Python 3.10+

This extension uses __Redis__, so it must be configured for CKAN.

Compatibility with core CKAN versions:

| CKAN version    | Compatible?   |
| --------------- | ------------- |
| 2.9 and earlier | no            |
| 2.10            | yes           |
| 2.11            | yes           |

If you want to add compatibility with CKAN 2.9 and earlier, you can contact me
and I'll help you with that.

## Installation

To install ckanext-auth:

1. Activate your CKAN virtual environment, for example:
```sh
. /usr/lib/ckan/default/bin/activate
```
2. Clone the source and install it on the virtualenv
```sh
git clone https://github.com/DataShades/ckanext-auth.git
cd ckanext-auth
pip install -e .
```
3. Add `auth` to the `ckan.plugins` setting in your CKAN
   config file (by default the config file is located at
   `/etc/ckan/default/ckan.ini`).

4. Apply database migrations:
```
ckan db upgrade
```
5. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu:
```
sudo service apache2 reload
```

## Config settings

There are several configuration settings available for this extension. Check the config [declaration file](./ckanext/auth/config_declaration.yaml).

If you have the [ckanext-admin-panel](https://github.com/DataShades/ckanext-admin-panel) installed, the configuration settings will be available in the admin panel too.

### Passkey settings

| Setting | Default | Description |
| ------- | ------- | ----------- |
| `ckanext.auth.passkey_enabled` | `false` | Enable passkey (WebAuthn) authentication |
| `ckanext.auth.passkey_rp_name` | `CKAN` | Relying party display name shown to users during passkey registration. |
| `ckanext.auth.passkey_rp_id` | _(site hostname)_ | Relying party ID (domain) for passkey authentication. Defaults to the hostname of `ckan.site_url`. |

> **Note:** The `passkey_rp_id` must match the domain (without port) of the site URL. For example, if your site URL is `https://data.example.com`, the RP ID should be `data.example.com`.

## How to

- If you want to change the email for email 2FA, you can do it by creating a new template file at `auth/emails/verification_code.html`.

### Passkeys

When passkeys are enabled (`ckanext.auth.passkey_enabled = true`):

- A **Sign in with a passkey** button appears on the login page.
- Logged-in users can manage their passkeys (register new ones, delete existing ones) via the **Passkeys** tab on their user profile page (`/passkey/list/<username>`).
- Passkeys use the WebAuthn standard and support any authenticator the browser supports — biometrics (fingerprint, Face ID), device PINs, or hardware security keys.

## Tests

To run the tests, do:
```sh
pytest --ckan-ini=test.ini
```

## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
