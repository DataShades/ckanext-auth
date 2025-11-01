[![Tests](https://github.com/DataShades/ckanext-auth/actions/workflows/test.yml/badge.svg)](https://github.com/DataShades/ckanext-auth/actions/workflows/test.yml)

__This extension partially based on the [ckanext-security](https://github.com/data-govt-nz/ckanext-security)__

The extension provides a 2FA authentication mechanism for CKAN.

There are two methods of 2FA available:
- TOTP (Time-based One-Time Password) with authenticator apps like Google Authenticator, Authy, etc.
- Email


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

## How to

- If you want to change the email for email 2FA, you can do it by creating a new template file at `auth/emails/verification_code.html`.

## Tests

To run the tests, do:
```sh
pytest --ckan-ini=test.ini
```

## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
