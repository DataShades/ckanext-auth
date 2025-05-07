from typing import TypedDict


class UserIdentity(TypedDict):
    login: str
    password: str
    check_captcha: bool
