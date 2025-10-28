from __future__ import annotations

import logging

import click

from ckanext.auth import model, utils

logger = logging.getLogger(__name__)

__all__ = [
    "auth",
]


@click.group()
def auth():
    pass


@auth.command()
@click.argument("username")
def reset_secret(username: str) -> None:
    utils.regenerate_user_secret(username)


@auth.command()
@click.argument("username")
def unblock_user(username: str) -> None:
    utils.LoginManager.reset_for_user(username)


@auth.command()
def unblock_all() -> None:
    utils.LoginManager.reset_all()


@auth.command()
@click.argument("username")
def get_code(username: str) -> None:
    secret = model.UserSecret.get_for_user(username)

    if not secret:
        secret = model.UserSecret.create_for_user(username)

    click.secho(f"Secret: {secret.get_code()}", fg="green")
