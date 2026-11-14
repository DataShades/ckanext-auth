from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timezone

import click

from ckanext.auth import model, utils

logger = logging.getLogger(__name__)

__all__ = [
    "auth",
]
OTP_LOG_EVENT_RE = re.compile(
    r"2FA email OTP event=(?P<event>send|verify) username=(?P<username>\S+) "
    r"outcome=(?P<outcome>sent|failed|verified|invalid|expired|error) status=\d{3}"
    r"(?: request_time=(?P<request_time>\S+) interval_s=(?P<interval_s>\d+|unknown)"
    r"(?: previous_window_match=(?P<previous_window_match>true|false|unknown))?)?(?=\s|$)",
)


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


@auth.command("otp-stats")
@click.argument("log_file", type=click.Path(exists=True, readable=True, dir_okay=False))
def otp_stats(log_file: str) -> None:  # noqa: C901, PLR0912, PLR0915
    """Summarize email OTP outcomes in one existing log file.

    Reads one file only. Retries count as separate attempts. Request times are
    approximate send-to-verify correlation, not the exact OTP generation time.
    Previous-window matches use the current stored secret; a false result does
    not rule out secret rotation. Requires ckanext.auth.middleware at INFO.
    """
    counts: Counter[str] = Counter()
    latest_successful_send: dict[str, datetime | None] = {}
    previous_window_matches: Counter[str] = Counter()
    send_delay_count = 0
    send_delay_total = 0.0
    send_delay_max = 0.0
    previous_window_within_interval = 0
    failed_verifications = 0

    click.echo("Unsuccessful OTP attempts (request time; send delay is approximate):")
    try:
        with open(log_file, encoding="utf-8", errors="replace") as stream:
            for line in stream:
                match = OTP_LOG_EVENT_RE.search(line)
                if not match:
                    continue

                event = match.group("event")
                username = match.group("username")
                outcome = match.group("outcome")
                counts[f"{event}_{outcome}"] += 1
                request_time = _parse_otp_request_time(match.group("request_time"))

                if event == "send" and outcome == "sent":
                    if username != "unknown":
                        existing_send = latest_successful_send.get(username)
                        if request_time is None:
                            latest_successful_send[username] = None
                        elif existing_send is None or request_time > existing_send:
                            latest_successful_send[username] = request_time
                elif event == "verify" and outcome in {"invalid", "expired", "error"}:
                    failed_verifications += 1
                    previous_match = match.group("previous_window_match") or "unknown"
                    previous_window_matches[previous_match] += 1
                    interval_text = match.group("interval_s")
                    interval_s = int(interval_text) if interval_text and interval_text.isdigit() else None

                    latest_send = latest_successful_send.get(username) if username != "unknown" else None
                    delay: float | None = None
                    if request_time is not None and latest_send is not None and latest_send <= request_time:
                        delay = (request_time - latest_send).total_seconds()
                        send_delay_count += 1
                        send_delay_total += delay
                        send_delay_max = max(send_delay_max, delay)

                    request_time_text = _format_otp_request_time(request_time)
                    delay_text = f"{delay:.1f}s" if delay is not None else "unknown"
                    interval_report = f"{interval_s}s" if interval_s is not None else "unknown"
                    if previous_match == "true" and delay is not None and interval_s is not None and delay < interval_s:
                        previous_window_within_interval += 1
                    click.echo(
                        f"  request_time={request_time_text} username={username} outcome={outcome} "
                        f"interval_s={interval_report} previous_window_match={previous_match} "
                        f"seconds_since_latest_send={delay_text}",
                    )
    except OSError as error:
        raise click.ClickException(f"Unable to read log file: {error}") from error

    if not failed_verifications:
        click.echo("  None")

    sends = counts["send_sent"] + counts["send_failed"]
    verifications = sum(counts[f"verify_{outcome}"] for outcome in ("verified", "invalid", "expired", "error"))
    failures = sum(counts[f"verify_{outcome}"] for outcome in ("invalid", "expired", "error"))

    click.echo("\nSummary:")
    click.echo(f"Email OTP sends: {counts['send_sent']} sent, {counts['send_failed']} failed ({sends} total)")
    click.echo(f"OTP verifications: {verifications}")
    click.echo(f"  Verified: {counts['verify_verified']}")
    click.echo(f"  Invalid: {counts['verify_invalid']}")
    click.echo(f"  Expired: {counts['verify_expired']}")
    click.echo(f"  Errors: {counts['verify_error']}")
    if verifications:
        click.echo(f"  Overall unsuccessful: {failures / verifications:.1%} ({failures}/{verifications})")
    else:
        click.echo("  Overall unsuccessful: N/A (no OTP submissions)")
    click.echo(
        "  Previous-window matches (current secret): "
        f"true={previous_window_matches['true']} false={previous_window_matches['false']} "
        f"unknown={previous_window_matches['unknown']}",
    )
    click.echo(
        f"  Previous-window matches within interval of latest send (approximate): {previous_window_within_interval}",
    )
    if send_delay_count:
        click.echo(
            "  Failed verification delays since latest successful send request "
            "(approximate, known correlations): "
            f"n={send_delay_count} mean={send_delay_total / send_delay_count:.1f} "
            f"max={send_delay_max:.1f}",
        )
    else:
        click.echo("  Failed verification delays since latest successful send request: N/A")


def _parse_otp_request_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _format_otp_request_time(value: datetime | None) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z") if value else "unknown"
