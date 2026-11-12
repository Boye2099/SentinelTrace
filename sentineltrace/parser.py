"""
SentinelTrace Log Parser

Responsible for:
1. Recognizing SSH authentication events.
2. Extracting timestamps, usernames and IP addresses.
3. Validating extracted IP addresses.
4. Normalizing events into LogEvent objects.
5. Handling malformed and unsupported log entries.
"""

import re
import ipaddress

from datetime import datetime

from .models import EventType, LogEvent


# Supported syslog timestamp format:
# Oct 01 21:00:01

TIMESTAMP_PATTERN = (
    r"(?P<timestamp>"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r")"
)


# Failed authentication attempts.
#
# Supports:
# Failed password for admin from 192.168.1.10
# Failed password for invalid user admin from 192.168.1.10
# Failed publickey for admin from 192.168.1.10

FAILED_LOGIN_PATTERN = re.compile(
    TIMESTAMP_PATTERN
    + r".*?\bFailed\s+"
    + r"(?:password|publickey|keyboard-interactive)"
    + r"\s+for\s+"
    + r"(?:invalid user\s+)?"
    + r"(?P<username>\S+)"
    + r"\s+from\s+"
    + r"(?P<ip>\S+)",
    re.IGNORECASE,
)


# Successful authentication attempts.
#
# Supports:
# Accepted password for admin from 192.168.1.10
# Accepted publickey for admin from 192.168.1.10

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    TIMESTAMP_PATTERN
    + r".*?\bAccepted\s+"
    + r"(?:password|publickey|keyboard-interactive)"
    + r"\s+for\s+"
    + r"(?P<username>\S+)"
    + r"\s+from\s+"
    + r"(?P<ip>\S+)",
    re.IGNORECASE,
)


def parse_timestamp(
    timestamp_string: str,
    year: int | None = None,
) -> datetime:
    """
    Convert a syslog timestamp into a Python datetime object.

    Traditional syslog timestamps do not include a year.

    If no year is supplied, the current year is used.
    """

    if year is None:
        year = datetime.now().year

    return datetime.strptime(
        f"{year} {timestamp_string}",
        "%Y %b %d %H:%M:%S",
    )


def validate_ip_address(ip_address: str) -> bool:
    """
    Validate IPv4 and IPv6 addresses.

    Invalid addresses return False instead of causing
    the parser to crash.
    """

    try:
        ipaddress.ip_address(ip_address)
        return True

    except ValueError:
        return False


def parse_line(
    line: str,
    year: int | None = None,
) -> LogEvent | None:
    """
    Parse one authentication log line.

    Returns:
        LogEvent: When a supported authentication event is found.

        None: When the line is empty, unsupported or malformed.
    """

    line = line.strip()

    if not line:
        return None

    # First, check for failed authentication.

    failed_match = FAILED_LOGIN_PATTERN.search(line)

    if failed_match:

        username = failed_match.group("username")
        source_ip = failed_match.group("ip")

        if not validate_ip_address(source_ip):
            return None

        try:
            timestamp = parse_timestamp(
                failed_match.group("timestamp"),
                year=year,
            )

        except ValueError:
            return None

        return LogEvent(
            timestamp=timestamp,
            username=username,
            source_ip=source_ip,
            event_type=EventType.LOGIN_FAILURE,
            raw_log=line,
        )

    # Next, check for successful authentication.

    success_match = SUCCESSFUL_LOGIN_PATTERN.search(line)

    if success_match:

        username = success_match.group("username")
        source_ip = success_match.group("ip")

        if not validate_ip_address(source_ip):
            return None

        try:
            timestamp = parse_timestamp(
                success_match.group("timestamp"),
                year=year,
            )

        except ValueError:
            return None

        return LogEvent(
            timestamp=timestamp,
            username=username,
            source_ip=source_ip,
            event_type=EventType.LOGIN_SUCCESS,
            raw_log=line,
        )

    # Unsupported events are ignored.

    return None


def parse_file(
    file_path: str,
    year: int | None = None,
) -> list[LogEvent]:
    """
    Parse an entire authentication log file.

    Events are sorted chronologically before being returned.

    Malformed individual lines are ignored without preventing
    the remaining file from being processed.
    """

    events: list[LogEvent] = []

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:

        for line in file:

            event = parse_line(
                line,
                year=year,
            )

            if event is not None:
                events.append(event)

    events.sort(
        key=lambda event: event.timestamp
    )

    return events