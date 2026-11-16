"""
SentinelTrace Parser Tests

Tests the reliability of authentication log parsing,
timestamp handling, IP validation and file processing.
"""

import pytest

from datetime import datetime

from sentineltrace.models import EventType
from sentineltrace.parser import (
    parse_line,
    parse_file,
    parse_timestamp,
    validate_ip_address,
)


# --------------------------------------------------
# BASIC AUTHENTICATION TESTS
# --------------------------------------------------


def test_failed_login_is_parsed():

    line = (
        "Oct 01 21:00:01 server sshd[1001]: "
        "Failed password for admin "
        "from 192.168.1.50 port 42100 ssh2"
    )

    event = parse_line(line, year=2026)

    assert event is not None
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.50"
    assert event.event_type == EventType.LOGIN_FAILURE


def test_successful_login_is_parsed():

    line = (
        "Oct 01 21:03:50 server sshd[1023]: "
        "Accepted password for employee "
        "from 172.16.0.20 port 44006 ssh2"
    )

    event = parse_line(line, year=2026)

    assert event is not None
    assert event.username == "employee"
    assert event.source_ip == "172.16.0.20"
    assert event.event_type == EventType.LOGIN_SUCCESS


# --------------------------------------------------
# AUTHENTICATION METHOD TESTS
# --------------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "password",
        "publickey",
        "keyboard-interactive",
    ],
)
def test_failed_authentication_methods(method):

    line = (
        f"Oct 01 21:00:01 server sshd[1001]: "
        f"Failed {method} for admin "
        f"from 192.168.1.50 port 42100 ssh2"
    )

    event = parse_line(line, year=2026)

    assert event is not None
    assert event.event_type == EventType.LOGIN_FAILURE


@pytest.mark.parametrize(
    "method",
    [
        "password",
        "publickey",
        "keyboard-interactive",
    ],
)
def test_successful_authentication_methods(method):

    line = (
        f"Oct 01 21:00:01 server sshd[1001]: "
        f"Accepted {method} for admin "
        f"from 192.168.1.50 port 42100 ssh2"
    )

    event = parse_line(line, year=2026)

    assert event is not None
    assert event.event_type == EventType.LOGIN_SUCCESS


# --------------------------------------------------
# USERNAME TESTS
# --------------------------------------------------


def test_invalid_username_is_parsed():

    line = (
        "Oct 01 21:00:01 server sshd[1001]: "
        "Failed password for invalid user attacker "
        "from 192.168.1.50 port 42100 ssh2"
    )

    event = parse_line(line, year=2026)

    assert event is not None
    assert event.username == "attacker"


# --------------------------------------------------
# IP ADDRESS VALIDATION TESTS
# --------------------------------------------------


@pytest.mark.parametrize(
    "ip_address",
    [
        "192.168.1.50",
        "10.0.0.1",
        "127.0.0.1",
        "2001:db8::1",
        "::1",
    ],
)
def test_valid_ip_addresses(ip_address):

    assert validate_ip_address(ip_address) is True


@pytest.mark.parametrize(
    "ip_address",
    [
        "999.999.999.999",
        "invalid-ip",
        "192.168.1",
        "",
        "not.an.ip.address",
    ],
)
def test_invalid_ip_addresses(ip_address):

    assert validate_ip_address(ip_address) is False


def test_invalid_ip_log_is_rejected():

    line = (
        "Oct 01 21:00:01 server sshd[1001]: "
        "Failed password for admin "
        "from invalid-ip port 42100 ssh2"
    )

    event = parse_line(line, year=2026)

    assert event is None


# --------------------------------------------------
# TIMESTAMP TESTS
# --------------------------------------------------


def test_timestamp_parsing():

    timestamp = parse_timestamp(
        "Oct 01 21:00:01",
        year=2026,
    )

    assert timestamp == datetime(2026, 10, 1, 21, 0, 1)


def test_invalid_timestamp_is_rejected():

    line = (
        "Oct 35 25:70:90 server sshd[1001]: "
        "Failed password for admin "
        "from 192.168.1.50 port 42100 ssh2"
    )

    event = parse_line(line, year=2026)

    assert event is None


# --------------------------------------------------
# MALFORMED AND UNKNOWN LOG TESTS
# --------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "",
        " ",
        "This is not a valid authentication log",
        "Oct 01 21:10:00 server systemd: Started background service.",
        "Oct 01 21:00:01 server sshd: Failed password",
    ],
)
def test_malformed_and_unknown_logs_return_none(line):

    assert parse_line(line, year=2026) is None


# --------------------------------------------------
# FILE PROCESSING TESTS
# --------------------------------------------------


def test_parse_file_reads_authentication_events(tmp_path):

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "\n".join([
            "Oct 01 21:00:01 server sshd[1001]: "
            "Failed password for admin from 192.168.1.50 port 42100 ssh2",

            "Oct 01 21:03:50 server sshd[1023]: "
            "Accepted password for employee from 172.16.0.20 port 44006 ssh2",

            "Oct 01 21:10:00 server systemd: Started background service.",
        ]),
        encoding="utf-8",
    )

    events = parse_file(
        str(log_file),
        year=2026,
    )

    assert len(events) == 2

    assert events[0].event_type == EventType.LOGIN_FAILURE
    assert events[1].event_type == EventType.LOGIN_SUCCESS


def test_parse_file_sorts_events_chronologically(tmp_path):

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "\n".join([
            "Oct 01 21:05:00 server sshd[1001]: "
            "Failed password for admin from 192.168.1.50 port 42100 ssh2",

            "Oct 01 21:00:00 server sshd[1002]: "
            "Failed password for admin from 192.168.1.50 port 42101 ssh2",
        ]),
        encoding="utf-8",
    )

    events = parse_file(
        str(log_file),
        year=2026,
    )

    assert len(events) == 2

    assert events[0].timestamp < events[1].timestamp