"""
SentinelTrace Detection Engine

Detects suspicious authentication activity, including:

1. Brute-force attacks
2. Password-spraying attacks
3. Possible account takeovers

All detection rules operate on normalized LogEvent objects.
"""

from collections import defaultdict
from datetime import timedelta

from .models import EventType, Finding, Severity


def _validate_threshold(threshold: int, window_minutes: int) -> None:
    """
    Ensure detection parameters contain valid positive values.
    """

    if threshold < 1:
        raise ValueError("Detection threshold must be at least 1.")

    if window_minutes < 1:
        raise ValueError("Time window must be at least 1 minute.")


def _find_matching_window(events, window):
    """
    Find the first group of events occurring within a time window.

    Events must already be sorted chronologically.
    """

    start = 0

    for end in range(len(events)):

        while (
            events[end].timestamp - events[start].timestamp
            > window
        ):
            start += 1

        yield events[start:end + 1]


def detect_brute_force(
    events,
    threshold=5,
    window_minutes=5,
):
    """
    Detect repeated failed login attempts against one account
    from one source IP address within a specified time window.

    Grouping by both username and IP prevents unrelated sources
    from being incorrectly attributed to one attacker.
    """

    _validate_threshold(threshold, window_minutes)

    failures_by_source = defaultdict(list)

    for event in events:

        if event.event_type != EventType.LOGIN_FAILURE:
            continue

        key = (event.username, event.source_ip)

        failures_by_source[key].append(event)

    findings = []

    window = timedelta(minutes=window_minutes)

    for (username, source_ip), failures in failures_by_source.items():

        failures.sort(key=lambda event: event.timestamp)

        for matching in _find_matching_window(failures, window):

            if len(matching) < threshold:
                continue

            findings.append(
                Finding(
                    detection_type="Brute Force",
                    severity=Severity.HIGH,
                    risk_score=80,
                    source_ip=source_ip,
                    username=username,
                    description=(
                        f"Detected {len(matching)} failed login "
                        f"attempts against '{username}' from "
                        f"{source_ip} within {window_minutes} minutes."
                    ),
                    evidence=[
                        event.raw_log
                        for event in matching
                    ],
                )
            )

            # One finding per username/source-IP combination.
            break

    return findings


def detect_password_spray(
    events,
    threshold=5,
    window_minutes=10,
):
    """
    Detect a source IP attempting to authenticate against
    multiple distinct usernames within a specified time window.

    Unlike brute-force detection, this focuses on the number
    of different accounts being targeted.
    """

    _validate_threshold(threshold, window_minutes)

    failures_by_ip = defaultdict(list)

    for event in events:

        if event.event_type != EventType.LOGIN_FAILURE:
            continue

        failures_by_ip[event.source_ip].append(event)

    findings = []

    window = timedelta(minutes=window_minutes)

    for source_ip, failures in failures_by_ip.items():

        failures.sort(key=lambda event: event.timestamp)

        for matching in _find_matching_window(failures, window):

            usernames = {
                event.username
                for event in matching
            }

            if len(usernames) < threshold:
                continue

            findings.append(
                Finding(
                    detection_type="Password Spraying",
                    severity=Severity.HIGH,
                    risk_score=85,
                    source_ip=source_ip,
                    description=(
                        f"Detected authentication failures against "
                        f"{len(usernames)} distinct accounts from "
                        f"{source_ip} within {window_minutes} minutes."
                    ),
                    evidence=[
                        event.raw_log
                        for event in matching
                    ],
                )
            )

            # One finding per source IP.
            break

    return findings


def detect_account_takeover(
    events,
    failure_threshold=5,
    window_minutes=10,
):
    """
    Detect a successful login following repeated failed
    authentication attempts against the same account.

    The successful login may originate from a different IP.
    This is useful for identifying suspicious authentication
    sequences involving multiple source addresses.

    This detection indicates suspicious activity, not
    confirmed account compromise.
    """

    _validate_threshold(failure_threshold, window_minutes)

    events_by_user = defaultdict(list)

    for event in events:

        if event.event_type not in (
            EventType.LOGIN_FAILURE,
            EventType.LOGIN_SUCCESS,
        ):
            continue

        events_by_user[event.username].append(event)

    findings = []

    window = timedelta(minutes=window_minutes)

    for username, account_events in events_by_user.items():

        account_events.sort(key=lambda event: event.timestamp)

        for index, event in enumerate(account_events):

            if event.event_type != EventType.LOGIN_SUCCESS:
                continue

            successful_login = event

            previous_failures = [
                previous
                for previous in account_events[:index]
                if (
                    previous.event_type == EventType.LOGIN_FAILURE
                    and previous.timestamp < successful_login.timestamp
                    and (
                        successful_login.timestamp - previous.timestamp
                        <= window
                    )
                )
            ]

            if len(previous_failures) < failure_threshold:
                continue

            findings.append(
                Finding(
                    detection_type="Possible Account Takeover",
                    severity=Severity.CRITICAL,
                    risk_score=95,
                    source_ip=successful_login.source_ip,
                    username=username,
                    description=(
                        f"Successful authentication for '{username}' "
                        f"occurred after {len(previous_failures)} "
                        f"failed login attempts within "
                        f"{window_minutes} minutes."
                    ),
                    evidence=[
                        previous.raw_log
                        for previous in previous_failures
                    ] + [
                        successful_login.raw_log
                    ],
                )
            )

    return findings