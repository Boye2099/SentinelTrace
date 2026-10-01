from collections import defaultdict
from datetime import timedelta

from .models import EventType, Finding, Severity


def detect_brute_force(
    events,
    threshold=5,
    window_minutes=5,
):
    """
    Detect repeated failed login attempts against the same account
    within a defined time window.
    """

    failures_by_user = defaultdict(list)

    for event in events:
        if event.event_type == EventType.LOGIN_FAILURE:
            failures_by_user[event.username].append(event)

    findings = []
    window = timedelta(minutes=window_minutes)

    for username, failures in failures_by_user.items():
        failures.sort(key=lambda event: event.timestamp)

        for index in range(len(failures)):
            start = failures[index].timestamp

            matching = [
                event
                for event in failures[index:]
                if event.timestamp - start <= window
            ]

            if len(matching) >= threshold:
                findings.append(
                    Finding(
                        detection_type="Brute Force",
                        severity=Severity.HIGH,
                        risk_score=80,
                        source_ip=matching[0].source_ip,
                        username=username,
                        description=(
                            f"Detected {len(matching)} failed login "
                            f"attempts against '{username}' within "
                            f"{window_minutes} minutes."
                        ),
                        evidence=[
                            event.raw_log
                            for event in matching
                        ],
                    )
                )
                break

    return findings


def detect_password_spray(
    events,
    threshold=5,
    window_minutes=10,
):
    """
    Detect a single source IP attempting authentication
    against multiple usernames within a time window.
    """

    failures_by_ip = defaultdict(list)

    for event in events:
        if event.event_type == EventType.LOGIN_FAILURE:
            failures_by_ip[event.source_ip].append(event)

    findings = []
    window = timedelta(minutes=window_minutes)

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda event: event.timestamp)

        for index in range(len(failures)):
            start = failures[index].timestamp

            matching = [
                event
                for event in failures[index:]
                if event.timestamp - start <= window
            ]

            usernames = {
                event.username
                for event in matching
            }

            if len(usernames) >= threshold:
                findings.append(
                    Finding(
                        detection_type="Password Spraying",
                        severity=Severity.HIGH,
                        risk_score=85,
                        source_ip=source_ip,
                        description=(
                            f"Detected password spraying from "
                            f"{source_ip} against "
                            f"{len(usernames)} accounts."
                        ),
                        evidence=[
                            event.raw_log
                            for event in matching
                        ],
                    )
                )
                break

    return findings


def detect_account_takeover(
    events,
    failure_threshold=5,
    window_minutes=10,
):
    """
    Detect a successful login shortly after repeated failed
    authentication attempts against the same account.
    """

    events_by_user = defaultdict(list)

    for event in events:
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
                    and successful_login.timestamp - previous.timestamp
                    <= window
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
                        f"Successful login for '{username}' occurred "
                        f"after {len(previous_failures)} failed "
                        f"authentication attempts within "
                        f"{window_minutes} minutes."
                    ),
                    evidence=[
                        event.raw_log
                        for event in previous_failures
                    ]
                    + [successful_login.raw_log],
                )
            )

    return findings