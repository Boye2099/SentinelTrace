from sentineltrace.models import EventType, LogEvent
from sentineltrace.detectors import (
    detect_account_takeover,
    detect_brute_force,
    detect_password_spray,
)
from datetime import datetime, timedelta


def make_event(
    seconds: int,
    username: str,
    ip: str,
    event_type: EventType,
) -> LogEvent:

    return LogEvent(
        timestamp=datetime(2026, 10, 1, 21, 0, 0)
        + timedelta(seconds=seconds),
        username=username,
        source_ip=ip,
        event_type=event_type,
        raw_log=f"{event_type.value} {username} {ip}",
    )


def test_brute_force_detection():

    events = [
        make_event(
            seconds=i * 10,
            username="admin",
            ip="192.168.1.50",
            event_type=EventType.LOGIN_FAILURE,
        )
        for i in range(10)
    ]

    findings = detect_brute_force(
        events,
        threshold=10,
    )

    assert len(findings) == 1
    assert findings[0].detection_type == "Brute Force"
    assert findings[0].username == "admin"


def test_password_spray_detection():

    usernames = [
        "user1",
        "user2",
        "user3",
        "user4",
        "user5",
    ]

    events = [
        make_event(
            seconds=i * 10,
            username=username,
            ip="10.0.0.25",
            event_type=EventType.LOGIN_FAILURE,
        )
        for i, username in enumerate(usernames)
    ]

    findings = detect_password_spray(
        events,
        threshold=5,
    )

    assert len(findings) == 1
    assert findings[0].detection_type == "Password Spraying"


def test_account_takeover_detection():

    events = [
        make_event(
            seconds=i * 10,
            username="employee",
            ip="172.16.0.20",
            event_type=EventType.LOGIN_FAILURE,
        )
        for i in range(5)
    ]

    events.append(
        make_event(
            seconds=60,
            username="employee",
            ip="172.16.0.20",
            event_type=EventType.LOGIN_SUCCESS,
        )
    )

    findings = detect_account_takeover(
        events,
        failure_threshold=5,
    )

    assert len(findings) == 1
    assert findings[0].detection_type == "Possible Account Takeover"