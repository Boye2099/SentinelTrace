from sentineltrace.models import EventType
from sentineltrace.parser import parse_line


def test_failed_login_is_parsed():

    line = (
        "Oct 01 21:00:01 server sshd[1001]: "
        "Failed password for admin "
        "from 192.168.1.50 port 42100 ssh2"
    )

    event = parse_line(line)

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

    event = parse_line(line)

    assert event is not None
    assert event.username == "employee"
    assert event.source_ip == "172.16.0.20"
    assert event.event_type == EventType.LOGIN_SUCCESS


def test_unknown_log_returns_none():

    line = (
        "Oct 01 21:10:00 server systemd: "
        "Started background service."
    )

    event = parse_line(line)

    assert event is None