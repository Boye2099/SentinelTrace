import re
from datetime import datetime

from .models import EventType, LogEvent


FAILED_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+)"
    r"\s+from\s+(?P<ip>\S+)"
)

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
    r"Accepted password for\s+"
    r"(?P<username>\S+)"
    r"\s+from\s+(?P<ip>\S+)"
)


def parse_timestamp(timestamp_string: str) -> datetime:
    """
    Parse a syslog-style timestamp.

    Syslog logs do not normally contain the year, so we use
    the current year.
    """

    current_year = datetime.now().year

    return datetime.strptime(
        f"{current_year} {timestamp_string}",
        "%Y %b %d %H:%M:%S",
    )


def parse_line(line: str) -> LogEvent | None:
    """
    Convert one raw log line into a LogEvent.

    Returns None when the line is not a supported
    authentication event.
    """

    line = line.strip()

    if not line:
        return None

    failed_match = FAILED_LOGIN_PATTERN.search(line)

    if failed_match:
        return LogEvent(
            timestamp=parse_timestamp(failed_match.group("timestamp")),
            username=failed_match.group("username"),
            source_ip=failed_match.group("ip"),
            event_type=EventType.LOGIN_FAILURE,
            raw_log=line,
        )

    success_match = SUCCESSFUL_LOGIN_PATTERN.search(line)

    if success_match:
        return LogEvent(
            timestamp=parse_timestamp(success_match.group("timestamp")),
            username=success_match.group("username"),
            source_ip=success_match.group("ip"),
            event_type=EventType.LOGIN_SUCCESS,
            raw_log=line,
        )

    return None


def parse_file(file_path: str) -> list[LogEvent]:
    """
    Parse an entire authentication log file.
    """

    events: list[LogEvent] = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_line(line)

            if event:
                events.append(event)

    events.sort(key=lambda event: event.timestamp)

    return events