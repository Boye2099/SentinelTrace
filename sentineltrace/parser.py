import re
from typing import List

from .models import LoginEvent


LOG_PATTERN = re.compile(
    r"(?P<timestamp>\S+\s+\S+)\s+"
    r"(?P<status>FAILED|SUCCESS)\s+"
    r"user=(?P<username>\S+)\s+"
    r"ip=(?P<ip>\S+)"
)


def parse_log_file(file_path: str) -> List[LoginEvent]:
    """Read a log file and convert valid entries into LoginEvent objects."""

    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            match = LOG_PATTERN.search(line)

            if not match:
                continue

            event = LoginEvent(
                timestamp=match.group("timestamp"),
                username=match.group("username"),
                ip_address=match.group("ip"),
                status=match.group("status"),
            )

            events.append(event)

    return events
