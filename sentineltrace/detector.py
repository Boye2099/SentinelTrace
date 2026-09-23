from collections import defaultdict
from typing import List

from .models import LoginEvent, SecurityAlert


class ThreatDetector:
    """Detect suspicious authentication activity."""

    def __init__(self, failed_login_threshold: int = 5):
        self.failed_login_threshold = failed_login_threshold

    def analyze(self, events: List[LoginEvent]) -> List[SecurityAlert]:
        """Analyze login events and generate security alerts."""

        alerts = []

        failed_attempts = defaultdict(int)

        # Count failed attempts from each IP address.
        for event in events:
            if event.status == "FAILED":
                failed_attempts[event.ip_address] += 1

        # Detect possible brute-force activity.
        for ip_address, count in failed_attempts.items():
            if count >= self.failed_login_threshold:
                alerts.append(
                    SecurityAlert(
                        alert_type="BRUTE_FORCE_ACTIVITY",
                        severity="HIGH",
                        username="multiple",
                        ip_address=ip_address,
                        description=(
                            f"{count} failed authentication attempts "
                            f"detected from {ip_address}"
                        ),
                        evidence=f"Failed attempts: {count}",
                    )
                )

        # Detect successful authentication after multiple failures.
        for index, event in enumerate(events):

            if event.status != "SUCCESS":
                continue

            previous_events = events[:index]

            recent_failures = [
                previous
                for previous in previous_events
                if (
                    previous.ip_address == event.ip_address
                    and previous.status == "FAILED"
                )
            ]

            if len(recent_failures) >= 3:
                alerts.append(
                    SecurityAlert(
                        alert_type="SUCCESS_AFTER_MULTIPLE_FAILURES",
                        severity="CRITICAL",
                        username=event.username,
                        ip_address=event.ip_address,
                        description=(
                            "Successful authentication occurred after "
                            "multiple failed attempts"
                        ),
                        evidence=(
                            f"{len(recent_failures)} previous failed "
                            "authentication attempts"
                        ),
                    )
                )

        return alerts
