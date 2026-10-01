from .detectors import (
    detect_account_takeover,
    detect_brute_force,
    detect_password_spray,
)
from .models import Finding, LogEvent


class SecurityAnalyzer:
    """
    Coordinates SentinelTrace detection rules.
    """

    def __init__(
        self,
        brute_force_threshold: int = 10,
        password_spray_threshold: int = 5,
        account_takeover_threshold: int = 5,
        window_seconds: int = 300,
    ):
        self.brute_force_threshold = brute_force_threshold
        self.password_spray_threshold = password_spray_threshold
        self.account_takeover_threshold = account_takeover_threshold
        self.window_seconds = window_seconds

    def analyze(self, events: list[LogEvent]) -> list[Finding]:
        """
        Run all detection rules against the supplied events.
        """

        findings: list[Finding] = []

        findings.extend(
            detect_brute_force(
                events,
                threshold=self.brute_force_threshold,
                window_seconds=self.window_seconds,
            )
        )

        findings.extend(
            detect_password_spray(
                events,
                threshold=self.password_spray_threshold,
                window_seconds=self.window_seconds,
            )
        )

        findings.extend(
            detect_account_takeover(
                events,
                failure_threshold=self.account_takeover_threshold,
                window_seconds=self.window_seconds,
            )
        )

        findings.sort(
            key=lambda finding: finding.risk_score,
            reverse=True,
        )

        return findings