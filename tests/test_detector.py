from sentineltrace.detector import ThreatDetector
from sentineltrace.models import LoginEvent


def test_detect_brute_force():
    events = [
        LoginEvent(
            timestamp=f"Sep 23 08:0{i}",
            username="admin",
            ip_address="192.168.1.50",
            status="FAILED",
        )
        for i in range(6)
    ]

    detector = ThreatDetector(
        failed_login_threshold=5
    )

    alerts = detector.analyze(events)

    assert len(alerts) >= 1

    assert alerts[0].alert_type == "BRUTE_FORCE_ACTIVITY"

    assert alerts[0].severity == "HIGH"


def test_detect_success_after_failures():
    events = [
        LoginEvent(
            timestamp="Sep 23 08:01",
            username="admin",
            ip_address="192.168.1.50",
            status="FAILED",
        ),
        LoginEvent(
            timestamp="Sep 23 08:02",
            username="admin",
            ip_address="192.168.1.50",
            status="FAILED",
        ),
        LoginEvent(
            timestamp="Sep 23 08:03",
            username="admin",
            ip_address="192.168.1.50",
            status="FAILED",
        ),
        LoginEvent(
            timestamp="Sep 23 08:04",
            username="admin",
            ip_address="192.168.1.50",
            status="SUCCESS",
        ),
    ]

    detector = ThreatDetector()

    alerts = detector.analyze(events)

    assert any(
        alert.alert_type == "SUCCESS_AFTER_MULTIPLE_FAILURES"
        for alert in alerts
    )
