import json
from typing import List

from .models import SecurityAlert


def print_report(alerts: List[SecurityAlert]) -> None:
    """Display detected security alerts in the terminal."""

    print("\n" + "=" * 65)
    print("SENTINELTRACE SECURITY ANALYSIS")
    print("=" * 65)

    if not alerts:
        print("\nNo suspicious activity detected.")
        return

    print(f"\nAlerts detected: {len(alerts)}\n")

    for number, alert in enumerate(alerts, start=1):
        print(f"[{number}] {alert.alert_type}")
        print(f"Severity   : {alert.severity}")
        print(f"Username   : {alert.username}")
        print(f"IP Address : {alert.ip_address}")
        print(f"Description: {alert.description}")
        print(f"Evidence   : {alert.evidence}")
        print("-" * 65)


def export_json(
    alerts: List[SecurityAlert],
    output_path: str
) -> None:
    """Export security alerts as a JSON report."""

    data = [
        {
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "username": alert.username,
            "ip_address": alert.ip_address,
            "description": alert.description,
            "evidence": alert.evidence,
        }
        for alert in alerts
    ]

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)
