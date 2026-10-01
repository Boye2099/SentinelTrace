import argparse
import json
import sys
from pathlib import Path

from .analyzer import SecurityAnalyzer
from .parser import parse_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentineltrace",
        description="Security log intelligence engine.",
    )

    parser.add_argument(
        "log_file",
        help="Path to the authentication log file.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    log_path = Path(args.log_file)

    if not log_path.is_file():
        print(
            f"Error: log file not found: {log_path}",
            file=sys.stderr,
        )
        return 1

    try:
        events = parse_file(str(log_path))
    except OSError as exc:
        print(
            f"Error reading log file: {exc}",
            file=sys.stderr,
        )
        return 1

    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(events)

    if args.json:
        print(
            json.dumps(
                [finding.to_dict() for finding in findings],
                indent=2,
                default=str,
            )
        )
        return 0

    print()
    print("SentinelTrace Security Analysis")
    print("=" * 40)
    print(f"Events analyzed: {len(events)}")
    print(f"Findings:        {len(findings)}")
    print()

    if not findings:
        print("No security threats detected.")
        return 0

    for index, finding in enumerate(findings, start=1):
        print(f"[{index}] {finding.detection_type}")
        print(f"    Severity:   {finding.severity.value}")
        print(f"    Risk Score: {finding.risk_score}")

        if finding.username:
            print(f"    Username:   {finding.username}")

        if finding.source_ip:
            print(f"    Source IP:  {finding.source_ip}")

        print(f"    Description: {finding.description}")

        if finding.evidence:
            print("    Evidence:")

            for evidence in finding.evidence[:5]:
                print(f"      - {evidence}")

        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())