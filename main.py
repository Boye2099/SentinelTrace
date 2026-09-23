import argparse
import os

from sentineltrace.parser import parse_log_file
from sentineltrace.detector import ThreatDetector
from sentineltrace.report import print_report, export_json


def main():
    parser = argparse.ArgumentParser(
        description="SentinelTrace Security Log Intelligence Engine"
    )

    parser.add_argument(
        "log_file",
        help="Path to the authentication log file",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required to trigger a brute-force alert",
    )

    parser.add_argument(
        "--output",
        default="output/alerts.json",
        help="Path for the JSON security report",
    )

    args = parser.parse_args()

    events = parse_log_file(args.log_file)

    detector = ThreatDetector(
        failed_login_threshold=args.threshold
    )

    alerts = detector.analyze(events)

    print_report(alerts)

    # Create the output directory if it doesn't exist.
    output_directory = os.path.dirname(args.output)

    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    export_json(alerts, args.output)

    print(f"\nJSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
