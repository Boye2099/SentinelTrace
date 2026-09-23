# SentinelTrace

### Security Log Intelligence & Threat Detection Engine

SentinelTrace is a Python-based security analysis tool that processes authentication logs and identifies suspicious login activity.

## Overview

Authentication logs can contain useful indicators of suspicious activity, but manually reviewing large amounts of log data is inefficient.

SentinelTrace automates this process by parsing authentication events and applying detection rules to identify potentially malicious behavior.

## Features

- Authentication log parsing
- Brute-force activity detection
- Detection of successful logins after repeated failures
- Severity-based security alerts
- JSON security reporting
- Configurable detection thresholds
- Automated unit tests
- Command-line interface

## Detection Rules

### Brute Force Activity

Triggers when an IP address exceeds the configured number of failed authentication attempts.

### Suspicious Authentication

Detects successful authentication following multiple failed attempts from the same IP address.

## Project Structure

```text
sentineltrace/
├── main.py
├── requirements.txt
├── sentineltrace/
│   ├── models.py
│   ├── parser.py
│   ├── detector.py
│   └── report.py
├── tests/
├── data/
└── output/
