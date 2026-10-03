# SentinelTrace

SentinelTrace is a Python security log intelligence engine that analyzes authentication logs and detects suspicious login activity.

It currently focuses on identifying brute-force attacks, password spraying, and possible account takeovers from authentication events.

The goal is simple: turn raw authentication logs into useful security findings.

## What it detects

* **Brute Force**
  Detects repeated failed login attempts against the same account within a defined time window.

* **Password Spraying**
  Detects a single source attempting authentication against multiple accounts.

* **Possible Account Takeover**
  Detects successful authentication following multiple failed attempts against the same account.

Each finding includes a severity level, risk score, affected account or source IP, description, and supporting log evidence.

## How it works

```text
Authentication Log
        ↓
      Parser
        ↓
   LogEvent objects
        ↓
 Security Analyzer
        ↓
 Detection Rules
        ↓
 Security Findings
        ↓
 CLI / JSON Output
```

SentinelTrace separates parsing, detection, analysis, and presentation so new detection rules can be added without rewriting the rest of the engine.

## Project Structure

```text
SentinelTrace/
├── sentineltrace/
│   ├── analyzer.py
│   ├── cli.py
│   ├── detectors.py
│   ├── models.py
│   └── parser.py
│
├── tests/
│   ├── test_detectors.py
│   └── test_parser.py
│
├── examples/
│   └── auth.log
│
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Getting Started

Clone the repository and move into the project:

```bash
git clone https://github.com/Boye2099/SentinelTrace.git
cd SentinelTrace
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

Run SentinelTrace against the example log:

```bash
python -m sentineltrace.cli examples/auth.log
```

For JSON output:

```bash
python -m sentineltrace.cli examples/auth.log --json
```

## Example

```text
SentinelTrace Security Analysis
========================================
Events analyzed: 15
Findings:        2

[1] Possible Account Takeover
    Severity:   CRITICAL
    Risk Score: 95
    Username:   admin
    Source IP:  192.168.1.20
    Description: Successful login for 'admin' occurred after
    5 failed authentication attempts within 5 minutes.
```

## Testing

Run the test suite with:

```bash
python -m pytest
```

The tests cover log parsing and the core detection rules.

## Built With

* Python
* pytest
* Regular expressions
* Dataclasses
* Python standard library

## Why I Built It

I wanted a project that went beyond simply parsing logs.

SentinelTrace is part of my work around cybersecurity, backend development, and security automation. Building it gave me a practical way to work with authentication events, detection logic, time-based analysis, structured findings, testing, and CLI tooling.

## Roadmap

Some of the things I want to explore next:

* More authentication log formats
* Better detection correlation
* Distributed attack detection
* Configurable detection rules
* Richer JSON output
* Additional test coverage
* REST API
* Dashboard for security findings
* Integration with other security tooling

---

Built with Python and a lot of logs.
