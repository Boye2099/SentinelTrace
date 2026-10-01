# SentinelTrace

SentinelTrace is a Python security log intelligence engine designed to analyze authentication activity and identify suspicious access patterns.

## Features

- Authentication log parsing
- Normalized security events
- Brute-force detection
- Password-spraying detection
- Account-takeover detection
- Risk scoring
- Severity classification
- CLI analysis
- JSON report generation
- Automated tests

## Architecture

```text
Raw Authentication Logs
          |
          v
       Parser
          |
          v
    Normalized Events
          |
          v
   Detection Engine
     /      |      \
    /       |       \
Brute    Password   Account
Force    Spray      Takeover
    \       |       /
     \      |      /
          v
     Risk Scoring
          |
          v
       Findings
          |
       +--+--+
       |     |
      CLI   JSON