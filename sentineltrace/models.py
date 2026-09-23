
from dataclasses import dataclass


@dataclass
class LoginEvent:
    timestamp: str
    username: str
    ip_address: str
    status: str


@dataclass
class SecurityAlert:
    alert_type: str
    severity: str
    username: str
    ip_address: str
    description: str
    evidence: str
