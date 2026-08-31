from dataclasses import dataclass

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    detail: str
    remediation: str
    matched: str


@dataclass
class ScanConfig:
    redact: bool = True
    min_severity: str = "LOW"
    mode: str = "both"
