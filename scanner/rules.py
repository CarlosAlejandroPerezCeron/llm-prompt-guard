from __future__ import annotations

import re

from . import patterns as P
from .base import SEVERITY_ORDER, Finding, ScanConfig


def check_prompt_injection(text: str, cfg: ScanConfig) -> list[Finding]:
    findings = []
    for pat in P.INJECTION:
        m = pat.search(text)
        if m:
            matched = m.group(0)
            if cfg.redact:
                matched = "*" * len(matched)
            findings.append(Finding(
                rule_id="GUARD-001",
                severity="CRITICAL",
                category="prompt_injection",
                title="Prompt injection attempt detected",
                detail=f"Pattern matched: {matched!r}",
                remediation="Sanitize user input before passing to LLM. Use an allowlist for system prompt modifications.",
                matched=matched,
            ))
            break
    return findings


def check_jailbreak(text: str, cfg: ScanConfig) -> list[Finding]:
    findings = []
    for pat in P.JAILBREAK:
        m = pat.search(text)
        if m:
            matched = m.group(0)
            if cfg.redact:
                matched = "*" * len(matched)
            findings.append(Finding(
                rule_id="GUARD-002",
                severity="HIGH",
                category="jailbreak",
                title="Jailbreak attempt detected",
                detail=f"Pattern matched: {matched!r}",
                remediation="Filter jailbreak patterns before forwarding to model. Consider rate-limiting repeat offenders.",
                matched=matched,
            ))
            break
    return findings


def check_pii(text: str, cfg: ScanConfig) -> list[Finding]:
    findings = []
    checks = [
        (P.EMAIL, "email address"),
        (P.PHONE_US, "US phone number"),
        (P.SSN, "Social Security Number"),
        (P.CREDIT_CARD, "credit card number"),
    ]
    for pat, label in checks:
        m = pat.search(text)
        if m:
            matched = m.group(0)
            if cfg.redact:
                matched = "[REDACTED]"
            findings.append(Finding(
                rule_id="GUARD-003",
                severity="HIGH",
                category="pii",
                title=f"PII detected: {label}",
                detail=f"Found {label} in input.",
                remediation="Strip or mask PII before sending to LLM. Log separately with access controls.",
                matched=matched,
            ))
    return findings


def check_secrets(text: str, cfg: ScanConfig) -> list[Finding]:
    findings = []
    checks = [
        (P.AWS_KEY, "AWS access key"),
        (P.GITHUB_TOKEN, "GitHub token"),
        (P.JWT, "JSON Web Token"),
        (P.PRIVATE_KEY, "private key header"),
        (P.GENERIC_SECRET, "generic secret/API key"),
    ]
    for pat, label in checks:
        m = pat.search(text)
        if m:
            matched = m.group(0)
            if cfg.redact:
                matched = "[REDACTED]"
            findings.append(Finding(
                rule_id="GUARD-004",
                severity="CRITICAL",
                category="secret",
                title=f"Secret detected: {label}",
                detail=f"Found {label} in input.",
                remediation="Rotate credential immediately. Never pass secrets to LLM inputs.",
                matched=matched,
            ))
    return findings


def check_indirect_injection(text: str, cfg: ScanConfig) -> list[Finding]:
    findings = []
    for pat in P.INDIRECT:
        m = pat.search(text)
        if m:
            matched = m.group(0)
            if cfg.redact:
                matched = "*" * min(len(matched), 12)
            findings.append(Finding(
                rule_id="GUARD-005",
                severity="HIGH",
                category="indirect_injection",
                title="Indirect prompt injection detected",
                detail=f"Pattern matched: {matched!r}",
                remediation="Sanitize external content (emails, web pages) before injecting into prompts.",
                matched=matched,
            ))
            break
    return findings


ALL_RULES = [
    check_prompt_injection,
    check_jailbreak,
    check_pii,
    check_secrets,
    check_indirect_injection,
]


def run_all(text: str, cfg: ScanConfig | None = None) -> list[Finding]:
    if cfg is None:
        cfg = ScanConfig()
    results: list[Finding] = []
    for rule in ALL_RULES:
        if rule.__name__.startswith("check_"):
            findings = rule(text, cfg)
            results.extend(findings)
    return sorted(results, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
