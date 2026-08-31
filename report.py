from __future__ import annotations

import csv
import json

from rich.console import Console
from rich.table import Table

from scanner.base import Finding

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


def print_terminal(findings: list[Finding], source: str = "-") -> None:
    console = Console()
    if not findings:
        console.print(f"[bold green]\u2713 No findings for {source!r}[/bold green]")
        return

    table = Table(title=f"llm-prompt-guard \u2014 {source}", show_lines=True)
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("Detail", max_width=50)

    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f.rule_id,
            f"[{color}]{f.severity}[/{color}]",
            f.category,
            f.title,
            f.detail,
        )
    console.print(table)


def print_json(findings: list[Finding]) -> None:
    data = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "detail": f.detail,
            "remediation": f.remediation,
        }
        for f in findings
    ]
    print(json.dumps(data, indent=2))


def write_csv(findings: list[Finding], path: str) -> None:
    fieldnames = ["rule_id", "severity", "category", "title", "detail", "remediation"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "remediation": f.remediation,
            })
