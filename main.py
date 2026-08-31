from __future__ import annotations

import argparse
import sys

from report import print_json, print_terminal, write_csv
from scanner.base import ScanConfig
from scanner.rules import run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llm-prompt-guard",
        description="Scan text for prompt injection, PII, and secrets before sending to an LLM.",
    )
    p.add_argument("--input", "-i", default="-", help="Input file path or '-' for stdin (default: stdin)")
    p.add_argument("--mode", choices=["input", "output", "both"], default="both",
                   help="What to scan: input, output, or both (default: both)")
    p.add_argument("--output", choices=["terminal", "json"], default="terminal",
                   help="Output format (default: terminal)")
    p.add_argument("--csv-path", metavar="PATH", help="Also write CSV report to PATH")
    p.add_argument("--fail-on-critical", action="store_true",
                   help="Exit with code 2 if any CRITICAL finding is detected")
    p.add_argument("--no-redact", action="store_true",
                   help="Show matched text without redaction (use with caution)")
    p.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   default="LOW", help="Minimum severity to report (default: LOW)")
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.input == "-":
        text = sys.stdin.read()
        source = "<stdin>"
    else:
        from pathlib import Path
        text = Path(args.input).read_text()
        source = args.input

    cfg = ScanConfig(
        redact=not args.no_redact,
        min_severity=args.min_severity,
        mode=args.mode,
    )

    findings = run_all(text, cfg)

    if args.output == "json":
        print_json(findings)
    else:
        print_terminal(findings, source=source)

    if args.csv_path:
        write_csv(findings, args.csv_path)

    if args.fail_on_critical and any(f.severity == "CRITICAL" for f in findings):
        sys.exit(2)


if __name__ == "__main__":
    main()
