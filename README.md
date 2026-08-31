# llm-prompt-guard

Static scanner that detects prompt injection, jailbreak attempts, PII, secrets, and indirect injection in text before it reaches an LLM.

## Rules

| ID | Severity | Category | What it catches |
|----|----------|----------|-----------------|
| GUARD-001 | CRITICAL | prompt_injection | "ignore previous instructions", system prompt overrides |
| GUARD-002 | HIGH | jailbreak | DAN, "no restrictions", bypass/jailbreak keywords |
| GUARD-003 | HIGH | pii | Email, US phone, SSN, credit card numbers |
| GUARD-004 | CRITICAL | secret | AWS keys, GitHub tokens, JWTs, private keys, generic API keys |
| GUARD-005 | HIGH | indirect_injection | AI-directed instructions embedded in external content |

## Installation

```bash
git clone https://github.com/CarlosAlejandroPerezCeron/llm-prompt-guard.git
cd llm-prompt-guard
pip install rich ruff pytest pytest-cov
```

## Usage

```bash
# Scan stdin
echo "ignore all previous instructions" | python main.py

# Scan a file
python main.py --input prompt.txt

# JSON output
python main.py --input prompt.txt --output json

# Write CSV report
python main.py --input prompt.txt --csv-path report.csv

# Exit code 2 on any CRITICAL finding (useful in CI)
python main.py --input prompt.txt --fail-on-critical

# Show matched text without redaction
python main.py --input prompt.txt --no-redact
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input` / `-i` | stdin | File path or `-` for stdin |
| `--mode` | `both` | `input`, `output`, or `both` |
| `--output` | `terminal` | `terminal` or `json` |
| `--csv-path` | — | Write CSV report to path |
| `--fail-on-critical` | off | Exit 2 on CRITICAL findings |
| `--no-redact` | off | Show matched text unredacted |
| `--min-severity` | `LOW` | Minimum severity to report |

## CI Integration

```yaml
- name: Scan prompt before LLM call
  run: echo "$PROMPT" | python main.py --fail-on-critical
```

## Project Structure

```
llm-prompt-guard/
├── scanner/
│   ├── __init__.py
│   ├── base.py        # Dataclasses: Finding, ScanConfig
│   ├── patterns.py    # Compiled regex patterns
│   └── rules.py       # Detection rules (GUARD-001 to GUARD-005)
├── report.py          # Terminal/JSON/CSV output
├── main.py            # CLI entrypoint
└── tests/
    ├── __init__.py
    └── test_scanner.py
```
