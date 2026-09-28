import re

# --- Prompt injection ---
INJECTION = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:in\s+)?(?:developer|jailbreak|dan|unrestricted)\s+mode", re.IGNORECASE),
    re.compile(r"system\s+prompt\s*[:\-]\s*", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]|\[INST\]|<\|system\|>|<\|im_start\|>\s*system", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*[:\-]", re.IGNORECASE),
]

# --- Jailbreak ---
JAILBREAK = [
    re.compile(r"\bDAN\b"),
    re.compile(r"pretend\s+(you\s+are|to\s+be)\s+(?:an?\s+)?(?:ai\s+without|unrestricted|evil)", re.IGNORECASE),
    re.compile(r"roleplay\s+as.*?(?:ai|bot)\s+(without|has\s+no)", re.IGNORECASE),
    re.compile(r"you\s+have\s+no\s+(restrictions?|limits?|rules?|guidelines?)", re.IGNORECASE),
    re.compile(r"bypass\s+(safety|content|filter|restriction|censorship)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
]

# --- PII ---
EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
PHONE_US = re.compile(r"(?<!\d)(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD = re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b")

# --- Secrets ---
AWS_KEY = re.compile(r"\b(?:AKIA|ASIA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b")
GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")
JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
PRIVATE_KEY = re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----")
GENERIC_SECRET = re.compile(
    r"\b(?:secret|api_?key|auth_?token|access_?token)\s*[=:]\s*['\"]?[a-zA-Z0-9+/=_\-]{20,}",
    re.IGNORECASE,
)

# --- Indirect injection ---
INDIRECT = [
    re.compile(r"ATTENTION\s+AI", re.IGNORECASE),
    re.compile(r"\b(AI|LLM|GPT|Claude|assistant)\s*:\s*(ignore|disregard|forget)", re.IGNORECASE),
    re.compile(r"<!--\s*(ignore|disregard|system)\b", re.IGNORECASE),
]
