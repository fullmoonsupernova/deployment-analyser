import os
import re
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from root if present
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(ROOT_DIR / ".env")

SCANNER_VERSION = "1.0.0"

class Settings:
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "").strip()
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "").strip()
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b").strip()
    APP_ENV: str = os.getenv("APP_ENV", "development").strip()
    HOST: str = os.getenv("HOST", "0.0.0.0").strip()
    PORT: int = int(os.getenv("PORT", "8000"))

settings = Settings()

# Regex patterns for redacting secrets from diffs, configs, and evidence
SECRET_PATTERNS = [
    # AWS Access Key ID
    (re.compile(r'\b(AKIA|ABIA|ACCA)[0-9A-Z]{16}\b'), "[REDACTED_AWS_KEY]"),
    # Generic API Keys / Tokens
    (re.compile(r'(?i)(api[_-]?key|secret|token|password|auth[_-]?token|bearer)\s*[:=]\s*["\']([^"\']{6,})["\']'), r'\1="[REDACTED_SECRET]"'),
    (re.compile(r'(?i)(api[_-]?key|secret|token|password|auth[_-]?token)\s*[:=]\s*([^\s,;]{8,})'), r'\1=[REDACTED_SECRET]'),
    # GitHub Tokens
    (re.compile(r'\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b'), "[REDACTED_GITHUB_TOKEN]"),
    # Private Key blocks
    (re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----'), "[REDACTED_PRIVATE_KEY]"),
    # JWT Tokens
    (re.compile(r'\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b'), "[REDACTED_JWT]"),
    # Database connection URIs with credentials
    (re.compile(r'(postgres|postgresql|mysql|mongodb|redis)://[^:@\s]+:[^@\s]+@'), r'\1://[USER]:[REDACTED]@'),
]

def redact_secrets(text: str) -> str:
    """Scrub sensitive credentials, API keys, passwords, and private keys."""
    if not text:
        return text
    scrubbed = text
    for pattern, replacement in SECRET_PATTERNS:
        scrubbed = pattern.sub(replacement, scrubbed)
    return scrubbed
