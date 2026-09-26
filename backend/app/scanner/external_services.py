import re
from typing import List, Dict, Any, Tuple
from ..analysis.schemas import RiskFinding

KNOWN_SERVICES = {
    "stripe": {"name": "Stripe API", "type": "external_api", "category": "payment"},
    "paypal": {"name": "PayPal API", "type": "external_api", "category": "payment"},
    "twilio": {"name": "Twilio SMS", "type": "external_api", "category": "messaging"},
    "sendgrid": {"name": "SendGrid Email", "type": "external_api", "category": "email"},
    "firebase": {"name": "Firebase", "type": "external_api", "category": "auth/storage"},
    "auth0": {"name": "Auth0 Identity", "type": "external_api", "category": "auth"},
    "boto3": {"name": "AWS Services", "type": "external_api", "category": "cloud"},
    "aws": {"name": "AWS Cloud", "type": "external_api", "category": "cloud"},
    "google-cloud": {"name": "Google Cloud", "type": "external_api", "category": "cloud"},
    "openai": {"name": "OpenAI API", "type": "external_api", "category": "ai"},
    "postgres": {"name": "PostgreSQL", "type": "database", "category": "storage"},
    "postgresql": {"name": "PostgreSQL", "type": "database", "category": "storage"},
    "mysql": {"name": "MySQL", "type": "database", "category": "storage"},
    "redis": {"name": "Redis Cache", "type": "cache", "category": "cache"},
    "mongodb": {"name": "MongoDB", "type": "database", "category": "storage"},
    "kafka": {"name": "Apache Kafka", "type": "queue", "category": "streaming"},
    "rabbitmq": {"name": "RabbitMQ", "type": "queue", "category": "queue"},
}

def scan_external_services(files: List[Dict[str, Any]]) -> Tuple[List[RiskFinding], Dict[str, Dict[str, Any]]]:
    """Detect external services, missing timeouts, and external calls."""
    findings: List[RiskFinding] = []
    detected_services: Dict[str, Dict[str, Any]] = {}
    finding_counter = 1

    for file_info in files:
        filename = file_info.get("filename", "")
        patch = file_info.get("patch", "")
        content = file_info.get("content", "")
        text = patch if patch else content
        if not text:
            continue

        for idx, line in enumerate(text.splitlines(), start=1):
            # Focus on additions or content
            if patch and not (line.startswith("+") and not line.startswith("+++")):
                continue
            clean_line = line[1:].strip() if patch and line.startswith("+") else line.strip()

            # Check for known external providers
            lower_line = clean_line.lower()
            for key, meta in KNOWN_SERVICES.items():
                if key in lower_line:
                    detected_services[key] = meta

            # Check for HTTP client calls without timeout
            # e.g., requests.get(url) without timeout=
            if re.search(r'requests\.(get|post|put|delete)\([^)]*\)', clean_line):
                if "timeout" not in clean_line:
                    findings.append(RiskFinding(
                        id=f"finding-ext-{finding_counter:03d}",
                        category="external_service",
                        type="missing_timeout",
                        severity_hint="high",
                        confidence=0.92,
                        evidence=clean_line[:150],
                        file=filename,
                        line=idx,
                        changed=True,
                        description=(
                            "Synchronous HTTP request made without explicit timeout parameter. "
                            "If the external provider experiences network degradation, incoming requests will hang indefinitely, "
                            "exhausting server connection pools."
                        )
                    ))
                    finding_counter += 1

            # Check for httpx / aiohttp / axios / fetch without timeout
            if re.search(r'(?:httpx|client)\.(?:get|post|put|delete)\([^)]*\)', clean_line):
                if "timeout" not in clean_line and "request" not in clean_line:
                    findings.append(RiskFinding(
                        id=f"finding-ext-{finding_counter:03d}",
                        category="external_service",
                        type="missing_timeout",
                        severity_hint="medium",
                        confidence=0.88,
                        evidence=clean_line[:150],
                        file=filename,
                        line=idx,
                        changed=True,
                        description="External HTTP call detected without explicit timeout configuration."
                    ))
                    finding_counter += 1

            # Synchronous external API call in request path
            if re.search(r'https?://[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}[^\s"\'<>]*', clean_line):
                # An external hardcoded URL in code
                url_match = re.search(r'https?://[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}[^\s"\'<>]*', clean_line).group(0)
                if not any(local in url_match for local in ["localhost", "127.0.0.1", "example.com", "schema.org"]):
                    findings.append(RiskFinding(
                        id=f"finding-ext-{finding_counter:03d}",
                        category="external_service",
                        type="external_api_call",
                        severity_hint="medium",
                        confidence=0.90,
                        evidence=clean_line[:150],
                        file=filename,
                        line=idx,
                        changed=True,
                        description=f"Outbound network call to external service URL '{url_match}'. Introduces runtime availability dependency on external provider.",
                        metadata={"url": url_match}
                    ))
                    finding_counter += 1

    return findings, detected_services
