import re
from typing import List, Dict, Any, Optional
from ..analysis.schemas import RiskFinding
from ..config import redact_secrets
from .classifier import is_config_file

CONFIG_PATTERNS = [
    # DB Pool Size
    (
        re.compile(r'(?i)(db_pool_size|pool_size|max_connections|database_pool)\s*[:=]\s*(\d+)', re.IGNORECASE),
        "connection_pool_change",
        "medium",
        "Database connection pool size configured to {val}. Large increases can overwhelm database connection limits; reductions may cause request queuing."
    ),
    # Timeouts
    (
        re.compile(r'(?i)(request_timeout|http_timeout|timeout_seconds|read_timeout|connect_timeout)\s*[:=]\s*(\d+)', re.IGNORECASE),
        "timeout_configuration_change",
        "medium",
        "Network/request timeout configured to {val}s. Excessive timeouts lead to connection starvation under slow upstream; low timeouts cause false-positive failures."
    ),
    # Retries
    (
        re.compile(r'(?i)(max_retries|retry_count|retry_limit)\s*[:=]\s*(\d+)', re.IGNORECASE),
        "retry_configuration_change",
        "medium",
        "Retry count configured to {val}. High retry counts without jitter can trigger retry storms and cascade failure across downstream dependencies."
    ),
    # Debug Mode Enabled
    (
        re.compile(r'(?i)(debug|app_debug|flask_debug|django_debug)\s*[:=]\s*(true|1|yes)', re.IGNORECASE),
        "debug_mode_enabled",
        "high",
        "Debug mode enabled in configuration. Production deployments with debug mode leak stack traces, environment variables, and degrade throughput."
    ),
    # CORS Wildcard
    (
        re.compile(r'(?i)(cors_origins?|allow_origins?|access_control_allow_origin)\s*[:=]\s*["\']?\*["\']?', re.IGNORECASE),
        "cors_wildcard_exposure",
        "medium",
        "Permissive CORS wildcard '*' configured. Allows arbitrary external origins to execute authenticated cross-origin requests."
    ),
    # Rate Limit Disabled or Changed
    (
        re.compile(r'(?i)(rate_limit|throttle_rate)\s*[:=]\s*["\']?([^"\'\n]+)["\']?', re.IGNORECASE),
        "rate_limit_change",
        "low",
        "Rate limiting policy altered to '{val}'."
    ),
]

def scan_configuration_changes(files: List[Dict[str, Any]]) -> List[RiskFinding]:
    """Scan configuration files and diffs for risky runtime settings with automatic secret redaction."""
    findings: List[RiskFinding] = []
    finding_counter = 1

    for file_info in files:
        filename = file_info.get("filename", "")
        # Scan if it's a config file or has config-like names
        if not (is_config_file(filename) or filename.endswith(".env.example") or "config" in filename.lower() or "settings" in filename.lower()):
            continue

        patch = file_info.get("patch", "")
        content = file_info.get("content", "")
        text = patch if patch else content
        if not text:
            continue

        lines = text.splitlines()

        # Check for diff transitions (e.g. DB_POOL_SIZE: 20 -> 100)
        old_pool = None
        new_pool = None

        for idx, raw_line in enumerate(lines, start=1):
            if patch and not (raw_line.startswith("+") and not raw_line.startswith("+++")):
                if raw_line.startswith("-"):
                    m_pool = re.search(r'(?i)(?:db_pool_size|pool_size|max_connections)\s*[:=]\s*(\d+)', raw_line)
                    if m_pool:
                        old_pool = int(m_pool.group(1))
                continue

            line = raw_line[1:].strip() if patch and raw_line.startswith("+") else raw_line.strip()
            # Redact before analyzing/storing
            safe_line = redact_secrets(line)

            m_pool_new = re.search(r'(?i)(?:db_pool_size|pool_size|max_connections)\s*[:=]\s*(\d+)', safe_line)
            if m_pool_new:
                new_pool = int(m_pool_new.group(1))

            for pattern, ftype, severity, desc_template in CONFIG_PATTERNS:
                match = pattern.search(safe_line)
                if match:
                    val = match.group(2) if len(match.groups()) >= 2 else match.group(1)
                    desc = desc_template.format(val=val)
                    findings.append(RiskFinding(
                        id=f"finding-cfg-{finding_counter:03d}",
                        category="configuration",
                        type=ftype,
                        severity_hint=severity,
                        confidence=0.94,
                        evidence=safe_line[:150],
                        file=filename,
                        line=idx,
                        changed=True,
                        description=desc,
                        metadata={"key": match.group(1), "value": val}
                    ))
                    finding_counter += 1

        # Check if paired pool transition occurred
        if old_pool is not None and new_pool is not None and old_pool != new_pool:
            findings.append(RiskFinding(
                id=f"finding-cfg-{finding_counter:03d}",
                category="configuration",
                type="connection_pool_change",
                severity_hint="high" if new_pool > 2 * old_pool else "medium",
                confidence=0.97,
                evidence=f"DB connection pool: {old_pool} → {new_pool}",
                file=filename,
                changed=True,
                description=(
                    f"Connection pool size shifted significantly from {old_pool} to {new_pool}. "
                    f"A sudden jump to {new_pool} concurrent connections across multiple application instances "
                    "can exhaust database engine max_connections and cause connection refusal outages."
                ),
                metadata={"old_pool": old_pool, "new_pool": new_pool}
            ))
            finding_counter += 1

    return findings
