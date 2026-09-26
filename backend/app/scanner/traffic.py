import re
from typing import List, Dict, Any
from ..analysis.schemas import RiskFinding
from .classifier import is_code_file

def scan_traffic_sensitive_patterns(files: List[Dict[str, Any]]) -> List[RiskFinding]:
    """Detect architectural patterns that can fail catastrophically under production traffic."""
    findings: List[RiskFinding] = []
    finding_counter = 1

    for file_info in files:
        filename = file_info.get("filename", "")
        if not is_code_file(filename):
            continue

        patch = file_info.get("patch", "")
        content = file_info.get("content", "")
        text = patch if patch else content
        if not text:
            continue

        lines = text.splitlines()

        # Check for unbounded queries
        for idx, line in enumerate(lines, start=1):
            if patch and not (line.startswith("+") and not line.startswith("+++")):
                continue
            clean_line = line[1:].strip() if patch and line.startswith("+") else line.strip()

            # Unbounded SQL query without LIMIT
            if re.search(r'SELECT\s+.*FROM\s+[a-zA-Z0-9_]+', clean_line, re.IGNORECASE):
                if not re.search(r'LIMIT\s+\d+', clean_line, re.IGNORECASE) and not re.search(r'WHERE\s+[a-zA-Z0-9_.]+\s*=\s*(?::|\$|\?)', clean_line, re.IGNORECASE):
                    findings.append(RiskFinding(
                        id=f"finding-traf-{finding_counter:03d}",
                        category="traffic",
                        type="unbounded_query",
                        severity_hint="medium",
                        confidence=0.88,
                        evidence=clean_line[:150],
                        file=filename,
                        line=idx,
                        changed=True,
                        description=(
                            "Unbounded database SELECT query without explicit LIMIT clause detected. "
                            "In production, as table row counts grow, this query will cause linear latency spikes and memory bloat."
                        )
                    ))
                    finding_counter += 1

            # ORM unbounded fetches (.all(), findAll(), .fetch_all())
            if re.search(r'(?i)\.(all\(\)|find_all\(\)|findall\(\)|fetch_all\(\))', clean_line):
                findings.append(RiskFinding(
                    id=f"finding-traf-{finding_counter:03d}",
                    category="traffic",
                    type="missing_pagination",
                    severity_hint="medium",
                    confidence=0.89,
                    evidence=clean_line[:150],
                    file=filename,
                    line=idx,
                    changed=True,
                    description=(
                        "Unbounded ORM fetch (e.g. .all() / findAll()) in code path without pagination. "
                        "Under production traffic loads, loading full datasets into application memory risks container OOM crashes."
                    )
                ))
                finding_counter += 1

            # Retry loops or aggressive retries
            if re.search(r'(?i)(retry\s*=\s*5|max_retries\s*=\s*[4-9]|retries\s*=\s*[4-9]|stop_after_attempt\([4-9]\))', clean_line):
                findings.append(RiskFinding(
                    id=f"finding-traf-{finding_counter:03d}",
                    category="traffic",
                    type="retry_amplification",
                    severity_hint="medium",
                    confidence=0.91,
                    evidence=clean_line[:150],
                    file=filename,
                    line=idx,
                    changed=True,
                    description=(
                        "Aggressive retry threshold (≥4 attempts) configured in request handling path. "
                        "When downstream services experience transient slowness, rapid client-side retries amplify traffic by multiple orders of magnitude (retry storm)."
                    )
                ))
                finding_counter += 1

        # Check for composite traffic hazard across the whole file/patch
        # e.g., Route + Database Call + External HTTP Call + Missing Timeout
        has_route = bool(re.search(r'(?i)@(app|router|blueprint)\.(get|post|put|delete)', text))
        has_db = bool(re.search(r'(?i)(db\.query|session\.execute|SELECT\s+.*FROM|\.objects\.)', text))
        has_ext_http = bool(re.search(r'(?i)(requests\.(get|post)|httpx\.(get|post)|fetch\(|axios\.)', text))
        has_no_timeout = bool(re.search(r'requests\.(get|post)\((?!.*timeout=)', text)) or (has_ext_http and "timeout" not in text)

        if has_route and has_db and has_ext_http and has_no_timeout:
            findings.append(RiskFinding(
                id=f"finding-traf-{finding_counter:03d}",
                category="traffic",
                type="traffic_amplification_risk",
                severity_hint="high",
                confidence=0.94,
                evidence=f"Composite hazard in {filename}: HTTP Route + DB Query + External HTTP call without timeout",
                file=filename,
                changed=True,
                description=(
                    "Composite traffic hazard: An exposed HTTP endpoint orchestrates both database queries and an external API call without a timeout constraint. "
                    "Under high concurrency, minor latency from the third-party API will cascade backwards, tying up database connections and worker threads until the pod stops accepting traffic."
                ),
                metadata={"composite_pattern": ["route", "db", "external_api", "missing_timeout"]}
            ))
            finding_counter += 1

    return findings
