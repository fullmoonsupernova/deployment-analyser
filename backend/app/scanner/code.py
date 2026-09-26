import re
from typing import List, Dict, Any, Optional
from ..analysis.schemas import RiskFinding
from .classifier import is_code_file

CODE_SIGNALS = [
    # Payment processing changes
    (
        re.compile(r'(?i)(stripe\.(charge|paymentintent|checkout|subscription|customer)|paypal|payment[_\s]?gateway|process_payment|create_charge)', re.IGNORECASE),
        "payment_processing_change",
        "high",
        "Payment processing logic altered. Direct changes to charge or checkout workflows risk payment processing degradation or double charges under concurrency."
    ),
    # Authentication & Authorization changes
    (
        re.compile(r'(?i)(jwt\.decode|verify_token|authenticate|has_role|is_authenticated|check_permission|hash_password|bcrypt)', re.IGNORECASE),
        "auth_security_change",
        "high",
        "Authentication or authorization verification logic altered. Risk of authorization bypass or session invalidation for active user sessions."
    ),
    # Suppressed / silent exceptions
    (
        re.compile(r'(?i)(except\s*(?:Exception)?\s*:\s*pass|catch\s*\([^)]*\)\s*\{\s*\})', re.IGNORECASE),
        "suppressed_error_handling",
        "medium",
        "Silent error suppression detected (except: pass / empty catch block). Swallows critical runtime failures, obscuring bugs from logs and monitoring."
    ),
    # Concurrency and locking
    (
        re.compile(r'(?i)(threading\.Lock|asyncio\.Lock|sync\.Mutex|synchronized|deadlock|race_condition)', re.IGNORECASE),
        "concurrency_locking_change",
        "medium",
        "Concurrency lock or synchronization primitive modified. Risk of thread contention, deadlock, or race condition under high concurrency."
    ),
    # Database Transaction Boundaries
    (
        re.compile(r'(?i)(@transaction\.atomic|db\.session\.commit|connection\.commit|auto_commit\s*=\s*False)', re.IGNORECASE),
        "transaction_boundary_change",
        "medium",
        "Database transaction boundaries modified. Uncommitted transactions or lengthened transaction scopes increase row lock duration and contention."
    ),
    # Caching and Invalidation
    (
        re.compile(r'(?i)(cache\.delete|cache\.clear|redis\.delete|cache\.set_many)', re.IGNORECASE),
        "cache_invalidation_change",
        "medium",
        "Cache invalidation logic changed. Incomplete cache invalidation causes stale reads; excessive cache flushing triggers database thundering herds."
    )
]

def scan_code_changes(files: List[Dict[str, Any]]) -> List[RiskFinding]:
    """Scan changed source files and diff patches for risky code and architectural changes."""
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

        # Check path-based signal (e.g. src/payment/service.py)
        is_payment_file = any(k in filename.lower() for k in ["payment", "billing", "checkout", "stripe", "charge"])
        is_auth_file = any(k in filename.lower() for k in ["auth", "security", "jwt", "permission", "login", "oauth"])

        for idx, raw_line in enumerate(lines, start=1):
            # Check removed endpoints/functions in diff
            if patch and raw_line.startswith("-"):
                # Detect removed API routes
                if re.search(r'(?i)(@(?:app|router|blueprint)\.(get|post|put|delete|patch)|router\.(get|post|put|delete)|route\()', raw_line):
                    findings.append(RiskFinding(
                        id=f"finding-code-{finding_counter:03d}",
                        category="code",
                        type="removed_api_endpoint",
                        severity_hint="high",
                        confidence=0.96,
                        evidence=raw_line[1:].strip()[:150],
                        file=filename,
                        line=idx,
                        changed=True,
                        description="API endpoint route was removed. Breaking change: Any active clients, webhooks, or frontends calling this route will receive immediate 404 errors."
                    ))
                    finding_counter += 1

                # Detect removed public functions
                if re.search(r'^\-\s*(def\s+[a-zA-Z0-9_]+\s*\(|function\s+[a-zA-Z0-9_]+|export\s+(?:const|function)\s+[a-zA-Z0-9_]+)', raw_line):
                    findings.append(RiskFinding(
                        id=f"finding-code-{finding_counter:03d}",
                        category="code",
                        type="removed_function",
                        severity_hint="medium",
                        confidence=0.90,
                        evidence=raw_line[1:].strip()[:150],
                        file=filename,
                        line=idx,
                        changed=True,
                        description="Function removed or signature altered. Risk of breaking internal consumers or RPC callers."
                    ))
                    finding_counter += 1
                continue

            # Only analyze additions if patch is provided
            if patch and not raw_line.startswith("+"):
                continue

            line = raw_line[1:].strip() if patch and raw_line.startswith("+") else raw_line.strip()

            # Path + keyword correlation
            if is_payment_file and any(kw in line.lower() for kw in ["stripe", "payment", "checkout", "webhook", "card", "amount"]):
                findings.append(RiskFinding(
                    id=f"finding-code-{finding_counter:03d}",
                    category="code",
                    type="payment_logic_modification",
                    severity_hint="high",
                    confidence=0.95,
                    evidence=line[:150],
                    file=filename,
                    line=idx,
                    changed=True,
                    description=f"Critical payment logic in {filename} modified. Direct impact on financial transaction handling."
                ))
                finding_counter += 1
                is_payment_file = False  # Avoid duplicating for every single line in this file

            if is_auth_file and any(kw in line.lower() for kw in ["token", "verify", "role", "claim", "header", "bearer"]):
                findings.append(RiskFinding(
                    id=f"finding-code-{finding_counter:03d}",
                    category="code",
                    type="auth_logic_modification",
                    severity_hint="high",
                    confidence=0.93,
                    evidence=line[:150],
                    file=filename,
                    line=idx,
                    changed=True,
                    description=f"Core security/auth module in {filename} modified. Can cause credential validation regressions."
                ))
                finding_counter += 1
                is_auth_file = False

            # General code signals
            for pattern, ftype, severity, desc in CODE_SIGNALS:
                if pattern.search(line):
                    findings.append(RiskFinding(
                        id=f"finding-code-{finding_counter:03d}",
                        category="code",
                        type=ftype,
                        severity_hint=severity,
                        confidence=0.92,
                        evidence=line[:150],
                        file=filename,
                        line=idx,
                        changed=True,
                        description=desc
                    ))
                    finding_counter += 1
                    break

    return findings
