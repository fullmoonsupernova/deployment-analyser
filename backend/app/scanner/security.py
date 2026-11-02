import asyncio
import re
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Set

import httpx

from ..analysis.schemas import SecurityAITriage, SecurityFinding, SecurityScanReport
from ..github.client import GitHubAPIError, GitHubClient
from ..analysis.groq import GroqAnalyzer

MAX_SECURITY_SCAN_FILES = 100
MAX_SECURITY_FILE_BYTES = 500_000
MAX_CONCURRENT_FILE_REQUESTS = 8
MAX_FINDINGS_PER_FILE = 20

SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx",
    ".kt", ".php", ".py", ".rb", ".rs", ".sh", ".sql", ".ts", ".tsx",
}
IGNORED_DIRECTORIES = {
    ".git", ".venv", "build", "coverage", "dist", "node_modules",
    "site-packages", "vendor",
}

RULES = (
    (
        "CODE-SQLI",
        "high",
        0.82,
        "Possible SQL injection",
        "A query appears to use string interpolation or formatting. If untrusted input reaches this query, an attacker may alter its meaning.",
        "Use parameterized queries and keep SQL structure separate from user-controlled values.",
        re.compile(
            r"""(?ix)
            (?:execute|executeQuery|executeUpdate|executemany|query|rawQuery)\s*\(\s*f["']
            |(?:execute|query)\s*\([^)\n]*\.format\s*\(
            |(?:execute|executeQuery|executeUpdate|query|rawQuery)\s*\([^)\n]*["'][^"']*["']\s*\+
            |\.query\s*\(\s*`[^`]*\$\{
            """
        ),
    ),
    (
        "CODE-CMDI",
        "high",
        0.84,
        "Possible command injection",
        "A shell command is constructed or executed through an API that can interpret shell metacharacters.",
        "Avoid shell execution; pass an argument list and validate every value derived from external input.",
        re.compile(r"(?i)\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen)\s*\([^)\n]*shell\s*=\s*True"),
    ),
    (
        "CODE-UNSAFE-DESERIALIZATION",
        "high",
        0.88,
        "Unsafe deserialization",
        "The code uses a deserializer that may instantiate executable or attacker-controlled objects.",
        "Use a safe data format and safe loader; do not deserialize untrusted data with object-capable loaders.",
        re.compile(r"(?i)\b(?:pickle\.(?:load|loads)|_pickle\.(?:load|loads)|yaml\.load\s*\(|unserialize\s*\(|readObject\s*\()"),
    ),
    (
        "CODE-DYNAMIC-EVAL",
        "high",
        0.78,
        "Dynamic code evaluation",
        "Dynamic evaluation can execute attacker-controlled input if the evaluated value is not fully trusted.",
        "Replace eval/exec with explicit parsing or a restricted mapping of supported operations.",
        re.compile(r"(?i)\b(?:eval|exec)\s*\("),
    ),
    (
        "TLS-VERIFY-DISABLED",
        "high",
        0.91,
        "TLS certificate verification disabled",
        "The client appears to skip TLS certificate validation, enabling interception of network traffic.",
        "Enable certificate verification and configure a trusted CA instead of disabling TLS checks.",
        re.compile(r"(?i)\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0"),
    ),
    (
        "HARDCODED-CREDENTIAL",
        "high",
        0.76,
        "Possible hardcoded credential",
        "A credential-like setting appears to be assigned a literal value in source code.",
        "Load credentials from a secret manager or environment configuration and rotate any exposed credential.",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|access[_-]?token|auth[_-]?token)\b
            \s*[:=]\s*["'][^"']{8,}["']
            """
        ),
    ),
    (
        "WEB-UNSAFE-HTML",
        "medium",
        0.72,
        "Potential unsafe HTML insertion",
        "HTML is inserted through a DOM API that does not escape content automatically.",
        "Escape or sanitize untrusted content, or use safe text APIs such as textContent.",
        re.compile(r"(?i)\.innerHTML\s*=|dangerouslySetInnerHTML\s*="),
    ),
    (
        "SSRF-DYNAMIC-URL",
        "medium",
        0.67,
        "Possible server-side request forgery",
        "An outbound request may use a dynamically controlled URL. Untrusted destinations can expose internal services.",
        "Allowlist destinations and reject private, loopback, and link-local addresses after DNS resolution.",
        re.compile(
            r"(?i)(?:requests\.(?:get|post|put|delete)|httpx\.(?:get|post)|fetch)\s*\(\s*(?:request\.(?:args|query_params|json)|req\.(?:query|body)|user_url)"
        ),
    ),
)


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./").lstrip("/").casefold()


def is_security_scan_candidate(path: str) -> bool:
    normalized = path.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if normalized.startswith("/") or any(part in (".", "..") for part in parts):
        return False
    if any(part.casefold() in IGNORED_DIRECTORIES for part in parts):
        return False
    if PurePosixPath(normalized).suffix.casefold() not in SOURCE_EXTENSIONS:
        return False
    filename = PurePosixPath(normalized).name.casefold()
    return not (filename.endswith(".min.js") or filename.endswith(".min.css"))


def scan_security_files(
    files: List[Dict[str, Any]],
    changed_paths: Optional[Set[str]] = None
) -> List[SecurityFinding]:
    """Apply local, heuristic security checks without retaining source snippets."""
    changed_paths = changed_paths or set()
    findings: List[SecurityFinding] = []

    for file_info in files:
        path = str(file_info.get("filename", ""))
        content = file_info.get("content", "")
        if not path or not isinstance(content, str):
            continue

        per_file_count = 0
        for line_number, line in enumerate(content.splitlines(), start=1):
            for rule_id, severity, confidence, title, description, recommendation, pattern in RULES:
                if not pattern.search(line):
                    continue
                if (
                    rule_id == "CODE-UNSAFE-DESERIALIZATION"
                    and "yaml.load" in line.lower()
                    and ("safeloader" in line.lower() or "safe_load" in line.lower())
                ):
                    continue
                findings.append(SecurityFinding(
                    id=f"security-{len(findings) + 1:04d}",
                    rule_id=rule_id,
                    severity=severity,
                    confidence=confidence,
                    title=title,
                    description=description,
                    recommendation=recommendation,
                    file=path,
                    line=line_number,
                    changed_in_deployment=_normalize_path(path) in changed_paths
                ))
                per_file_count += 1
                if per_file_count >= MAX_FINDINGS_PER_FILE:
                    break
            if per_file_count >= MAX_FINDINGS_PER_FILE:
                break

    return findings


async def scan_github_repository(
    client: GitHubClient,
    owner: str,
    repo: str,
    ref: str,
    changed_files: List[Dict[str, Any]]
) -> SecurityScanReport:
    """Fetch and scan a bounded source snapshot from a GitHub repository."""
    try:
        tree, tree_truncated = await client.get_repository_tree(owner, repo, ref)
    except GitHubAPIError:
        return SecurityScanReport(
            status="unavailable",
            message="GitHub did not provide the repository tree. Check repository visibility and token permissions."
        )
    except httpx.HTTPError:
        return SecurityScanReport(
            status="unavailable",
            message="GitHub could not be reached to retrieve the repository tree."
        )

    candidate_paths = [
        item["path"]
        for item in tree
        if item.get("type") == "blob"
        and isinstance(item.get("path"), str)
        and is_security_scan_candidate(item["path"])
    ]
    paths_to_scan = candidate_paths[:MAX_SECURITY_SCAN_FILES]
    changed_paths = {
        _normalize_path(str(file_info.get("filename", "")))
        for file_info in changed_files
        if file_info.get("filename")
    }

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_FILE_REQUESTS)
    failed_files = 0

    async def fetch_file(path: str) -> Optional[Dict[str, str]]:
        nonlocal failed_files
        async with semaphore:
            try:
                content = await client.get_file_content(
                    owner,
                    repo,
                    path,
                    ref=ref,
                    max_bytes=MAX_SECURITY_FILE_BYTES
                )
            except (GitHubAPIError, httpx.HTTPError):
                failed_files += 1
                return None
        if content is None:
            failed_files += 1
            return None
        return {"filename": path, "content": content}

    fetched = await asyncio.gather(*(fetch_file(path) for path in paths_to_scan))
    source_files = [file_info for file_info in fetched if file_info is not None]
    findings = scan_security_files(source_files, changed_paths)

    incomplete = (
        tree_truncated
        or len(candidate_paths) > MAX_SECURITY_SCAN_FILES
        or failed_files > 0
    )
    status = "partial" if incomplete else "completed"
    details = [
        f"Scanned {len(source_files)} of {len(candidate_paths)} candidate source files."
    ]
    if failed_files:
        details.append(f"{failed_files} file(s) could not be read.")
    if len(candidate_paths) > MAX_SECURITY_SCAN_FILES:
        details.append(f"Scan capped at {MAX_SECURITY_SCAN_FILES} files.")
    if tree_truncated:
        details.append("GitHub truncated the repository file listing.")
    details.append(
        "Findings are heuristic signals, not proof of exploitability; "
        "a file changed by this deployment is not necessarily a newly introduced issue."
    )

    report = SecurityScanReport(
        status=status,
        message=" ".join(details),
        candidates_total=len(candidate_paths),
        files_scanned=len(source_files),
        findings=findings
    )
    if findings:
        report.ai_triage = await GroqAnalyzer().triage_security_findings(findings)
    else:
        report.ai_triage = SecurityAITriage(
            status="not_run",
            message="No pattern matches were found; AI triage was not requested."
        )
    return report
