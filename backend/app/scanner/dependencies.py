import re
from typing import List, Dict, Any, Optional, Tuple
from ..analysis.schemas import RiskFinding
from .classifier import is_dependency_file

PAYMENT_PACKAGES = {"stripe", "paypalrestsdk", "braintree", "adyen", "square", "@stripe/stripe-js", "checkout-sdk-node"}
AUTH_PACKAGES = {"pyjwt", "jsonwebtoken", "passport", "auth0", "firebase-admin", "bcrypt", "oauthlib", "keycloak", "next-auth"}
DB_PACKAGES = {"psycopg2", "psycopg2-binary", "pg", "asyncpg", "mysqlclient", "mysql-connector-python", "sqlalchemy", "typeorm", "prisma", "sequelize", "pymongo", "mongodb", "ioredis", "redis"}
FRAMEWORK_PACKAGES = {"django", "fastapi", "flask", "express", "next", "nestjs", "spring-boot", "rails", "laravel", "gin-gonic/gin"}
CLOUD_PACKAGES = {"boto3", "botocore", "google-cloud-storage", "google-cloud-bigquery", "azure-storage", "@aws-sdk/client-s3"}

def parse_semver(v: str) -> Optional[Tuple[int, int, int]]:
    """Extract major, minor, patch ints from version string."""
    clean = re.sub(r'^[^\d]*', '', v.strip())
    match = re.search(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?', clean)
    if match:
        maj = int(match.group(1))
        min_v = int(match.group(2)) if match.group(2) else 0
        patch = int(match.group(3)) if match.group(3) else 0
        return (maj, min_v, patch)
    return None

def parse_requirements_txt(content: str) -> Dict[str, str]:
    deps = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # match pkg==1.2.3 or pkg>=1.2.3
        match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([a-zA-Z0-9_\-\.]+)', line)
        if match:
            deps[match.group(1).lower()] = match.group(2)
    return deps

def parse_package_json_deps(content: str) -> Dict[str, str]:
    import json
    deps = {}
    try:
        data = json.loads(content)
        for key in ["dependencies", "devDependencies"]:
            for pkg, ver in data.get(key, {}).items():
                deps[pkg.lower()] = str(ver)
    except Exception:
        pass
    return deps

def scan_dependency_changes(files: List[Dict[str, Any]]) -> List[RiskFinding]:
    """Scan dependency changes between baseline and candidate commits."""
    findings: List[RiskFinding] = []
    finding_counter = 1

    for file_info in files:
        filename = file_info.get("filename", "")
        if not is_dependency_file(filename):
            continue

        patch = file_info.get("patch", "")
        if not patch:
            continue

        # Extract removed (-) lines and added (+) lines to detect version transitions
        removed_deps: Dict[str, str] = {}
        added_deps: Dict[str, str] = {}

        for line in patch.splitlines():
            if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
                continue

            if line.startswith("-"):
                raw = line[1:].strip()
                # requirements.txt style
                m = re.match(r'^([a-zA-Z0-9_\-\./@]+)\s*(?:==|>=|<=|~=|\s*:)\s*["\']?([0-9a-zA-Z\.\-]+)["\']?', raw)
                if m:
                    pkg, ver = m.group(1).lower(), m.group(2)
                    removed_deps[pkg] = ver
                # package.json style "stripe": "^10.2.0"
                m_json = re.search(r'"([@a-zA-Z0-9_\-\./]+)"\s*:\s*"[\^~]?([0-9a-zA-Z\.\-]+)"', raw)
                if m_json:
                    removed_deps[m_json.group(1).lower()] = m_json.group(2)

            elif line.startswith("+"):
                raw = line[1:].strip()
                m = re.match(r'^([a-zA-Z0-9_\-\./@]+)\s*(?:==|>=|<=|~=|\s*:)\s*["\']?([0-9a-zA-Z\.\-]+)["\']?', raw)
                if m:
                    pkg, ver = m.group(1).lower(), m.group(2)
                    added_deps[pkg] = ver
                m_json = re.search(r'"([@a-zA-Z0-9_\-\./]+)"\s*:\s*"[\^~]?([0-9a-zA-Z\.\-]+)"', raw)
                if m_json:
                    added_deps[m_json.group(1).lower()] = m_json.group(2)

        # Check for upgrades
        for pkg, new_ver in added_deps.items():
            old_ver = removed_deps.get(pkg)
            new_sem = parse_semver(new_ver)
            old_sem = parse_semver(old_ver) if old_ver else None

            is_payment = pkg in PAYMENT_PACKAGES
            is_auth = pkg in AUTH_PACKAGES
            is_db = pkg in DB_PACKAGES
            is_fw = pkg in FRAMEWORK_PACKAGES
            is_cloud = pkg in CLOUD_PACKAGES

            if old_ver and old_sem and new_sem:
                old_maj, _, _ = old_sem
                new_maj, _, _ = new_sem

                if new_maj > old_maj:
                    # Major version upgrade!
                    sev = "high" if (is_payment or is_auth or is_db or is_fw) else "medium"
                    type_name = "major_dependency_upgrade"
                    if is_payment:
                        type_name = "payment_dependency_upgrade"
                    elif is_auth:
                        type_name = "auth_dependency_upgrade"
                    elif is_db:
                        type_name = "db_driver_upgrade"

                    findings.append(RiskFinding(
                        id=f"finding-dep-{finding_counter:03d}",
                        category="dependency",
                        type=type_name,
                        severity_hint=sev,
                        confidence=0.96,
                        evidence=f"{pkg}: {old_ver} → {new_ver}",
                        file=filename,
                        changed=True,
                        description=(
                            f"Major version upgrade of '{pkg}' ({old_ver} → {new_ver}). "
                            "Major upgrades introduce breaking API changes, parameter restructuring, or deprecated lifecycle methods. "
                            "May pass mocked unit tests but fail at runtime."
                        ),
                        metadata={"package": pkg, "old_version": old_ver, "new_version": new_ver, "is_breaking_candidate": True}
                    ))
                    finding_counter += 1
                elif new_sem > old_sem:
                    # Minor / patch upgrade
                    findings.append(RiskFinding(
                        id=f"finding-dep-{finding_counter:03d}",
                        category="dependency",
                        type="minor_dependency_upgrade",
                        severity_hint="low",
                        confidence=0.90,
                        evidence=f"{pkg}: {old_ver} → {new_ver}",
                        file=filename,
                        changed=True,
                        description=f"Dependency '{pkg}' upgraded from {old_ver} to {new_ver}.",
                        metadata={"package": pkg, "old_version": old_ver, "new_version": new_ver}
                    ))
                    finding_counter += 1

            elif not old_ver:
                # Newly introduced dependency
                sev = "medium" if (is_payment or is_auth or is_db or is_cloud) else "low"
                findings.append(RiskFinding(
                    id=f"finding-dep-{finding_counter:03d}",
                    category="dependency",
                    type="new_dependency",
                    severity_hint=sev,
                    confidence=0.95,
                    evidence=f"Added '{pkg}': {new_ver}",
                    file=filename,
                    changed=True,
                    description=f"Newly added dependency '{pkg}' introduced into deployment manifest.",
                    metadata={"package": pkg, "version": new_ver}
                ))
                finding_counter += 1

        # Check for removed dependencies
        for pkg, old_ver in removed_deps.items():
            if pkg not in added_deps:
                findings.append(RiskFinding(
                    id=f"finding-dep-{finding_counter:03d}",
                    category="dependency",
                    type="removed_dependency",
                    severity_hint="medium",
                    confidence=0.92,
                    evidence=f"Removed '{pkg}' ({old_ver})",
                    file=filename,
                    changed=True,
                    description=f"Dependency '{pkg}' was removed. Any lingering code imports will throw ModuleNotFoundError / ImportError in production.",
                    metadata={"package": pkg, "old_version": old_ver}
                ))
                finding_counter += 1

    return findings
