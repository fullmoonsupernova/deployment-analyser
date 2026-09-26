import json
from pathlib import Path
from typing import List, Set, Dict
from ..analysis.schemas import RiskFinding, HistoricalIncidentMatch

DB_PATH = Path(__file__).resolve().parent / "database.json"

PAYMENT_PACKAGES = {"stripe", "paypalrestsdk", "braintree", "adyen", "square", "@stripe/stripe-js", "checkout-sdk-node"}
AUTH_PACKAGES = {"pyjwt", "jsonwebtoken", "passport", "auth0", "firebase-admin", "bcrypt", "oauthlib", "keycloak", "next-auth"}
DB_PACKAGES = {"psycopg2", "psycopg2-binary", "pg", "asyncpg", "mysqlclient", "mysql-connector-python", "sqlalchemy", "typeorm", "prisma", "sequelize", "pymongo", "mongodb", "ioredis", "redis"}

def extract_finding_patterns(f: RiskFinding) -> Set[str]:
    """
    Extract exact, evidence-grounded pattern tags for a finding.
    Evaluates finding type, package, domain, and metadata strictly.
    Does NOT use broad category substrings.
    """
    patterns: Set[str] = set()
    ftype = f.type.lower()
    cat = f.category.lower()
    meta = f.metadata or {}

    # Exact finding type is always an explicit pattern
    patterns.add(ftype)

    # Category-specific pattern derivations
    if cat == "dependency":
        is_major = meta.get("is_major") is True or ("major" in ftype)
        pkg = str(meta.get("package", "")).lower()
        domain = str(meta.get("domain", "")).lower()

        if is_major:
            patterns.add("major_dependency_upgrade")
            patterns.add("sdk_upgrade")
            if domain == "payment" or pkg in PAYMENT_PACKAGES or "payment" in ftype:
                patterns.add("payment_dependency_upgrade")
            elif domain == "auth" or pkg in AUTH_PACKAGES or "auth" in ftype:
                patterns.add("auth_dependency_upgrade")
            elif domain == "database" or pkg in DB_PACKAGES or "db" in ftype:
                patterns.add("db_driver_upgrade")
        else:
            # Minor or patch upgrade ONLY produces minor_dependency_upgrade
            # Must NEVER match major_dependency_upgrade, payment_dependency_upgrade, or sdk_upgrade
            patterns.add("minor_dependency_upgrade")

    elif cat == "database":
        if ftype in ("destructive_database_change", "drop_column", "drop_table"):
            patterns.update({"destructive_migration", "drop_column", "destructive_database_change", "schema_compatibility"})
        elif ftype in ("not_null_without_default", "not_null_addition"):
            patterns.update({"not_null_addition", "not_null_without_default", "schema_compatibility", "destructive_migration"})
        elif ftype == "expand_contract_hazard":
            patterns.update({"destructive_migration", "schema_compatibility"})

    elif cat == "infrastructure":
        if ftype in ("single_replica_risk", "reduced_redundancy"):
            patterns.update({"single_replica_risk", "reduced_redundancy", "redundancy_loss"})
        elif ftype in ("health_check_change", "health_check_disabled", "missing_readiness_probe"):
            patterns.update({"health_check_change", "probe_misconfiguration", "infrastructure_risk"})
        elif ftype in ("resource_limit_reduction", "autoscaling_removal"):
            patterns.update({"resource_limit_reduction", "autoscaling_removal"})

    elif cat in ("traffic", "external_service"):
        if ftype == "unbounded_query":
            patterns.update({"unbounded_query", "traffic_amplification_risk"})
        elif ftype == "missing_pagination":
            patterns.update({"missing_pagination", "traffic_amplification_risk"})
        elif ftype == "missing_timeout":
            patterns.update({"missing_timeout", "synchronous_external_call", "external_api_call"})
        elif ftype == "retry_amplification":
            patterns.update({"retry_amplification", "missing_timeout"})

    elif cat == "configuration":
        if ftype == "connection_pool_change":
            patterns.update({"connection_pool_change", "database_timeout"})

    return patterns

# Incidents have primary mandatory pattern requirements.
# If findings do not contain at least one primary pattern, the incident cannot match.
PRIMARY_INCIDENT_REQUIREMENTS: Dict[str, Set[str]] = {
    "INC-001": {"destructive_database_change", "drop_column", "destructive_migration"},
    "INC-002": {"external_api_call", "missing_timeout", "synchronous_external_call"},
    "INC-003": {"single_replica_risk", "reduced_redundancy"},
    "INC-004": {"payment_dependency_upgrade"},  # Must be an actual payment SDK upgrade
    "INC-005": {"unbounded_query", "missing_pagination"},
    "INC-006": {"connection_pool_change"},
    "INC-007": {"not_null_addition", "not_null_without_default"},
    "INC-008": {"retry_amplification"},
    "INC-009": {"health_check_change", "probe_misconfiguration", "missing_readiness_probe"},
    "INC-010": {"resource_limit_reduction", "autoscaling_removal"},
}

class IncidentMatcher:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.incidents = self._load_incidents()

    def _load_incidents(self) -> list:
        if not self.db_path.exists():
            return []
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def match(self, findings: List[RiskFinding]) -> List[HistoricalIncidentMatch]:
        """
        Deterministically and strictly match discovered risk findings against historical incident patterns.
        Enforces evidence grounding: generic or minor dependency changes will NEVER match major SDK incidents.
        """
        if not findings or not self.incidents:
            return []

        # Map each pattern to the finding IDs that exhibit it
        pattern_to_fids: Dict[str, Set[str]] = {}
        for f in findings:
            f_patterns = extract_finding_patterns(f)
            for p in f_patterns:
                if p not in pattern_to_fids:
                    pattern_to_fids[p] = set()
                pattern_to_fids[p].add(f.id)

        all_present_patterns = set(pattern_to_fids.keys())

        matches = []
        for inc in self.incidents:
            inc_id = inc.get("id", "")
            inc_patterns = [p.lower() for p in inc.get("patterns", [])]
            if not inc_patterns:
                continue

            # Check primary mandatory requirement for this incident
            reqs = PRIMARY_INCIDENT_REQUIREMENTS.get(inc_id)
            if reqs and not (all_present_patterns & reqs):
                # Mandatory primary evidence missing (e.g., minor Jinja2 upgrade lacks payment_dependency_upgrade)
                continue

            # Exact pattern matching only (no loose substring matching against category names)
            matched_patterns = [p for p in inc_patterns if p in all_present_patterns]
            if not matched_patterns:
                continue

            matched_finding_ids = set()
            for p in matched_patterns:
                matched_finding_ids.update(pattern_to_fids.get(p, set()))

            score = round(len(matched_patterns) / len(inc_patterns), 2)
            if score < 0.33:
                # Insufficient pattern coverage
                continue

            matches.append(HistoricalIncidentMatch(
                incident_id=inc_id,
                title=inc.get("title", inc_id),
                matched_patterns=matched_patterns,
                failure_summary=inc.get("failure", ""),
                historic_impact=inc.get("impact", ""),
                severity=inc.get("severity", "medium"),
                match_score=score,
                matched_findings=sorted(list(matched_finding_ids))
            ))

        # Sort by match_score descending, then severity
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        matches.sort(
            key=lambda m: (m.match_score, severity_rank.get(m.severity.lower(), 0)),
            reverse=True
        )
        return matches
