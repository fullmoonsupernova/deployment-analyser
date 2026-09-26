import pytest
from backend.app.scanner.classifier import (
    classify_file,
    is_migration_file,
    is_infrastructure_file,
    is_dependency_file,
    is_config_file,
    is_code_file
)
from backend.app.scanner.database import scan_database_changes
from backend.app.scanner.dependencies import scan_dependency_changes
from backend.app.scanner.infrastructure import scan_infrastructure_changes
from backend.app.scanner.configuration import scan_configuration_changes
from backend.app.scanner.external_services import scan_external_services
from backend.app.scanner.traffic import scan_traffic_sensitive_patterns
from backend.app.scanner.services import infer_service_topology
from backend.app.incidents.matcher import IncidentMatcher
from backend.app.config import redact_secrets

def test_file_classification():
    assert classify_file("migrations/001_initial.sql") == "database_migration"
    assert classify_file("alembic/versions/1234_add_col.py") == "database_migration"
    assert classify_file("requirements.txt") == "dependency"
    assert classify_file("package.json") == "dependency"
    assert classify_file("Dockerfile") == "infrastructure"
    assert classify_file("k8s/deployment.yaml") == "infrastructure"
    assert classify_file("docker-compose.yml") == "infrastructure"
    assert classify_file("config/settings.py") == "configuration"
    assert classify_file("src/service.py") == "code"
    assert classify_file("README.md") == "documentation"

def test_database_scanner_drop_column():
    files = [{
        "filename": "migrations/002_drop_token.sql",
        "patch": "+ALTER TABLE users DROP COLUMN legacy_token;\n+ALTER TABLE users DROP TABLE old_sessions;"
    }]
    findings = scan_database_changes(files)
    types = [f.type for f in findings]
    assert "destructive_database_change" in types
    assert "expand_contract_hazard" in types
    
    # Verify line content and details
    f_drop = next(f for f in findings if "Column 'legacy_token'" in f.description)
    assert f_drop.severity_hint == "high"
    assert f_drop.category == "database"

def test_dependency_scanner_major_upgrade():
    files = [{
        "filename": "requirements.txt",
        "patch": "-stripe==10.2.0\n+stripe==12.1.0\n-flask==2.0.1\n+flask==3.0.0"
    }]
    findings = scan_dependency_changes(files)
    types = [f.type for f in findings]
    assert "payment_dependency_upgrade" in types
    assert any("stripe" in f.evidence for f in findings)
    
    # Check severity
    stripe_finding = next(f for f in findings if "stripe" in f.evidence)
    assert stripe_finding.severity_hint == "high"

def test_infrastructure_scanner_single_replica():
    files = [{
        "filename": "k8s/deployment.yaml",
        "patch": "-  replicas: 3\n+  replicas: 1\n-            cpu: \"1000m\"\n+            cpu: \"100m\""
    }]
    findings = scan_infrastructure_changes(files)
    types = [f.type for f in findings]
    assert "single_replica_risk" in types
    assert "resource_limit_reduction" in types

def test_configuration_scanner_pool_shift_and_redaction():
    secret_text = "DATABASE_URL = postgres://admin:superSecret123@db.prod.internal:5432/app"
    redacted = redact_secrets(secret_text)
    assert "superSecret123" not in redacted
    assert "[REDACTED]" in redacted

    files = [{
        "filename": "config/production.env",
        "patch": "-DB_POOL_SIZE=20\n+DB_POOL_SIZE=100\n+DEBUG=true"
    }]
    findings = scan_configuration_changes(files)
    types = [f.type for f in findings]
    assert "connection_pool_change" in types
    assert "debug_mode_enabled" in types

def test_external_services_missing_timeout():
    files = [{
        "filename": "src/client.py",
        "patch": "+resp = requests.get('https://api.stripe.com/v1/charges')"
    }]
    findings, detected = scan_external_services(files)
    assert any(f.type == "missing_timeout" for f in findings)
    assert "stripe" in detected

def test_traffic_composite_hazard():
    files = [{
        "filename": "src/api/routes.py",
        "patch": """
+@router.get('/api/users')
+def get_users(db: Session):
+    users = db.query(User).all()
+    ext = requests.get('https://api.thirdparty.com/enrich')
+    return users
"""
    }]
    findings = scan_traffic_sensitive_patterns(files)
    types = [f.type for f in findings]
    assert "traffic_amplification_risk" in types
    assert "missing_pagination" in types

def test_service_topology_inference():
    files = [{"filename": "docker-compose.yml", "content": "services:\n  api:\n  postgres:\n  redis:\n  worker:"}]
    detected = {"stripe": {"name": "Stripe API", "type": "external_api", "category": "payment"}}
    nodes, edges = infer_service_topology(files, detected)
    node_ids = {n.id for n in nodes}
    assert "service-api" in node_ids
    assert "service-postgres" in node_ids
    assert "service-redis" in node_ids
    assert "ext-stripe" in node_ids
    assert len(edges) > 0

def test_incident_matcher():
    from backend.app.analysis.schemas import RiskFinding
    findings = [
        RiskFinding(
            id="finding-001",
            category="database",
            type="destructive_database_change",
            severity_hint="critical",
            confidence=0.99,
            evidence="DROP COLUMN legacy_token",
            file="migrations/001.sql"
        ),
        RiskFinding(
            id="finding-002",
            category="infrastructure",
            type="single_replica_risk",
            severity_hint="high",
            confidence=0.98,
            evidence="replicas: 1",
            file="k8s/deployment.yaml"
        )
    ]
    matcher = IncidentMatcher()
    matches = matcher.match(findings)
    assert len(matches) > 0
    matched_ids = {m.incident_id for m in matches}
    assert "INC-001" in matched_ids or "INC-003" in matched_ids
