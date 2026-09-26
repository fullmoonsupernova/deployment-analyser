import asyncio
from backend.app.scanner.dependencies import scan_dependency_changes
from backend.app.incidents.matcher import IncidentMatcher
from backend.app.analysis.schemas import RiskFinding, EvidencePackage
from backend.app.analysis.groq import GroqAnalyzer
from backend.app.scanner.orchestrator import ScannerOrchestrator

def test_regression_jinja2_minor_upgrade_no_payment_match():
    """
    Test 1 — Jinja2 minor upgrade:
    Input: jinja2 3.1.2 → 3.1.3
    Expected: minor_dependency_upgrade
    Expected historical match: NO match to major payment SDK incident (INC-004) or any payment incident.
    """
    files = [{
        "filename": "app/requirements.txt",
        "patch": "-jinja2==3.1.2\n+jinja2==3.1.3"
    }]
    findings = scan_dependency_changes(files)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "minor_dependency_upgrade"
    assert f.severity_hint == "low"
    assert f.metadata.get("is_major") is False

    matcher = IncidentMatcher()
    matches = matcher.match(findings)
    matched_ids = [m.incident_id for m in matches]
    assert "INC-004" not in matched_ids
    assert len(matches) == 0, f"Expected 0 matches for minor Jinja2 upgrade, got: {matched_ids}"

def test_regression_stripe_major_upgrade_matches_inc_004():
    """
    Test 2 — Major payment SDK upgrade:
    Input: stripe 10.2.0 → 12.1.0
    Expected: payment_dependency_upgrade / major_dependency_upgrade
    Expected: INC-004 matches with evidence-driven patterns.
    """
    files = [{
        "filename": "app/requirements.txt",
        "patch": "-stripe==10.2.0\n+stripe==12.1.0"
    }]
    findings = scan_dependency_changes(files)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "payment_dependency_upgrade"
    assert f.severity_hint == "high"
    assert f.metadata.get("domain") == "payment"
    assert f.metadata.get("is_major") is True

    matcher = IncidentMatcher()
    matches = matcher.match(findings)
    matched_ids = [m.incident_id for m in matches]
    assert "INC-004" in matched_ids
    inc_004 = next(m for m in matches if m.incident_id == "INC-004")
    assert "payment_dependency_upgrade" in inc_004.matched_patterns
    assert "major_dependency_upgrade" in inc_004.matched_patterns

def test_regression_unsupported_ai_scenario_no_templatesyntaxerror():
    """
    Test 3 — Unsupported AI scenario:
    If the only evidence is Jinja2 3.1.2 → 3.1.3,
    the system must NOT assert TemplateSyntaxError will occur,
    and must describe dependency compatibility uncertainty instead.
    """
    f = RiskFinding(
        id="finding-001",
        category="dependency",
        type="minor_dependency_upgrade",
        severity_hint="low",
        confidence=0.9,
        evidence="jinja2: 3.1.2 → 3.1.3",
        file="app/requirements.txt",
        description="Dependency 'jinja2' upgraded from 3.1.2 to 3.1.3.",
        metadata={"package": "jinja2", "old_version": "3.1.2", "new_version": "3.1.3", "domain": "general", "is_major": False}
    )
    evidence = EvidencePackage(
        repository={"name": "fastapi-k8s", "full_name": "DevOps-Boot/fastapi-k8s"},
        findings=[f],
        services=[],
        relationships=[],
        historical_matches=[]
    )

    analyzer = GroqAnalyzer()
    
    async def _test():
        res = await analyzer.analyze(evidence)
        assert res.overall_assessment == "low"
        
        # Verify no speculative TemplateSyntaxError assertions
        for sc in res.failure_scenarios:
            assert "templatesyntaxerror" not in sc.title.lower(), f"Speculative TemplateSyntaxError in title: {sc.title}"
            for step in sc.failure_chain:
                assert "templatesyntaxerror" not in step.lower(), f"Speculative TemplateSyntaxError in step: {step}"
            assert sc.severity == "low"
            assert "uncertainty" in sc.title.lower() or "compatibility" in sc.title.lower() or "readiness" in sc.title.lower()

    asyncio.run(_test())

def test_regression_missing_infrastructure_confidence_low():
    """
    Test 4 — Missing infrastructure:
    If no Docker/Kubernetes/Terraform/runtime configuration changes are detected,
    preserve analysis_confidence = LOW with an explanation of missing evidence.
    """
    repo_meta = {"name": "fastapi-k8s", "full_name": "DevOps-Boot/fastapi-k8s"}
    changed_files = [
        {"filename": "app/requirements.txt", "patch": "-jinja2==3.1.2\n+jinja2==3.1.3"},
        {"filename": "app/main.py", "patch": "+# minor comment change"}
    ]
    orchestrator = ScannerOrchestrator()
    evidence_package, risk_level, score, sig_count, confidence, confidence_reason = orchestrator.scan_repository_changes(
        repository_meta=repo_meta,
        changed_files=changed_files,
        single_commit_mode=False
    )

    assert confidence == "LOW"
    assert "No infrastructure configurations (Docker, Kubernetes, Terraform)" in confidence_reason
    assert "production deployment environment cannot be fully verified" in confidence_reason
    assert risk_level == "LOW"
