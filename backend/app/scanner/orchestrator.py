from typing import List, Dict, Any, Tuple
from ..analysis.schemas import (
    RiskFinding,
    ServiceNode,
    ServiceEdge,
    HistoricalIncidentMatch,
    EvidencePackage
)
from .database import scan_database_changes
from .dependencies import scan_dependency_changes
from .infrastructure import scan_infrastructure_changes
from .configuration import scan_configuration_changes
from .external_services import scan_external_services
from .code import scan_code_changes
from .traffic import scan_traffic_sensitive_patterns
from .services import infer_service_topology
from .classifier import is_infrastructure_file, is_config_file
from ..incidents.matcher import IncidentMatcher

class ScannerOrchestrator:
    def __init__(self):
        self.incident_matcher = IncidentMatcher()

    def scan_repository_changes(
        self,
        repository_meta: Dict[str, Any],
        changed_files: List[Dict[str, Any]],
        single_commit_mode: bool = False
    ) -> Tuple[EvidencePackage, str, float, int, str, str]:
        """
        Executes all deterministic scanners, correlates findings, matches historical incidents,
        and computes deterministic baseline risk metrics.
        
        Returns:
            (evidence_package, risk_level, risk_score, significant_count, confidence, confidence_reason)
        """
        all_findings: List[RiskFinding] = []
        global_counter = 1

        # 1. Database Migrations
        try:
            db_findings = scan_database_changes(changed_files)
            all_findings.extend(db_findings)
        except Exception:
            pass

        # 2. Dependencies
        try:
            dep_findings = scan_dependency_changes(changed_files)
            all_findings.extend(dep_findings)
        except Exception:
            pass

        # 3. Infrastructure
        try:
            infra_findings = scan_infrastructure_changes(changed_files)
            all_findings.extend(infra_findings)
        except Exception:
            pass

        # 4. Configuration
        try:
            cfg_findings = scan_configuration_changes(changed_files)
            all_findings.extend(cfg_findings)
        except Exception:
            pass

        # 5. External Services & Timeouts
        detected_external = {}
        try:
            ext_findings, detected_external = scan_external_services(changed_files)
            all_findings.extend(ext_findings)
        except Exception:
            pass

        # 6. Code Logic Signals
        try:
            code_findings = scan_code_changes(changed_files)
            all_findings.extend(code_findings)
        except Exception:
            pass

        # 7. Traffic Sensitive Patterns
        try:
            traffic_findings = scan_traffic_sensitive_patterns(changed_files)
            all_findings.extend(traffic_findings)
        except Exception:
            pass

        # Normalize finding IDs to clean sequential format: finding-001, finding-002...
        normalized_findings: List[RiskFinding] = []
        for idx, f in enumerate(all_findings, start=1):
            normalized_findings.append(RiskFinding(
                id=f"finding-{idx:03d}",
                category=f.category,
                type=f.type,
                severity_hint=f.severity_hint,
                confidence=f.confidence,
                evidence=f.evidence,
                file=f.file,
                line=f.line,
                changed=f.changed,
                description=f.description,
                metadata=f.metadata
            ))

        # 8. Infer Service Topology
        services, edges = infer_service_topology(changed_files, detected_external)

        # 9. Match Historical Incident Patterns
        historical_matches = self.incident_matcher.match(normalized_findings)

        # 10. Compute Deterministic Baseline Risk Score
        crit_score = 0.0
        high_score = 0.0
        med_score = 0.0
        low_score = 0.0
        
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0

        for f in normalized_findings:
            sev = f.severity_hint.lower()
            if sev == "critical":
                crit_score += 25.0
                crit_count += 1
            elif sev == "high":
                high_score += 15.0
                high_count += 1
            elif sev == "medium":
                med_score += 8.0
                med_count += 1
            elif sev == "low":
                low_score += 2.5
                low_count += 1

        # Apply diminishing returns / caps to prevent low-severity noise from artificially inflating risk
        capped_low = min(15.0, low_score)
        capped_med = min(30.0, med_score)
        capped_high = min(60.0, high_score)
        
        risk_score = min(100.0, round(crit_score + capped_high + capped_med + capped_low, 1))

        # Significant factors are those that carry meaningful production hazard (Critical, High, Medium)
        significant_count = crit_count + high_count + med_count

        # Risk Level Determination:
        # CRITICAL requires at least 1 CRITICAL finding, OR multiple HIGH findings with severe score
        if crit_count > 0 or (high_count >= 2 and risk_score >= 50.0):
            risk_level = "CRITICAL"
        # HIGH requires at least 1 HIGH finding, OR extensive MEDIUM findings
        elif high_count > 0 or (med_count >= 4 and risk_score >= 40.0):
            risk_level = "HIGH"
        # MEDIUM for moderate score or any medium findings
        elif risk_score >= 12.0 or med_count > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 11. Determine Analysis Confidence (Section 32)
        has_infra = any(is_infrastructure_file(f.get("filename", "")) for f in changed_files)
        has_config = any(is_config_file(f.get("filename", "")) for f in changed_files)
        has_code = any(f.get("filename", "").endswith((".py", ".js", ".ts", ".go", ".java")) for f in changed_files)

        if single_commit_mode:
            confidence = "MEDIUM"
            confidence_reason = (
                "Single commit repository revision. Analyzing current-state code, infrastructure manifests, and configuration "
                "against production readiness heuristics without historical comparison diff."
            )
        elif not has_infra and not has_config:
            confidence = "LOW"
            confidence_reason = (
                "No infrastructure configurations (Docker, Kubernetes, Terraform) or runtime environment settings were detected in the change set. "
                "Analysis is scoped to application code and dependency changes; production deployment environment cannot be fully verified."
            )
        elif has_infra and (has_config or has_code):
            confidence = "HIGH"
            confidence_reason = (
                "Comprehensive multi-layer evidence available: infrastructure manifests, runtime configuration, and application code "
                "were successfully parsed for cross-stack correlation."
            )
        else:
            confidence = "MEDIUM"
            confidence_reason = "Partial deployment context detected. Infrastructure or configuration signals are partially represented."

        # Build normalized EvidencePackage
        evidence_package = EvidencePackage(
            repository=repository_meta,
            findings=normalized_findings,
            services=services,
            relationships=edges,
            historical_matches=historical_matches,
            metadata={
                "scanner_version": "1.0.0",
                "single_commit_mode": single_commit_mode,
                "deterministic_score": risk_score,
                "deterministic_level": risk_level,
                "total_files_analyzed": len(changed_files)
            }
        )

        return (
            evidence_package,
            risk_level,
            risk_score,
            significant_count,
            confidence,
            confidence_reason
        )
