from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class RiskFinding(BaseModel):
    id: str
    category: str  # database, dependency, infrastructure, configuration, code, external_service, traffic
    type: str      # e.g., destructive_migration, single_replica_risk, major_dependency_upgrade
    severity_hint: str # critical, high, medium, low, info
    confidence: float = 0.95
    evidence: str
    file: str
    line: Optional[int] = None
    changed: bool = True
    description: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ServiceNode(BaseModel):
    id: str
    name: str
    type: str # service, api, frontend, database, cache, external_api, worker, queue
    confidence: float = 0.9
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ServiceEdge(BaseModel):
    from_node: str
    to_node: str
    type: str # rest_api, database, cache, external_api, queue
    confidence: float = 0.9

class HistoricalIncidentMatch(BaseModel):
    incident_id: str
    title: str
    matched_patterns: List[str]
    failure_summary: str
    historic_impact: str
    severity: str
    match_score: float
    matched_findings: List[str] = Field(default_factory=list)

class EvidencePackage(BaseModel):
    repository: Dict[str, Any]
    findings: List[RiskFinding]
    services: List[ServiceNode]
    relationships: List[ServiceEdge]
    historical_matches: List[HistoricalIncidentMatch]
    metadata: Dict[str, Any] = Field(default_factory=dict)

class FailureScenario(BaseModel):
    title: str
    severity: str # critical, high, medium, low
    confidence: float = 0.85
    evidence_ids: List[str]
    failure_chain: List[str]
    affected_services: List[str]
    blast_radius: str
    why_tests_may_miss_it: str
    mitigation: str

class RolloutStrategy(BaseModel):
    strategy: str
    steps: List[str]

class MonitoringSignal(BaseModel):
    metric: str
    reason: str

class GroqAnalysisResponse(BaseModel):
    overall_assessment: str # low, medium, high, critical
    summary: str
    failure_scenarios: List[FailureScenario]
    rollout_strategy: RolloutStrategy
    monitoring: List[MonitoringSignal]
    rollback_conditions: List[str]

class DeploymentAnalysisResult(BaseModel):
    repository: Dict[str, Any]
    baseline_commit: str
    deployment_commit: str
    single_commit_mode: bool = False
    deterministic_risk_level: str # LOW, MEDIUM, HIGH, CRITICAL
    deterministic_risk_score: float # 0.0 - 100.0
    significant_factors_count: int
    analysis_confidence: str # HIGH, MEDIUM, LOW
    confidence_reason: str
    findings: List[RiskFinding]
    services: List[ServiceNode]
    relationships: List[ServiceEdge]
    historical_matches: List[HistoricalIncidentMatch]
    ai_analysis: GroqAnalysisResponse
    cached: bool = False
    created_at: str
