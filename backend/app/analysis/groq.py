import json
import logging
from typing import Dict, Any, List, Set, Optional
import httpx

from ..config import settings
from .schemas import (
    EvidencePackage,
    GroqAnalysisResponse,
    FailureScenario,
    RolloutStrategy,
    MonitoringSignal
)
from .prompts import GROQ_SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger(__name__)

class GroqAnalysisError(Exception):
    pass

class GroqAnalyzer:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key if api_key else settings.GROQ_API_KEY
        self.model = model if model else settings.GROQ_MODEL
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"

    async def analyze(self, evidence: EvidencePackage) -> GroqAnalysisResponse:
        """
        Executes Groq AI reasoning on deterministic evidence package.
        Includes hallucination verification and automatic fallback.
        """
        valid_finding_ids = {f.id for f in evidence.findings}

        if not self.api_key:
            logger.info("GROQ_API_KEY not configured. Generating deterministic SRE reasoning.")
            return self.generate_deterministic_fallback(evidence)

        evidence_dict = evidence.model_dump()
        user_prompt = build_user_prompt(json.dumps(evidence_dict, indent=2))

        try:
            raw_response = await self._call_groq(user_prompt)
            parsed = self._parse_and_validate(raw_response, valid_finding_ids)
            return parsed
        except Exception as e:
            logger.warning(f"Groq API call or validation failed ({str(e)}). Retrying with correction...")
            try:
                # Retry once with explicit format reminder
                correction_prompt = (
                    f"The previous output was invalid or failed validation. Error: {str(e)}.\n\n"
                    f"Please re-analyze the following evidence and return ONLY valid JSON matching the exact schema:\n\n"
                    f"{user_prompt}"
                )
                raw_response = await self._call_groq(correction_prompt)
                parsed = self._parse_and_validate(raw_response, valid_finding_ids)
                return parsed
            except Exception as retry_err:
                logger.error(f"Groq retry also failed ({str(retry_err)}). Falling back to deterministic reasoning.")
                return self.generate_deterministic_fallback(evidence)

    async def _call_groq(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": GROQ_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"}
        }

        async with httpx.AsyncClient(timeout=35.0) as client:
            resp = await client.post(self.api_url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise GroqAnalysisError(f"Groq API returned HTTP {resp.status_code}: {resp.text}")
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise GroqAnalysisError("Empty choices returned from Groq API")
            return choices[0]["message"]["content"]

    def _parse_and_validate(self, json_text: str, valid_finding_ids: Set[str]) -> GroqAnalysisResponse:
        """Parse JSON response and enforce Hallucination Control on evidence_ids."""
        try:
            data = json.loads(json_text)
        except Exception as e:
            raise GroqAnalysisError(f"Malformed JSON from AI model: {str(e)}")

        response_obj = GroqAnalysisResponse.model_validate(data)

        # Enforce Hallucination Control: Every scenario must map to existing deterministic finding IDs
        sanitized_scenarios: List[FailureScenario] = []
        for sc in response_obj.failure_scenarios:
            valid_ids = [eid for eid in sc.evidence_ids if eid in valid_finding_ids]
            if not valid_ids and valid_finding_ids:
                # AI hallucinated an evidence ID that does not exist in findings
                logger.warning(f"Rejecting scenario '{sc.title}': No valid evidence IDs ({sc.evidence_ids})")
                continue
            
            sc.evidence_ids = valid_ids if valid_ids else list(valid_finding_ids)[:1]
            sanitized_scenarios.append(sc)

        response_obj.failure_scenarios = sanitized_scenarios
        if not response_obj.failure_scenarios and valid_finding_ids:
            # Fall back to deterministic scenarios if all were rejected
            fallback = self.generate_deterministic_fallback(EvidencePackage(
                repository={}, findings=[f for f in evidence.findings], services=[], relationships=[], historical_matches=[]
            ))
            response_obj.failure_scenarios = fallback.failure_scenarios

        return response_obj

    def generate_deterministic_fallback(self, evidence: EvidencePackage) -> GroqAnalysisResponse:
        """
        Generates robust, production-grade SRE failure reasoning directly from deterministic findings.
        Acts as the guaranteed fallback when Groq is unconfigured or rate-limited.
        """
        findings = evidence.findings
        scenarios: List[FailureScenario] = []
        monitoring: List[MonitoringSignal] = []
        rollback_conditions: List[str] = []
        steps: List[str] = []
        overall = "low"
        summary_points = []

        # Find specific finding categories
        db_findings = [f for f in findings if f.category == "database" or "migration" in f.type]
        infra_findings = [f for f in findings if f.category == "infrastructure" or "replica" in f.type]
        dep_findings = [f for f in findings if f.category == "dependency"]
        traffic_findings = [f for f in findings if f.category == "traffic" or "timeout" in f.type]
        cfg_findings = [f for f in findings if f.category == "configuration"]
        code_findings = [f for f in findings if f.category == "code"]

        # 1. Database Scenarios
        if db_findings:
            overall = "critical" if any(f.severity_hint == "critical" for f in db_findings) else "high"
            evidence_ids = [f.id for f in db_findings]
            scenarios.append(FailureScenario(
                title="Active Application Instances Crash on Removed Database Schema During Rolling Cutover",
                severity="critical" if "destructive" in db_findings[0].type else "high",
                confidence=0.96,
                evidence_ids=evidence_ids,
                failure_chain=[
                    "Rolling deployment initiates new container deployment while old containers still serve user traffic",
                    "Database migration executes destructively, dropping columns or altering constraints in place",
                    "Existing active containers receive user requests and attempt to query the old schema columns",
                    "Database engine rejects queries with column does not exist or constraint violation errors",
                    "HTTP 500 error spike cascades across all active client sessions and in-flight transactions"
                ],
                affected_services=["Backend API", "PostgreSQL Database"],
                blast_radius="Global application availability failure for all endpoints querying modified database tables during the release window.",
                why_tests_may_miss_it=(
                    "Unit and integration tests run in isolated pipelines against a single, freshly-migrated database schema where new code runs alone. "
                    "Tests do not simulate the multi-version rolling deployment phase where old application code and new database state coexist simultaneously."
                ),
                mitigation="Halt deployment immediately. Implement expand/contract migration by retaining legacy columns until 100% of old pods terminate."
            ))
            monitoring.append(MonitoringSignal(
                metric="Database Query Error Rate & Deadlocks",
                reason="Detects missing column errors and lock contention during migration execution"
            ))
            rollback_conditions.append("Any spike in database 'column does not exist' or foreign key violation errors")

        # 2. Single Replica / Availability Scenarios
        if infra_findings:
            if overall != "critical":
                overall = "high" if any(f.severity_hint == "high" for f in infra_findings) else "medium"
            single_rep = [f for f in infra_findings if "single_replica" in f.type or "replica" in f.type]
            evidence_ids = [f.id for f in single_rep] if single_rep else [infra_findings[0].id]
            scenarios.append(FailureScenario(
                title="Downtime Caused by Single Replica Termination During Container Rolling Transition",
                severity="high",
                confidence=0.94,
                evidence_ids=evidence_ids,
                failure_chain=[
                    "Container orchestrator schedules new deployment revision",
                    "Existing single replica receives termination signal (SIGTERM) or is detached from load balancer",
                    "New container undergoes image pull, initialization, and application cold start",
                    "Load balancer has 0 healthy upstreams available to route incoming web traffic",
                    "End users receive immediate HTTP 503 Service Unavailable errors until startup probe succeeds"
                ],
                affected_services=["Backend API", "Ingress / Load Balancer"],
                blast_radius="Complete ingress outage for all traffic arriving between old pod termination and new container health readiness.",
                why_tests_may_miss_it=(
                    "CI/CD tests run against an already spun-up instance. Test frameworks verify that an endpoint is healthy when running, "
                    "not whether the deployment orchestrator can maintain availability during container re-creation."
                ),
                mitigation="Ensure replicas >= 2 with PodDisruptionBudget (minAvailable: 1) and valid readiness probes before initiating rollout."
            ))
            monitoring.append(MonitoringSignal(
                metric="Ingress HTTP 503 Unavailable Responses",
                reason="Measures traffic dropping due to zero ready backend endpoints"
            ))
            rollback_conditions.append("Ingress 503 response rate exceeds 0.5% during pod startup")

        # 3. Dependency Major Upgrade Scenarios
        major_deps = [f for f in dep_findings if "major" in f.type or f.severity_hint in ["high", "critical"]]
        if major_deps:
            if overall in ["low", "medium"]:
                overall = "high"
            scenarios.append(FailureScenario(
                title="Runtime Signature Deserialization Regression Following Major SDK Upgrade",
                severity="high",
                confidence=0.91,
                evidence_ids=[f.id for f in major_deps],
                failure_chain=[
                    "Application deployed with upgraded major dependency version",
                    "Live production traffic delivers requests or external webhooks matching real-world edge cases",
                    "Upgraded library fails due to altered return types, renamed error classes, or deprecated parameters",
                    "Unhandled exception propagates past boundary handlers",
                    "Critical operations (e.g. checkout, authentication, billing) fail silently or produce 500s"
                ],
                affected_services=["Backend API", "External SDK Integration"],
                blast_radius="Specific business domain (e.g., billing, auth, cloud storage) encounters systematic processing failures.",
                why_tests_may_miss_it=(
                    "Unit test suites typically mock third-party SDK calls using static fixtures recorded under the previous library version, "
                    "failing to validate real live wire protocols or changed exception hierarchies."
                ),
                mitigation="Deploy in dark launch or shadow mode with dual-logging to compare legacy vs updated SDK responses."
            ))
            monitoring.append(MonitoringSignal(
                metric="Unhandled Exception Rate in Worker / SDK Handlers",
                reason="Tracks unexpected TypeError, AttributeError, or DeserializationError spikes"
            ))
            rollback_conditions.append("Error rate on endpoints calling upgraded SDK exceeds 0.2%")

        # 4. Traffic & Timeout Scenarios
        if traffic_findings:
            if overall == "low":
                overall = "medium"
            scenarios.append(FailureScenario(
                title="Cascading Thread Starvation and Gateway 504 Timeouts Under Peak Traffic",
                severity="high" if any(f.severity_hint == "high" for f in traffic_findings) else "medium",
                confidence=0.92,
                evidence_ids=[f.id for f in traffic_findings],
                failure_chain=[
                    "Peak production traffic arrives at exposed endpoint",
                    "Endpoint triggers synchronous database queries or external network requests without timeout boundaries",
                    "Downstream service experiences transient latency degradation",
                    "Worker threads remain blocked waiting on socket read operations",
                    "Server connection backlog fills completely, triggering cascading gateway 504 timeouts across unrelated routes"
                ],
                affected_services=["Backend API", "External Service", "PostgreSQL Database"],
                blast_radius="System-wide latency spike and worker pool starvation affecting all co-hosted endpoints.",
                why_tests_may_miss_it=(
                    "Staging environments execute individual functional test requests with near-zero network latency and low concurrency. "
                    "Unbounded socket reads and missing timeouts only manifest when concurrency exceeds available worker capacity."
                ),
                mitigation="Inject strict socket read timeouts (e.g. 2.5s) and circuit breakers around all external or unbounded network calls."
            ))
            monitoring.append(MonitoringSignal(
                metric="p99 Request Latency & Active Worker Threads",
                reason="Monitors thread starvation and latency degradation under concurrent load"
            ))
            rollback_conditions.append("p99 latency exceeds 3x baseline for more than 45 seconds")

        # Default fallback if no specific scenario matched
        if not scenarios:
            scenarios.append(FailureScenario(
                title="Standard Deployment Readiness Verification",
                severity="low",
                confidence=0.85,
                evidence_ids=[f.id for f in findings[:2]] if findings else [],
                failure_chain=[
                    "Routine application deployment initiated",
                    "Baseline rolling restart begins",
                    "Standard smoke verification executes"
                ],
                affected_services=["Backend API"],
                blast_radius="Minimal expected blast radius.",
                why_tests_may_miss_it="No high-risk structural or destructive changes detected in candidate revision.",
                mitigation="Proceed with standard automated canary analysis."
            ))

        # Build Rollout Strategy based on findings
        if db_findings:
            strategy_name = "Expand/Contract Phased Deployment"
            steps = [
                "Phase 1 (Expand): Deploy database migration adding new columns/tables with NULL or DEFAULT. Do NOT drop existing schema.",
                "Phase 2 (Dual Write / Compat): Deploy application revision that writes to new columns while gracefully reading fallback data.",
                "Phase 3 (Backfill): Run background data backfill script asynchronously outside the request-response path.",
                "Phase 4 (Canary): Direct 5% of production traffic to new version for 15 minutes; monitor error rates.",
                "Phase 5 (Full Cutover): Complete rollout to 100% of pods; ensure all old application pods have terminated.",
                "Phase 6 (Contract): Apply final cleanup migration removing deprecated columns after 24 hours of stable operation."
            ]
        elif infra_findings:
            strategy_name = "Guaranteed-Redundancy Canary Rollout"
            steps = [
                "Phase 1: Scale deployment to at least 2 replicas before initiating container update to ensure high availability.",
                "Phase 2: Set maxSurge=1, maxUnavailable=0 in deployment rolling update strategy.",
                "Phase 3: Route 10% traffic to canary pod for 10 minutes while observing readiness probe stability.",
                "Phase 4: Promote to 100% capacity once health checks and latency benchmarks confirm baseline parity."
            ]
        elif dep_findings or traffic_findings:
            strategy_name = "Canary with Circuit-Breaking & Rate Limiting"
            steps = [
                "Phase 1: Deploy to staging under simulated 200 QPS load test to observe socket latency and thread saturation.",
                "Phase 2: Canary deploy to 5% of production traffic with circuit breakers armed on external calls.",
                "Phase 3: Monitor p95/p99 latency, HTTP 5xx error rate, and worker pool saturation for 20 minutes.",
                "Phase 4: Incrementally increase traffic: 25% → 50% → 100% over a 1-hour window."
            ]
        else:
            strategy_name = "Standard Automated Canary Analysis"
            steps = [
                "Phase 1: Deploy candidate revision to canary fleet (5% traffic).",
                "Phase 2: Evaluate automated metrics (error rate, p99 latency) for 15 minutes.",
                "Phase 3: Automatically promote to 100% production traffic."
            ]

        # Standard Monitoring
        monitoring.append(MonitoringSignal(
            metric="HTTP 5xx Error Rate",
            reason="Primary golden signal indicating server-side deployment errors"
        ))
        monitoring.append(MonitoringSignal(
            metric="p95 / p99 Request Latency",
            reason="Identifies performance regressions, lock contention, or slow upstream dependencies"
        ))

        # Standard Rollback Conditions
        rollback_conditions.append("HTTP 5xx error rate exceeds 1.0% over a 60-second window during canary rollout")
        rollback_conditions.append("p99 latency doubles compared to pre-deployment baseline for > 90 seconds")

        summary = (
            f"Deployment candidate exhibits {overall.upper()} production risk based on {len(findings)} deterministic findings. "
            f"Key risk drivers include "
            + (", ".join([f.type.replace('_', ' ') for f in findings[:4]]) if findings else "minor code updates")
            + ". Proceeding requires a structured rollout with strict canary verification."
        )

        return GroqAnalysisResponse(
            overall_assessment=overall,
            summary=summary,
            failure_scenarios=scenarios,
            rollout_strategy=RolloutStrategy(strategy=strategy_name, steps=steps),
            monitoring=monitoring,
            rollback_conditions=rollback_conditions
        )
