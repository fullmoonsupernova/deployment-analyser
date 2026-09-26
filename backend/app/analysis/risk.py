import datetime
from typing import Dict, Any, List, Optional
from ..config import SCANNER_VERSION
from .schemas import (
    EvidencePackage,
    DeploymentAnalysisResult,
    GroqAnalysisResponse
)
from ..scanner.orchestrator import ScannerOrchestrator
from .groq import GroqAnalyzer

class AnalysisPipeline:
    def __init__(self):
        self.orchestrator = ScannerOrchestrator()
        self.groq_analyzer = GroqAnalyzer()
        self._cache: Dict[str, DeploymentAnalysisResult] = {}

    def _make_cache_key(self, owner: str, repo: str, base_commit: str, deployment_commit: str) -> str:
        return f"{owner.lower()}/{repo.lower()}:{base_commit}:{deployment_commit}:{SCANNER_VERSION}"

    async def run_analysis(
        self,
        repo_meta: Dict[str, Any],
        baseline_commit: str,
        deployment_commit: str,
        changed_files: List[Dict[str, Any]],
        single_commit_mode: bool = False,
        bypass_cache: bool = False
    ) -> DeploymentAnalysisResult:
        """
        Executes complete production deployment risk analysis pipeline:
        1. Check Cache
        2. Run Deterministic Scanner
        3. Match Historical Incidents
        4. Infer Service Topology
        5. Groq AI Reasoning (or Deterministic SRE Fallback)
        6. Return Complete DeploymentAnalysisResult
        """
        owner = repo_meta.get("owner", {}).get("login", "repo-owner")
        repo_name = repo_meta.get("name", "repo-name")
        cache_key = self._make_cache_key(owner, repo_name, baseline_commit, deployment_commit)

        if not bypass_cache and cache_key in self._cache:
            cached_res = self._cache[cache_key]
            # Create a shallow copy with cached=True flag
            result = cached_res.model_copy()
            result.cached = True
            return result

        # 1. Deterministic Scanning & Evidence Gathering
        (
            evidence_package,
            risk_level,
            risk_score,
            significant_count,
            confidence,
            confidence_reason
        ) = self.orchestrator.scan_repository_changes(
            repository_meta=repo_meta,
            changed_files=changed_files,
            single_commit_mode=single_commit_mode
        )

        # 2. AI Reasoning on Evidence (Single Call with Hallucination Control)
        ai_response = await self.groq_analyzer.analyze(evidence_package)

        # 3. Construct Final Result Object
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = DeploymentAnalysisResult(
            repository={
                "owner": owner,
                "name": repo_name,
                "full_name": repo_meta.get("full_name", f"{owner}/{repo_name}"),
                "html_url": repo_meta.get("html_url", f"https://github.com/{owner}/{repo_name}"),
                "description": repo_meta.get("description", ""),
                "default_branch": repo_meta.get("default_branch", "main")
            },
            baseline_commit=baseline_commit,
            deployment_commit=deployment_commit,
            single_commit_mode=single_commit_mode,
            deterministic_risk_level=risk_level,
            deterministic_risk_score=risk_score,
            significant_factors_count=significant_count,
            analysis_confidence=confidence,
            confidence_reason=confidence_reason,
            findings=evidence_package.findings,
            services=evidence_package.services,
            relationships=evidence_package.relationships,
            historical_matches=evidence_package.historical_matches,
            ai_analysis=ai_response,
            cached=False,
            created_at=now_iso
        )

        # Cache result
        self._cache[cache_key] = result
        return result

# Singleton analysis pipeline
analysis_pipeline = AnalysisPipeline()
