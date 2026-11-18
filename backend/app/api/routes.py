import json
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from ..config import settings, SCANNER_VERSION
from ..github.client import GitHubClient, GitHubAPIError
from ..github.repository import parse_repo_url, resolve_deployment_targets
from ..github.comparison import fetch_deployment_diff
from ..analysis.risk import analysis_pipeline
from ..analysis.schemas import DeploymentAnalysisResult
from ..scanner.security import scan_github_repository

router = APIRouter()

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "fixtures"

class AnalyzeRepoRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL or slug (e.g., https://github.com/owner/repo or owner/repo)")
    branch: Optional[str] = Field(None, description="Optional target branch")
    commit_sha: Optional[str] = Field(None, description="Optional deployment candidate commit SHA")
    bypass_cache: bool = Field(False, description="Bypass cache and force re-scan")

class AnalyzeScenarioRequest(BaseModel):
    scenario_id: str
    bypass_cache: bool = False

@router.get("/", response_class=HTMLResponse)
@router.head("/", response_class=HTMLResponse)
async def index_page(request: Request):
    """Render main SRE deployment risk analyzer dashboard."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "scanner_version": SCANNER_VERSION,
            "groq_model": settings.GROQ_MODEL,
            "has_github_token": bool(settings.GITHUB_TOKEN),
            "has_groq_key": bool(settings.GROQ_API_KEY)
        }
    )

@router.get("/api/health")
async def health_check():
    """System health and integration status."""
    return {
        "status": "healthy",
        "scanner_version": SCANNER_VERSION,
        "groq_configured": bool(settings.GROQ_API_KEY),
        "groq_model": settings.GROQ_MODEL,
        "github_token_configured": bool(settings.GITHUB_TOKEN),
        "app_env": settings.APP_ENV
    }

@router.get("/api/scenarios")
async def list_scenarios():
    """List pre-built test scenarios representing common production risk patterns."""
    scenarios = []
    if FIXTURES_DIR.exists():
        for fixture_file in sorted(FIXTURES_DIR.glob("*.json")):
            try:
                with open(fixture_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    scenarios.append({
                        "id": data.get("scenario_id", fixture_file.stem),
                        "title": data.get("title", fixture_file.stem),
                        "description": data.get("description", ""),
                        "repo_name": data.get("repo_meta", {}).get("full_name", "")
                    })
            except Exception:
                pass
    return {"scenarios": scenarios}

@router.post("/api/analyze-scenario")
async def analyze_scenario(req: AnalyzeScenarioRequest):
    """Execute analysis against a pre-built fixture scenario without requiring live GitHub credentials."""
    fixture_map = {
        "scenario-1": "scenario_1_destructive_migration.json",
        "scenario-2": "scenario_2_reduced_redundancy.json",
        "scenario-3": "scenario_3_dependency_upgrade.json",
        "scenario-4": "scenario_4_traffic_risk.json",
        "scenario-5": "scenario_5_combined_deployment.json",
    }

    filename = fixture_map.get(req.scenario_id)
    if not filename:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found.")

    fixture_path = FIXTURES_DIR / filename
    if not fixture_path.exists():
        raise HTTPException(status_code=404, detail=f"Fixture file '{filename}' missing on server.")

    try:
        with open(fixture_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read scenario fixture: {str(e)}")

    repo_meta = data["repo_meta"]
    baseline_commit = data["baseline_commit"]
    deployment_commit = data["deployment_commit"]
    single_commit_mode = data.get("single_commit_mode", False)
    changed_files = data.get("changed_files", [])

    result = await analysis_pipeline.run_analysis(
        repo_meta=repo_meta,
        baseline_commit=baseline_commit,
        deployment_commit=deployment_commit,
        changed_files=changed_files,
        single_commit_mode=single_commit_mode,
        bypass_cache=req.bypass_cache
    )
    result.composite_risk_score = result.deterministic_risk_score
    result.composite_risk_level = result.deterministic_risk_level
    result.total_risk_factors = result.significant_factors_count
    return result

@router.post("/api/analyze")
async def analyze_repository(req: AnalyzeRepoRequest):
    """
    Connect to GitHub REST API, extract commit diffs, run deterministic scanners,
    correlate evidence, and execute Groq AI reasoning.
    """
    try:
        owner, repo = parse_repo_url(req.repo_url)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))

    client = GitHubClient()

    try:
        repo_meta, baseline_sha, candidate_sha, single_commit_mode = await resolve_deployment_targets(
            client=client,
            owner=owner,
            repo=repo,
            target_branch=req.branch,
            deployment_commit_sha=req.commit_sha
        )
    except GitHubAPIError as api_err:
        raise HTTPException(status_code=api_err.status_code or 500, detail=api_err.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error resolving repository: {str(e)}")

    try:
        changed_files = await fetch_deployment_diff(
            client=client,
            owner=owner,
            repo=repo,
            baseline_sha=baseline_sha,
            candidate_sha=candidate_sha,
            single_commit_mode=single_commit_mode
        )
    except GitHubAPIError as api_err:
        raise HTTPException(status_code=api_err.status_code or 500, detail=api_err.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve deployment diff: {str(e)}")

    # Execute complete risk analysis pipeline
    try:
        cache_key = analysis_pipeline._make_cache_key(owner, repo, baseline_sha, candidate_sha)
        if not req.bypass_cache and cache_key in analysis_pipeline._cache:
            cached_res = analysis_pipeline._cache[cache_key]
            if cached_res.security_scan and cached_res.security_scan.status != "not_checked" and cached_res.composite_risk_score is not None:
                res = cached_res.model_copy()
                res.cached = True
                return res

        result = await analysis_pipeline.run_analysis(
            repo_meta=repo_meta,
            baseline_commit=baseline_sha,
            deployment_commit=candidate_sha,
            changed_files=changed_files,
            single_commit_mode=single_commit_mode,
            bypass_cache=req.bypass_cache
        )
        result.security_scan = await scan_github_repository(
            client=client,
            owner=owner,
            repo=repo,
            ref=candidate_sha,
            changed_files=changed_files
        )

        sec = result.security_scan
        dep_score = result.deterministic_risk_score
        sec_score = sec.risk_score

        # Composite release gate: if either security or deployment has critical risks, overall is CRITICAL
        if sec.risk_level == "CRITICAL" or result.deterministic_risk_level == "CRITICAL":
            comp_level = "CRITICAL"
            comp_score = max(dep_score, sec_score, 80.0)
        elif sec.risk_level == "HIGH" or result.deterministic_risk_level == "HIGH":
            comp_level = "HIGH"
            comp_score = max(dep_score, sec_score, 55.0)
        elif sec.risk_level == "MEDIUM" or result.deterministic_risk_level == "MEDIUM":
            comp_level = "MEDIUM"
            comp_score = max(dep_score, sec_score, 30.0)
        else:
            comp_level = "LOW"
            comp_score = max(dep_score, sec_score)

        result.composite_risk_score = round(min(comp_score, 100.0), 1)
        result.composite_risk_level = comp_level
        result.total_risk_factors = result.significant_factors_count + sec.significant_count
        analysis_pipeline._cache[cache_key] = result
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Risk analysis error: {str(e)}")
