import asyncio
import json
from pathlib import Path
from backend.app.analysis.risk import analysis_pipeline

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

def test_scenario_1_destructive_migration():
    async def _run():
        path = FIXTURES_DIR / "scenario_1_destructive_migration.json"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        result = await analysis_pipeline.run_analysis(
            repo_meta=data["repo_meta"],
            baseline_commit=data["baseline_commit"],
            deployment_commit=data["deployment_commit"],
            changed_files=data["changed_files"],
            single_commit_mode=False,
            bypass_cache=True
        )

        assert result.deterministic_risk_level in ["HIGH", "CRITICAL"]
        finding_types = [f.type for f in result.findings]
        assert "destructive_database_change" in finding_types
        assert "expand_contract_hazard" in finding_types
        assert len(result.ai_analysis.failure_scenarios) > 0
    asyncio.run(_run())

def test_scenario_2_reduced_redundancy():
    async def _run():
        path = FIXTURES_DIR / "scenario_2_reduced_redundancy.json"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        result = await analysis_pipeline.run_analysis(
            repo_meta=data["repo_meta"],
            baseline_commit=data["baseline_commit"],
            deployment_commit=data["deployment_commit"],
            changed_files=data["changed_files"],
            single_commit_mode=False,
            bypass_cache=True
        )

        finding_types = [f.type for f in result.findings]
        assert "single_replica_risk" in finding_types
        assert any("replica" in sc.title.lower() for sc in result.ai_analysis.failure_scenarios)
    asyncio.run(_run())

def test_scenario_3_dependency_upgrade():
    async def _run():
        path = FIXTURES_DIR / "scenario_3_dependency_upgrade.json"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        result = await analysis_pipeline.run_analysis(
            repo_meta=data["repo_meta"],
            baseline_commit=data["baseline_commit"],
            deployment_commit=data["deployment_commit"],
            changed_files=data["changed_files"],
            single_commit_mode=False,
            bypass_cache=True
        )

        finding_types = [f.type for f in result.findings]
        assert "payment_dependency_upgrade" in finding_types or "major_dependency_upgrade" in finding_types
    asyncio.run(_run())

def test_scenario_4_traffic_risk():
    async def _run():
        path = FIXTURES_DIR / "scenario_4_traffic_risk.json"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        result = await analysis_pipeline.run_analysis(
            repo_meta=data["repo_meta"],
            baseline_commit=data["baseline_commit"],
            deployment_commit=data["deployment_commit"],
            changed_files=data["changed_files"],
            single_commit_mode=False,
            bypass_cache=True
        )

        finding_types = [f.type for f in result.findings]
        assert "traffic_amplification_risk" in finding_types or "missing_pagination" in finding_types
    asyncio.run(_run())

def test_scenario_5_combined_deployment():
    async def _run():
        path = FIXTURES_DIR / "scenario_5_combined_deployment.json"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        result = await analysis_pipeline.run_analysis(
            repo_meta=data["repo_meta"],
            baseline_commit=data["baseline_commit"],
            deployment_commit=data["deployment_commit"],
            changed_files=data["changed_files"],
            single_commit_mode=False,
            bypass_cache=True
        )

        assert result.deterministic_risk_level == "CRITICAL"
        assert result.significant_factors_count >= 3
        assert len(result.findings) >= 5
    asyncio.run(_run())
