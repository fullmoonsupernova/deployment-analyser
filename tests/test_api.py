import asyncio
from httpx import AsyncClient, ASGITransport
from backend.app.main import app

def test_health_check_endpoint():
    async def _run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "healthy"
            assert "scanner_version" in data
    asyncio.run(_run())

def test_scenarios_list_endpoint():
    async def _run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/scenarios")
            assert resp.status_code == 200
            data = resp.json()
            assert "scenarios" in data
            assert len(data["scenarios"]) >= 5
    asyncio.run(_run())

def test_analyze_scenario_endpoint():
    async def _run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            payload = {"scenario_id": "scenario-1", "bypass_cache": True}
            resp = await client.post("/api/analyze-scenario", json=payload)
            assert resp.status_code == 200
            data = resp.json()
            assert data["deterministic_risk_level"] in ["HIGH", "CRITICAL"]
            assert len(data["findings"]) > 0
            assert "ai_analysis" in data
    asyncio.run(_run())

def test_index_page_render():
    async def _run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/")
            assert resp.status_code == 200
            assert "SRE RISK ANALYZER" in resp.text
            assert "Production Deployment Risk Analyzer" in resp.text
    asyncio.run(_run())

def test_invalid_repo_url():
    async def _run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            payload = {"repo_url": "invalid_url_with_no_slash"}
            resp = await client.post("/api/analyze", json=payload)
            assert resp.status_code == 400
    asyncio.run(_run())
