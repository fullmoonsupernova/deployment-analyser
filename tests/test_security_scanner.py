import asyncio
import json

from backend.app.analysis.groq import GroqAnalyzer
from backend.app.analysis.schemas import EvidencePackage, RiskFinding, SecurityAITriage
from backend.app.github.client import GitHubClient
from backend.app.scanner.security import scan_github_repository, scan_security_files


def test_static_security_patterns_report_locations_without_source_text():
    source = {
        "filename": "src/data.py",
        "content": (
            'cursor.execute(f"SELECT * FROM users WHERE name={name}")\n'
            "subprocess.run(command, shell=True)\n"
            "yaml.load(payload)\n"
            "yaml.load(payload, Loader=yaml.SafeLoader)\n"
            "requests.get(url, verify=False)\n"
            'password = "this-is-a-secret-value"\n'
        )
    }

    findings = scan_security_files([source], {"src/data.py"})

    rule_ids = {finding.rule_id for finding in findings}
    assert {
        "CODE-SQLI",
        "CODE-CMDI",
        "CODE-UNSAFE-DESERIALIZATION",
        "TLS-VERIFY-DISABLED",
        "HARDCODED-CREDENTIAL",
    }.issubset(rule_ids)
    assert sum(finding.rule_id == "CODE-UNSAFE-DESERIALIZATION" for finding in findings) == 1
    assert all(finding.file == "src/data.py" for finding in findings)
    assert all(finding.changed_in_deployment for finding in findings)
    assert "this-is-a-secret-value" not in str([finding.model_dump() for finding in findings])


def test_groq_security_triage_receives_only_sanitized_metadata(monkeypatch):
    findings = scan_security_files([{
        "filename": "private/path/handler.py",
        "content": 'cursor.execute(f"SELECT * FROM users WHERE name={SECRET_VALUE}")'
    }])
    analyzer = GroqAnalyzer(api_key="test-key")
    sent_prompts = []

    async def fake_call(prompt):
        sent_prompts.append(prompt)
        return json.dumps({
            "summary": "Review the high-confidence query and command-execution findings.",
            "prioritized_finding_ids": [findings[0].id, "unknown-id"]
        })

    monkeypatch.setattr(analyzer, "_call_groq", fake_call)
    result = asyncio.run(analyzer.triage_security_findings(findings))

    assert result.status == "completed"
    assert result.prioritized_finding_ids == [findings[0].id]
    assert "SECRET_VALUE" not in sent_prompts[0]
    assert "private/path/handler.py" not in sent_prompts[0]
    assert "CODE-SQLI" in sent_prompts[0]


def test_deployment_groq_prompt_does_not_include_source_or_repository_identity(monkeypatch):
    evidence = EvidencePackage(
        repository={"name": "private-repo", "full_name": "secret-owner/private-repo"},
        findings=[RiskFinding(
            id="finding-001",
            category="code",
            type="payment_logic_modification",
            severity_hint="high",
            evidence="PRIVATE_SOURCE_CODE",
            file="private/path/checkout.py",
            description="Source file private/path/checkout.py changed."
        )],
        services=[],
        relationships=[],
        historical_matches=[]
    )
    analyzer = GroqAnalyzer(api_key="test-key")
    sent_prompts = []

    async def fake_call(prompt):
        sent_prompts.append(prompt)
        return json.dumps({"overall_assessment": "high", "summary": "Review the code change."})

    monkeypatch.setattr(analyzer, "_call_groq", fake_call)
    asyncio.run(analyzer.analyze(evidence))

    assert "PRIVATE_SOURCE_CODE" not in sent_prompts[0]
    assert "private/path/checkout.py" not in sent_prompts[0]
    assert "secret-owner/private-repo" not in sent_prompts[0]
    assert "payment_logic_modification" in sent_prompts[0]


def test_repository_scan_fetches_source_and_marks_deployment_path(monkeypatch):
    class FakeGitHubClient:
        token = "configured-token"

        async def get_repository_tree(self, owner, repo, ref):
            return [
                {"path": "src/handler.py", "type": "blob"},
                {"path": "node_modules/library/index.js", "type": "blob"},
                {"path": "README.md", "type": "blob"},
            ], False

        async def get_file_content(self, owner, repo, path, ref, max_bytes):
            assert path == "src/handler.py"
            return 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'

    async def fake_triage(self, findings):
        return SecurityAITriage(
            status="completed",
            summary="Review the candidate SQL construction.",
            prioritized_finding_ids=[finding.id for finding in findings]
        )

    monkeypatch.setattr(GroqAnalyzer, "triage_security_findings", fake_triage)
    report = asyncio.run(scan_github_repository(
        FakeGitHubClient(),
        "owner",
        "repo",
        "commit-sha",
        [{"filename": "src/handler.py"}]
    ))

    assert report.status == "completed"
    assert report.candidates_total == 1
    assert report.files_scanned == 1
    assert report.findings[0].changed_in_deployment is True
    assert report.ai_triage.status == "completed"


def test_repository_scan_supports_public_repository_without_token():
    class FakeGitHubClient:
        token = ""

        async def get_repository_tree(self, owner, repo, ref):
            return [], False

    report = asyncio.run(
        scan_github_repository(FakeGitHubClient(), "owner", "repo", "commit-sha", [])
    )

    assert report.status == "completed"
    assert report.files_scanned == 0
    assert report.candidates_total == 0


def test_repository_tree_resolves_commit_to_tree_sha(monkeypatch):
    requested_urls = []

    class FakeResponse:
        status_code = 200

        def __init__(self, data):
            self.data = data

        def json(self):
            return self.data

    class FakeAsyncClient:
        def __init__(self, timeout=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_value, traceback):
            return None

        async def get(self, url, headers, params=None):
            requested_urls.append(url)
            if "/commits/" in url:
                return FakeResponse({"commit": {"tree": {"sha": "tree-sha"}}})
            return FakeResponse({"tree": [{"path": "src/app.py", "type": "blob"}]})

    monkeypatch.setattr("backend.app.github.client.httpx.AsyncClient", FakeAsyncClient)
    tree, truncated = asyncio.run(
        GitHubClient(token="test-token").get_repository_tree("owner", "repo", "commit-sha")
    )

    assert requested_urls[0].endswith("/commits/commit-sha")
    assert requested_urls[1].endswith("/git/trees/tree-sha")
    assert tree == [{"path": "src/app.py", "type": "blob"}]
    assert truncated is False


def test_github_token_is_used_for_repository_read_access():
    headers = GitHubClient(token="sample-github-token")._headers()
    assert headers["Authorization"] == "Bearer sample-github-token"


def test_explicit_empty_token_disables_configured_token():
    assert "Authorization" not in GitHubClient(token="")._headers()


def test_github_client_retries_public_repository_without_rejected_token(monkeypatch):
    requested_headers = []

    class FakeResponse:
        headers = {}

        def __init__(self, status_code, data=None):
            self.status_code = status_code
            self.data = data or {}

        def json(self):
            return self.data

    class FakeAsyncClient:
        def __init__(self, timeout=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_value, traceback):
            return None

        async def get(self, url, headers):
            requested_headers.append(headers)
            if "Authorization" in headers:
                return FakeResponse(401, {"message": "Bad credentials"})
            return FakeResponse(200, {"full_name": "owner/repo"})

    monkeypatch.setattr("backend.app.github.client.httpx.AsyncClient", FakeAsyncClient)
    client = GitHubClient(token="rejected-token")
    repository = asyncio.run(client.get_repo("owner", "repo"))

    assert repository["full_name"] == "owner/repo"
    assert "Authorization" in requested_headers[0]
    assert "Authorization" not in requested_headers[1]
    assert client.token == ""


def test_github_401_explains_token_rejection_without_echoing_token(monkeypatch):
    class FakeResponse:
        status_code = 401

    class FakeAsyncClient:
        def __init__(self, timeout=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_value, traceback):
            return None

        async def get(self, url, headers):
            assert headers["Authorization"] == "Bearer private-test-token"
            return FakeResponse()

    monkeypatch.setattr("backend.app.github.client.httpx.AsyncClient", FakeAsyncClient)

    async def fetch_repo():
        try:
            await GitHubClient(token="private-test-token").get_repo("owner", "repo")
        except Exception as error:
            return error
        raise AssertionError("Expected GitHub authentication failure")

    error = asyncio.run(fetch_repo())
    assert error.status_code == 401
    assert "GitHub rejected GITHUB_TOKEN" in error.message
    assert "private-test-token" not in error.message


def test_groq_client_uses_configured_api_key(monkeypatch):
    observed_headers = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"choices": [{"message": {"content": "ok"}}]}

    class FakeAsyncClient:
        def __init__(self, timeout=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_value, traceback):
            return None

        async def post(self, url, headers, json):
            observed_headers.update(headers)
            return FakeResponse()

    monkeypatch.setattr("backend.app.analysis.groq.httpx.AsyncClient", FakeAsyncClient)
    response = asyncio.run(
        GroqAnalyzer(api_key="sample-groq-key")._call_groq("sanitized prompt")
    )

    assert response == "ok"
    assert observed_headers["Authorization"] == "Bearer sample-groq-key"
