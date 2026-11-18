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


def test_comprehensive_vulnerability_pattern_detection():
    samples = [
        # HARDCODED-API-TOKEN
        ('aws_key = "' + 'AKIA' + 'IOSFODNN7EXAMPLE"', "HARDCODED-API-TOKEN"),
        ('github_token = "' + 'ghp_' + '1234567890abcdefghijklmnopqrstuvwxyz"', "HARDCODED-API-TOKEN"),
        ('slack_token = "' + 'xoxb-' + '123456789012-' + 'abcdefghijklmnopqrst"', "HARDCODED-API-TOKEN"),
        ('stripe_key = "' + 'sk_live_' + '1234567890abcdefghijklmn"', "HARDCODED-API-TOKEN"),
        ('google_api = "' + 'AIza' + 'SyD-1234567890abcdefghijklmnopqrst"', "HARDCODED-API-TOKEN"),
        ('key = "' + '-----BEGIN RSA ' + 'PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."', "HARDCODED-API-TOKEN"),

        # HARDCODED-DATABASE-URI
        ('url = "postgres://admin:secretpass@localhost:5432/mydb"', "HARDCODED-DATABASE-URI"),
        ('mongo = "mongodb://user:password123@cluster0.mongodb.net/prod"', "HARDCODED-DATABASE-URI"),

        # PATH-TRAVERSAL
        ('with open(f"/app/data/{user_path}") as f:', "PATH-TRAVERSAL"),
        ('send_file(request.args.get("file"))', "PATH-TRAVERSAL"),
        ('fs.readFile(req.query.target, "utf8")', "PATH-TRAVERSAL"),

        # TEMPLATE-INJECTION-SSTI
        ('render_template_string(f"Hello {user_input}")', "TEMPLATE-INJECTION-SSTI"),
        ('jinja2.Template(f"Hello {name}").render()', "TEMPLATE-INJECTION-SSTI"),
        ('ejs.render(req.body.template)', "TEMPLATE-INJECTION-SSTI"),

        # WEAK-CRYPTOGRAPHY
        ('token = hashlib.md5(data.encode()).hexdigest()', "WEAK-CRYPTOGRAPHY"),
        ('sig = hashlib.sha1(payload).digest()', "WEAK-CRYPTOGRAPHY"),
        ('cipher = AES.new(key, AES.MODE_ECB)', "WEAK-CRYPTOGRAPHY"),
        ('crypto.createHash("md5")', "WEAK-CRYPTOGRAPHY"),

        # INSECURE-RANDOM
        ('auth_token = "".join([random.choice(chars) for _ in range(32)])', "INSECURE-RANDOM"),
        ('password = random.randint(100000, 999999)', "INSECURE-RANDOM"),

        # INSECURE-JWT
        ('payload = jwt.decode(token, verify=False)', "INSECURE-JWT"),
        ('jwt.decode(token, key, algorithms=["none"])', "INSECURE-JWT"),

        # XML-EXTERNAL-ENTITY-XXE
        ('parser = etree.XMLParser(resolve_entities=True)', "XML-EXTERNAL-ENTITY-XXE"),
        ('libxml_disable_entity_loader(false)', "XML-EXTERNAL-ENTITY-XXE"),

        # INSECURE-CORS
        ('app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)', "INSECURE-CORS"),

        # DEBUG-MODE-ENABLED
        ('app.run(host="0.0.0.0", debug=True)', "DEBUG-MODE-ENABLED"),
        ('DEBUG = True', "DEBUG-MODE-ENABLED"),

        # OPEN-REDIRECT
        ('return redirect(request.args.get("next"))', "OPEN-REDIRECT"),
        ('res.redirect(req.query.redirect_url)', "OPEN-REDIRECT"),

        # PROTOTYPE-POLLUTION
        ('Object.assign(target, req.body)', "PROTOTYPE-POLLUTION"),
        ('lodash.merge({}, req.body)', "PROTOTYPE-POLLUTION"),

        # INSECURE-PERMISSIONS-OR-TEMP
        ('temp_file = tempfile.mktemp()', "INSECURE-PERMISSIONS-OR-TEMP"),
        ('os.chmod(path, 0o777)', "INSECURE-PERMISSIONS-OR-TEMP"),

        # NOSQL-INJECTION
        ('db.users.find({ "$where": "this.user == \'" + user })', "NOSQL-INJECTION"),

        # LDAP-INJECTION
        ('ldap.search_s("dc=com", ldap.SCOPE_SUBTREE, "cn=" + username)', "LDAP-INJECTION"),

        # REDOS-UNTRUSTED-REGEX
        ('regex = new RegExp(req.query.pattern)', "REDOS-UNTRUSTED-REGEX"),
        ('re.compile(request.args.get("filter"))', "REDOS-UNTRUSTED-REGEX"),

        # INSECURE-COOKIE
        ('response.set_cookie("auth", token, httponly=False)', "INSECURE-COOKIE"),

        # CODE-BROKEN-AUTHENTICATION
        ('def is_authenticated(user): return True', "CODE-BROKEN-AUTHENTICATION"),
        ('if password == "" or True:', "CODE-BROKEN-AUTHENTICATION"),
    ]

    for code_snippet, expected_rule in samples:
        findings = scan_security_files([{"filename": "app/service.py", "content": code_snippet}])
        detected_rules = {f.rule_id for f in findings}
        assert expected_rule in detected_rules, f"Expected {expected_rule} for snippet: {code_snippet}"


def test_changed_files_are_prioritized_in_scan():
    class FakeClient:
        token = "token"

        async def get_repository_tree(self, owner, repo, ref):
            # 120 files: file_000 to file_119
            tree = [{"path": f"src/file_{i:03d}.py", "type": "blob"} for i in range(120)]
            return tree, False

        async def get_file_content(self, owner, repo, path, ref, max_bytes):
            if path == "src/file_115.py":
                return 'app.run(debug=True)'
            return '# normal file content'

    # src/file_115.py is at index 115 (past 100 limit), but it was changed in deployment
    report = asyncio.run(scan_github_repository(
        FakeClient(),
        "owner",
        "repo",
        "sha",
        changed_files=[{"filename": "src/file_115.py"}]
    ))

    # Because it was prioritized, it was fetched and scanned
    matched_files = [f.file for f in report.findings]
    assert "src/file_115.py" in matched_files
    assert any(f.rule_id == "DEBUG-MODE-ENABLED" for f in report.findings)

