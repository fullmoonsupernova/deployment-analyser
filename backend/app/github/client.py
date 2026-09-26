import httpx
from typing import Dict, Any, Optional, List
from ..config import settings

class GitHubAPIError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message

class GitHubClient:
    def __init__(self, token: Optional[str] = None):
        self.token = token if token else settings.GITHUB_TOKEN
        self.base_url = "https://api.github.com"

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SRE-Deployment-Risk-Analyzer/1.0"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def get_repo(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetch repository metadata."""
        url = f"{self.base_url}/repos/{owner}/{repo}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code == 404:
                raise GitHubAPIError(f"Repository '{owner}/{repo}' not found. Please verify the URL or ensure the repository is public.", 404)
            elif resp.status_code == 403:
                rate_limit_reset = resp.headers.get("x-ratelimit-reset", "")
                raise GitHubAPIError(f"GitHub API rate limit exceeded or access forbidden. Please set a GITHUB_TOKEN in settings. (Reset: {rate_limit_reset})", 403)
            elif resp.status_code != 200:
                raise GitHubAPIError(f"GitHub API error ({resp.status_code}): {resp.text}", resp.status_code)
            return resp.json()

    async def get_commits(self, owner: str, repo: str, sha: Optional[str] = None, per_page: int = 5) -> List[Dict[str, Any]]:
        """Fetch latest commits."""
        url = f"{self.base_url}/repos/{owner}/{repo}/commits"
        params = {"per_page": per_page}
        if sha:
            params["sha"] = sha
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=self._headers(), params=params)
            if resp.status_code != 200:
                raise GitHubAPIError(f"Failed to fetch commits ({resp.status_code}): {resp.text}", resp.status_code)
            return resp.json()

    async def get_commit(self, owner: str, repo: str, ref: str) -> Dict[str, Any]:
        """Fetch single commit details including changed files."""
        url = f"{self.base_url}/repos/{owner}/{repo}/commits/{ref}"
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code == 404:
                raise GitHubAPIError(f"Commit/Ref '{ref}' not found in '{owner}/{repo}'.", 404)
            elif resp.status_code != 200:
                raise GitHubAPIError(f"Failed to fetch commit details ({resp.status_code}): {resp.text}", resp.status_code)
            return resp.json()

    async def compare_commits(self, owner: str, repo: str, base: str, head: str) -> Dict[str, Any]:
        """Compare two commits via GitHub compare API."""
        url = f"{self.base_url}/repos/{owner}/{repo}/compare/{base}...{head}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code == 404:
                raise GitHubAPIError(f"Cannot compare '{base}'...'{head}'. One of the revisions was not found.", 404)
            elif resp.status_code != 200:
                raise GitHubAPIError(f"GitHub compare error ({resp.status_code}): {resp.text}", resp.status_code)
            return resp.json()

    async def get_file_content(self, owner: str, repo: str, path: str, ref: Optional[str] = None) -> Optional[str]:
        """Fetch raw content of a file from repository."""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        params = {}
        if ref:
            params["ref"] = ref
        headers = self._headers()
        headers["Accept"] = "application/vnd.github.v3.raw"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    return resp.text
        except Exception:
            pass
        return None
