import httpx
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import quote
from ..config import settings

class GitHubAPIError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message

class GitHubClient:
    def __init__(self, token: Optional[str] = None):
        self.token = settings.GITHUB_TOKEN if token is None else token
        self.base_url = "https://api.github.com"

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SRE-Deployment-Risk-Analyzer/1.0"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @staticmethod
    def _raise_if_unauthorized(status_code: int) -> None:
        if status_code == 401:
            raise GitHubAPIError(
                "GitHub rejected GITHUB_TOKEN (401 Unauthorized). Verify it is active, copied without a 'Bearer ' prefix, and belongs to an account with access to this repository.",
                401
            )

    async def get_repo(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetch repository metadata."""
        url = f"{self.base_url}/repos/{owner}/{repo}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=self._headers())
            is_bad_credentials = (
                resp.status_code == 401
                and bool(self.token)
                and callable(getattr(resp, "json", None))
                and resp.json().get("message") == "Bad credentials"
            )
            if is_bad_credentials:
                anonymous_headers = self._headers()
                anonymous_headers.pop("Authorization", None)
                anonymous_resp = await client.get(url, headers=anonymous_headers)
                if anonymous_resp.status_code == 200:
                    self.token = ""
                    resp = anonymous_resp
            self._raise_if_unauthorized(resp.status_code)
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
            self._raise_if_unauthorized(resp.status_code)
            if resp.status_code != 200:
                raise GitHubAPIError(f"Failed to fetch commits ({resp.status_code}): {resp.text}", resp.status_code)
            return resp.json()

    async def get_commit(self, owner: str, repo: str, ref: str) -> Dict[str, Any]:
        """Fetch single commit details including changed files."""
        url = f"{self.base_url}/repos/{owner}/{repo}/commits/{ref}"
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, headers=self._headers())
            self._raise_if_unauthorized(resp.status_code)
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
            self._raise_if_unauthorized(resp.status_code)
            if resp.status_code == 404:
                raise GitHubAPIError(f"Cannot compare '{base}'...'{head}'. One of the revisions was not found.", 404)
            elif resp.status_code != 200:
                raise GitHubAPIError(f"GitHub compare error ({resp.status_code}): {resp.text}", resp.status_code)
            return resp.json()

    async def get_repository_tree(self, owner: str, repo: str, ref: str) -> Tuple[List[Dict[str, Any]], bool]:
        """Resolve a revision's tree SHA, then fetch its recursive repository tree."""
        commit_url = f"{self.base_url}/repos/{owner}/{repo}/commits/{quote(ref, safe='')}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            commit_resp = await client.get(commit_url, headers=self._headers())
            self._raise_if_unauthorized(commit_resp.status_code)
            if commit_resp.status_code != 200:
                raise GitHubAPIError(
                    f"Failed to resolve repository revision (HTTP {commit_resp.status_code}).",
                    commit_resp.status_code
                )
            commit_data = commit_resp.json()
            tree_sha = commit_data.get("commit", {}).get("tree", {}).get("sha")
            if not isinstance(tree_sha, str):
                raise GitHubAPIError("GitHub commit response did not contain a tree SHA.")

            tree_url = f"{self.base_url}/repos/{owner}/{repo}/git/trees/{quote(tree_sha, safe='')}"
            resp = await client.get(
                tree_url,
                headers=self._headers(),
                params={"recursive": "1"}
            )
        self._raise_if_unauthorized(resp.status_code)
        if resp.status_code != 200:
            raise GitHubAPIError(
                f"Failed to fetch repository tree (HTTP {resp.status_code}).",
                resp.status_code
            )
        data = resp.json()
        tree = data.get("tree")
        if not isinstance(tree, list):
            raise GitHubAPIError("GitHub returned an invalid repository tree.")
        return tree, bool(data.get("truncated", False))

    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: Optional[str] = None,
        max_bytes: int = 500_000
    ) -> Optional[str]:
        """Fetch bounded raw content of a text file from a repository."""
        normalized_path = path.replace("\\", "/")
        if normalized_path.startswith("/") or any(
            segment in (".", "..") for segment in normalized_path.split("/")
        ):
            raise ValueError("Repository file path must be relative and cannot traverse directories.")
        encoded_path = quote(path, safe="/")
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{encoded_path}"
        params = {}
        if ref:
            params["ref"] = ref
        headers = self._headers()
        headers["Accept"] = "application/vnd.github.v3.raw"
        async with httpx.AsyncClient(timeout=20.0) as client:
            async with client.stream("GET", url, headers=headers, params=params) as resp:
                self._raise_if_unauthorized(resp.status_code)
                if resp.status_code == 404:
                    return None
                if resp.status_code != 200:
                    raise GitHubAPIError(
                        f"Failed to fetch repository file (HTTP {resp.status_code}).",
                        resp.status_code
                    )

                content = bytearray()
                async for chunk in resp.aiter_bytes():
                    if len(content) + len(chunk) > max_bytes:
                        raise GitHubAPIError(
                            f"Repository file exceeds the {max_bytes}-byte scan limit.",
                            413
                        )
                    content.extend(chunk)
        return content.decode("utf-8", errors="replace")
