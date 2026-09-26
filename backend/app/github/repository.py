import re
from typing import Tuple, Dict, Any, Optional
from .client import GitHubClient, GitHubAPIError

def parse_repo_url(url_or_slug: str) -> Tuple[str, str]:
    """
    Parse a GitHub repository URL or slug into (owner, repo).
    Supports:
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
      - http://github.com/owner/repo/
      - owner/repo
    """
    cleaned = url_or_slug.strip()
    # Remove protocol
    cleaned = re.sub(r'^https?://', '', cleaned)
    # Remove github.com/
    cleaned = re.sub(r'^github\.com/', '', cleaned)
    # Remove trailing .git and slashes
    cleaned = re.sub(r'\.git/?$', '', cleaned).strip('/')
    
    parts = cleaned.split('/')
    if len(parts) >= 2:
        return parts[0], parts[1]
    
    raise ValueError(f"Invalid GitHub repository identifier '{url_or_slug}'. Expected format 'https://github.com/owner/repo' or 'owner/repo'.")

async def resolve_deployment_targets(
    client: GitHubClient,
    owner: str,
    repo: str,
    target_branch: Optional[str] = None,
    deployment_commit_sha: Optional[str] = None
) -> Tuple[Dict[str, Any], str, str, bool]:
    """
    Identifies repository default branch, candidate commit, and baseline commit.
    
    Returns:
        (repo_metadata, baseline_sha, candidate_sha, single_commit_mode)
    """
    repo_meta = await client.get_repo(owner, repo)
    default_branch = repo_meta.get("default_branch", "main")
    branch = target_branch if target_branch else default_branch

    # Resolve candidate commit
    if deployment_commit_sha:
        commit_data = await client.get_commit(owner, repo, deployment_commit_sha)
        candidate_sha = commit_data["sha"]
        parents = commit_data.get("parents", [])
    else:
        commits = await client.get_commits(owner, repo, sha=branch, per_page=2)
        if not commits:
            raise GitHubAPIError(f"No commits found on branch '{branch}' in repository '{owner}/{repo}'.")
        candidate_sha = commits[0]["sha"]
        parents = commits[0].get("parents", [])

    # Identify baseline commit
    if parents:
        baseline_sha = parents[0]["sha"]
        single_commit_mode = False
    else:
        # Single commit repository
        baseline_sha = candidate_sha
        single_commit_mode = True

    return repo_meta, baseline_sha, candidate_sha, single_commit_mode
