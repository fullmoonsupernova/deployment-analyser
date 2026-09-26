from typing import List, Dict, Any
from .client import GitHubClient

MAX_PATCH_LENGTH = 30000

async def fetch_deployment_diff(
    client: GitHubClient,
    owner: str,
    repo: str,
    baseline_sha: str,
    candidate_sha: str,
    single_commit_mode: bool = False
) -> List[Dict[str, Any]]:
    """
    Retrieves the list of changed files, patches, and statuses between the baseline
    revision and deployment candidate.
    """
    raw_files: List[Dict[str, Any]] = []

    if single_commit_mode or baseline_sha == candidate_sha:
        # Fetch files from the single commit
        commit_data = await client.get_commit(owner, repo, candidate_sha)
        raw_files = commit_data.get("files", [])
    else:
        # Fetch comparison between baseline and candidate
        compare_data = await client.compare_commits(owner, repo, baseline_sha, candidate_sha)
        raw_files = compare_data.get("files", [])

    normalized_files: List[Dict[str, Any]] = []

    for f in raw_files:
        filename = f.get("filename", "")
        status = f.get("status", "modified")
        patch = f.get("patch", "")
        additions = f.get("additions", 0)
        deletions = f.get("deletions", 0)

        # Truncate overly long generated or lockfile patches to prevent memory bloat
        if patch and len(patch) > MAX_PATCH_LENGTH:
            patch = patch[:MAX_PATCH_LENGTH] + "\n...[DIFF TRUNCATED FOR SRE ANALYSIS]..."

        normalized_files.append({
            "filename": filename,
            "status": status,
            "patch": patch,
            "additions": additions,
            "deletions": deletions,
            "raw_url": f.get("raw_url", "")
        })

    return normalized_files
