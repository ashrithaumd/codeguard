import requests

COMMENTS_URL = "https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"


def post_comment(installation_token: str, owner: str, repo: str, pr_number: int, body: str) -> None:
    """Post a comment on a PR. PRs are issues under the hood on GitHub's
    API, hence the /issues/ path even for a pull request number."""
    resp = requests.post(
        COMMENTS_URL.format(owner=owner, repo=repo, pr_number=pr_number),
        headers={
            "Authorization": f"Bearer {installation_token}",
            "Accept": "application/vnd.github+json",
        },
        json={"body": body},
        timeout=10,
    )
    resp.raise_for_status()
