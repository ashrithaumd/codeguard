import time

import jwt
import requests

from codeguard.config import get_settings

INSTALLATION_TOKEN_URL = "https://api.github.com/app/installations/{installation_id}/access_tokens"


def build_app_jwt() -> str:
    """Build a short-lived JWT authenticating as the GitHub App itself
    (not any installation) — used only to request installation tokens.

    `iat` is backdated by 60s to tolerate clock drift between this
    machine and GitHub's, per GitHub's own docs. `exp` is capped at 10
    minutes, GitHub's maximum allowed lifetime for App JWTs.
    """
    settings = get_settings()
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": str(settings.github_app_id),
    }
    private_key = _load_private_key(settings)
    return jwt.encode(payload, private_key, algorithm="RS256")


def _load_private_key(settings) -> str:
    """github_private_key (raw PEM, an env-var-friendly secret — see
    Settings' own docstring) wins when set; otherwise falls back to
    reading github_private_key_path, local dev's mounted-file
    convention. Raises plainly if neither is configured rather than
    silently trying to open an empty path.
    """
    if settings.github_private_key:
        return settings.github_private_key
    if not settings.github_private_key_path:
        raise ValueError("neither github_private_key nor github_private_key_path is set")
    with open(settings.github_private_key_path, "r") as f:
        return f.read()


def get_installation_token(installation_id: int) -> str:
    """Exchange a fresh App JWT for a short-lived installation access
    token, scoped to one installation.

    Deliberately uncached: called fresh on every use, even though the
    resulting token is valid for an hour. Each unit of work gets its
    own token rather than reusing one across requests/jobs — smaller
    blast radius if a token leaks, and no cache-invalidation logic to
    get wrong.
    """
    app_jwt = build_app_jwt()
    resp = requests.post(
        INSTALLATION_TOKEN_URL.format(installation_id=installation_id),
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["token"]
