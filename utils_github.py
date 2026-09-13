import re
import base64
import requests
import tiktoken
from urllib.parse import urlparse

REVIEWABLE_EXTENSIONS = {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs', '.go', '.rb', '.php'}

IGNORED_PATHS = (
    'node_modules/', '.git/', 'dist/', 'build/', '__pycache__/',
    'vendor/', '.venv/', 'venv/',
)

PRIORITY_NAMES = {'main.py', 'index.js', 'app.py', 'index.ts', 'main.js', 'main.ts', 'server.py', 'server.js'}

MAX_FILE_SIZE = 100 * 1024  # 100 KB

MAX_REVIEW_TOKENS = 40_000

_tokenizer = tiktoken.get_encoding("cl100k_base")


def parse_github_url(url: str) -> tuple[str, str]:
    """
    Extract owner and repo name from a GitHub URL.
    Handles:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      github.com/owner/repo
    Returns (owner, repo) or raises ValueError.
    """
    url = url.strip().rstrip('/')
    if not url.startswith('http'):
        url = 'https://' + url

    parsed = urlparse(url)
    if parsed.netloc not in ('github.com', 'www.github.com'):
        raise ValueError(f"Not a GitHub URL: {url}")

    parts = [p for p in parsed.path.strip('/').split('/') if p]
    if len(parts) < 2:
        raise ValueError(f"Cannot extract owner/repo from: {url}")

    owner = parts[0]
    repo = parts[1]
    if repo.endswith('.git'):
        repo = repo[:-4]

    return owner, repo


def fetch_repo_files(owner: str, repo: str, token: str = None) -> list[dict]:
    """
    Retrieve the full file tree for a GitHub repo via the Git Trees API.
    Returns a list of dicts with keys: path, size.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    headers = {'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = f"Bearer {token}"

    response = requests.get(url, headers=headers, timeout=15)
    if response.status_code == 404:
        raise ValueError(f"Repository '{owner}/{repo}' not found or is private. Provide a token for private repos.")
    if response.status_code == 401:
        raise ValueError("GitHub token is invalid or expired.")
    if response.status_code != 200:
        raise ValueError(f"GitHub API error {response.status_code}: {response.text[:200]}")

    data = response.json()
    return [
        {'path': item['path'], 'size': item.get('size', 0)}
        for item in data.get('tree', [])
        if item['type'] == 'blob'
    ]


def filter_reviewable_files(files: list[dict], max_files: int = 10) -> list[dict]:
    """
    Filter to reviewable source files and return up to max_files,
    prioritised by: main entry points > src/lib paths > size descending.
    """
    filtered = []
    for f in files:
        path = f['path']
        # Skip ignored directories
        if any(path.startswith(ignored) or f'/{ignored}' in path for ignored in IGNORED_PATHS):
            continue
        # Keep only code extensions
        ext = '.' + path.rsplit('.', 1)[-1] if '.' in path else ''
        if ext not in REVIEWABLE_EXTENSIONS:
            continue
        # Skip oversized files
        if f['size'] > MAX_FILE_SIZE:
            continue
        filtered.append(f)

    def priority(f):
        name = f['path'].rsplit('/', 1)[-1].lower()
        in_src = f['path'].startswith('src/') or f['path'].startswith('lib/')
        is_main = name in PRIORITY_NAMES
        return (0 if is_main else 1, 0 if in_src else 1, -f['size'])

    filtered.sort(key=priority)
    return filtered[:max_files]


def fetch_file_content(owner: str, repo: str, path: str, token: str = None) -> str:
    """
    Fetch the decoded content of a single file from GitHub.
    Returns the file content as a string.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    headers = {'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = f"Bearer {token}"

    response = requests.get(url, headers=headers, timeout=15)
    if response.status_code != 200:
        raise ValueError(f"Could not fetch '{path}': HTTP {response.status_code}")

    data = response.json()
    if data.get('encoding') != 'base64':
        raise ValueError(f"Unexpected encoding for '{path}': {data.get('encoding')}")

    return base64.b64decode(data['content']).decode('utf-8', errors='replace')


def build_code_bundle(files: list[dict], max_tokens: int = MAX_REVIEW_TOKENS) -> tuple[str, list[str], str | None]:
    """
    Concatenate fetched file contents into a single review blob, prefixed
    with a manifest of included files.

    files: list of dicts with 'path' and 'content', already ordered by
    review priority (highest first, as returned by filter_reviewable_files).

    If the combined token count exceeds max_tokens, lower-priority files
    are dropped until the bundle fits, and a warning string describing the
    truncation is returned.

    Returns (code_blob, included_paths, warning_or_None).
    """
    included = []
    dropped = []
    total_tokens = 0

    for f in files:
        block = f"# === FILE: {f['path']} ===\n{f['content']}"
        block_tokens = len(_tokenizer.encode(block))
        if included and total_tokens + block_tokens > max_tokens:
            dropped.append(f['path'])
            continue
        included.append((f['path'], block))
        total_tokens += block_tokens

    manifest = "# Files included in this review: " + ", ".join(path for path, _ in included)
    body = "\n\n".join(block for _, block in included)
    code_blob = f"{manifest}\n\n{body}"

    warning = None
    if dropped:
        warning = (
            f"⚠️ Repository content exceeded the {max_tokens:,}-token review limit. "
            f"Reviewing the top {len(included)} file(s) by priority; "
            f"{len(dropped)} file(s) were skipped: {', '.join(dropped)}."
        )

    return code_blob, [path for path, _ in included], warning
