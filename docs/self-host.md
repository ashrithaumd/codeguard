# Self-hosting

Running CodeGuard locally, the test suite, configuration, and the Azure deployment.

For the GitHub App itself see [github-app.md](github-app.md). For a one-off scan with no
infrastructure at all, see the README quickstart — `codeguard audit` needs only an Anthropic key.

## Local stack

```bash
cp .env.example .env    # fill in ANTHROPIC_API_KEY at minimum
docker compose up -d
```

That brings up:

| Service | Port | What it is |
|---|---|---|
| `db` | 5433 | Postgres. Migrations apply automatically on startup. Also creates `codeguard_test`. |
| `api` | 8000 | Webhook receiver, `/health`, `/metrics`, and the review dashboard at `/dashboard`. |
| `worker` | 9000 | Claims jobs and runs reviews. Its own `/metrics`. |
| `prometheus` | 9090 | Scrapes both. |
| `grafana` | 3000 | Anonymous viewer access, CodeGuard dashboard pre-provisioned. |

For real webhook deliveries locally, use a tunnel — see [github-app.md](github-app.md#6-point-the-webhook-url-at-your-deployment).

## Tests

The container is the recommended route and the only one that covers everything:

```bash
docker compose exec worker pytest
```

The image already carries `semgrep`, `bandit`, `ruff` and `git`, and compose builds it with the dev
extras. The suite points itself at the separate `codeguard_test` database, so it is safe to run
while the api and worker are up.

On the host instead, install the dev extras and run the groups by what each needs:

```bash
pip install -e ".[dev]"
pytest tests/diff tests/github                  # pure unit tests, nothing external
pytest tests/tools tests/cli tests/mcp          # + semgrep, bandit, ruff, git on PATH
pytest tests/queue tests/pipeline tests/api     # + Postgres (docker compose up -d db)
```

Two things worth knowing before trusting a green host run:

- **`tests/pipeline` and `tests/api` need Postgres.** Most of `tests/pipeline` does not, but
  `test_hunk_cache.py`, `test_feedback.py` and `test_feedback_webhook.py` open real connections, so
  the directory belongs with `tests/queue`.
- **Semgrep cannot run on Windows at all.** Its CLI execs a `semgrep-core` binary not shipped for
  that platform. The live-runner and rule tests skip there rather than fail, so a Windows host run
  comes back green having exercised none of `rules/`. The container is the only place that coverage
  is real.

The custom ruleset has its own tests, which every rule must have a case in:

```bash
docker compose exec worker semgrep --test --metrics=off rules/
```

## `.codeguard.yml`

Optional, committed at the repository root, read from the **base branch only** — a pull request can
never change the policy that reviews it.

```yaml
fix_threshold: high        # low | medium | high | critical — min severity for a proposed fix
gate_threshold: critical   # min severity that fails the Check Run
enable_ai_aware: true      # run the LLM-security ruleset + eval-hygiene checks
max_files_per_pr: 15       # also capped by the operator's global ceiling
max_tokens_per_pr: 40000
max_wall_clock_s: 120
ignored_paths: []          # fnmatch patterns, applied before language filtering
```

## Environment variables

`ANTHROPIC_API_KEY` is the **only** setting without a default. Everything else is optional and
gates a specific feature.

| Variable | Needed for | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | Everything | The only genuinely required setting. Every entry point exits 2 with a one-line error when it is unset. A key that is set but invalid starts normally and fails at the first model call. |
| `DATABASE_URL` | GitHub App path | The queue. Not needed by `codeguard audit` or the MCP server. `sslmode=require` in production. |
| `GITHUB_APP_ID` | GitHub App path | |
| `GITHUB_WEBHOOK_SECRET` | GitHub App path | Verifies `X-Hub-Signature-256` on every delivery. |
| `GITHUB_PRIVATE_KEY_PATH` | GitHub App path | A mounted `.pem`. Local convention. |
| `GITHUB_PRIVATE_KEY` | GitHub App path | The PEM contents. Takes precedence over the path; use where secrets are env-vars only. |
| `GITHUB_TOKEN` | `audit --post-issue` | Never pass a token on the command line. |
| `METRICS_AUTH_TOKEN` | Public deployments | Bearer token for `/metrics`. Unset means the endpoint is open — fine on a compose network, not on a public ingress. The api warns at startup when it is unset. |
| `DASHBOARD_AUDIT_PRINCIPALS` | The dashboard's Run audit button | Comma-separated GitHub logins allowed to trigger an on-demand audit. **Unset means nobody**, deliberately: an audit clones a repository and spends your Anthropic credit, so "any signed-in user" is not a safe gate. Case-insensitive. |
| `LANGSMITH_TRACING` / `LANGSMITH_API_KEY` / `LANGSMITH_PROJECT` | Optional | Traces every real Anthropic call. |

Per-agent model, timeout and budget settings are in `codeguard/config.py`.

## Azure

`deploy/azure.sh` provisions and deploys the whole thing: Container Apps (api at one replica,
worker scale-to-zero), Azure Database for PostgreSQL, Container Registry and Log Analytics. It is
idempotent and deletes nothing.

Images are built by `.github/workflows/build-push.yml` on GitHub's runners, not locally — ACR Tasks
are blocked on this subscription's tier, and a local `docker push` cannot be made to work through
some corporate proxies. CI pushes both `:latest` and an immutable `:sha-<7>`.

```bash
SKIP_BUILD=1 ./deploy/azure.sh      # deploy the image CI already built
```

The script will not ship unless `:latest` and this commit's `:sha-` tag resolve to the same digest,
so a stale or someone else's build cannot be deployed under this commit's name. It deploys **by
digest** under a commit-named revision, which is what makes "which commit is running?" answerable
from the revision list.

It pauses once, deliberately, for you to set the app secrets yourself. The script prints the
commands and never handles a secret value — `SKIP_SECRETS_PROMPT=1` skips only that pause, for a
redeploy where the secrets are already known good.

### Deploying while the queue is busy

The worker is updated in a single operation, so no transient revision exists to claim a job and
then be superseded. On `SIGTERM` a worker releases its in-flight job back to the queue with its
attempt count untouched, and the replacement replica picks it up immediately. Deploying during a
review is safe; the review is redelivered rather than half-finished.

## Dashboard

`/dashboard/repos` is the control panel and the signed-in landing view: every repository CodeGuard
is installed on, whether it's active, when it was last reviewed, how many reviews and what they
cost. Repositories are connected and disconnected on **GitHub's own installation settings page**,
which the page links to prominently — that page is the on/off switch and is not reimplemented here.
A repository that's installed but has never been reviewed still appears, with an empty state.

`/dashboard` lists every recorded review: findings by trust bucket, cost, gate result, and a
before/after diff of each fix suggestion. Filters live in the query string, so a filtered view is a
URL you can share. `Ctrl`/`Cmd`+`K` jumps to a repo, pull request or file. A bare visit to
`/dashboard` while signed in redirects to the repositories page; any URL carrying filters or a page
number does not, so shared links keep working.

### On-demand audits

An audit scans every reviewable file in a repository rather than one pull request's diff. It runs
as a `repo_audit` job on the existing queue — never inline in the request — and the page polls
until it finishes, then renders the report. A failed audit shows the reason it failed.

Two limits worth knowing up front:

- **Audit mode produces no fix suggestions.** Fixes are anchored to a diff, and an audit has none.
  The UI says so rather than leaving it to be discovered.
- **Private repositories cannot be audited.** The audit clones over HTTPS, and the clone URL is
  echoed into logs and into stored error text, so a credentialed URL would leak. Public only, for
  now.

One audit at a time per repository, enforced by a partial unique index rather than by a check in
the route: a double-clicked button or two open tabs get redirected to the audit already running
instead of starting a second one.

Public repositories are visible to anyone; private ones require a signed-in GitHub identity that
GitHub confirms can access the repository. Visibility is recorded per review when the review runs,
and anything unknown is treated as private.

Access control expects Azure Container Apps' built-in auth in allow-anonymous mode in front of the
app, with `/webhook`, `/health`, `/ready` and `/metrics` excluded from it. `/webhook` keeps its own
HMAC verification and `/metrics` its bearer token — neither can follow a login redirect.
