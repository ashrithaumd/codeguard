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

### The suite does not cover the image's own permissions

`docker compose exec worker pytest` runs inside a container whose `/app` is a **bind mount of your
working tree**, and that mount is writable. The deployed image's `/app` is root-owned and read-only
to the non-root user it runs as. So the tests cannot see a bug that only exists when `/app` cannot
be written to — and one got through: `ruff` writes its cache to the working directory, failed with
`Permission denied` in Azure, and was silently missing from every audit there while every local
check passed, including a container audit run specifically to verify the non-root switch.

```bash
scripts/smoke_image.sh                       # whatever compose last built
scripts/smoke_image.sh codeguardacr.azurecr.io/codeguard:sha-abc1234
```

It runs one real audit inside the image with **no volume of any kind** and no `--user` override, so
the permissions are the deployed ones, and fails if any scanner reports "did not run" or if the
expected `B608` and `F401` findings are missing. It needs no API key and spends nothing — the key it
passes is deliberately invalid, so a verdict call fails with 401 before it can cost anything.

CI runs it on every build (`.github/workflows/build-push.yml`). Run it by hand before deploying an
image built any other way.

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
| `DASHBOARD_AUDIT_PRINCIPALS` | The dashboard's Run audit button | Comma-separated GitHub **numeric user ids** allowed to trigger an on-demand audit — not logins. `gh api users/<login> --jq .id` gives you one. **Unset means nobody**, deliberately: an audit clones a repository and spends your Anthropic credit, so "any signed-in user" is not a safe gate. A login here is *ignored*, not matched, and the api warns about it by name at startup — ids are used because a renamed login is released for anyone else to register, and would carry this grant with it. |
| `LANGSMITH_TRACING` / `LANGSMITH_API_KEY` / `LANGSMITH_PROJECT` | Optional | Traces every real Anthropic call. |
| `DASHBOARD_AUTH_MODE` | Which sign-in the dashboard uses | `easyauth` (default) or `app`. `easyauth` is the Azure Container Apps built-in; `app` is CodeGuard's own GitHub OAuth flow. Anything else signs everyone out and warns at startup, rather than trusting an unrecognised value. |
| `GITHUB_OAUTH_CLIENT_ID` | `app` mode | The **GitHub App's** client id (`Iv2…`), not an OAuth App's. Not a secret — it travels in a redirect URL the browser follows. |
| `GITHUB_OAUTH_CLIENT_SECRET` | `app` mode | The App's client secret. Sign-in refuses to start without it rather than bouncing someone to GitHub for a flow that cannot finish. |
| `SESSION_SECRET` | `app` mode | HMAC key for the session cookie, **32 characters minimum** — shorter is refused. Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Changing it signs everyone out, which is the intended rotation behaviour. |

Per-agent model, timeout and budget settings are in `codeguard/config.py`.

## Sign-in: EasyAuth or the app's own OAuth

Two modes, switched by `DASHBOARD_AUTH_MODE`, because this is the one subsystem
where a mistake locks everyone out — including whoever would fix it. Rollback is
one environment variable, with no image rebuild and no Azure auth-config edit.

`easyauth` (the default) uses Azure Container Apps' built-in authentication.
`app` uses CodeGuard's own GitHub OAuth flow, which exists because EasyAuth
cannot do three things:

- **Show GitHub's account picker.** `prompt=select_account` is documented by
  GitHub, and EasyAuth drops it — verified: unknown query parameters never reach
  the authorize URL, and the GitHub provider exposes no `loginParameters`. With
  two accounts on one machine GitHub silently reuses whichever session it holds,
  which presents as "I signed in and the dashboard thinks I'm someone else".
- **End a session.** There is no session of ours to end, so nothing we do makes
  the next sign-in ask which account.
- **Provide a user-to-server token**, which phase 2 needs to list a visitor's own
  repositories.

### Turning `app` mode on

1. On the **GitHub App** settings page, add the callback URL:
   `https://<your-api-fqdn>/auth/callback`, and generate a client secret.

   Note these are the **GitHub App's** (client id `Iv2…`). EasyAuth's
   `/.auth/login/github/callback` belongs to a *separate OAuth App*
   (`Ov23…`) and is configured on that registration — nothing here touches
   it, which is exactly why rolling back works: the EasyAuth registration is
   left intact and untouched throughout.
2. Generate a client secret on that page if there isn't one.
3. Store the two secrets as Container Apps **secrets**, not plain env vars:

   ```bash
   az containerapp secret set -n codeguard-api -g codeguard-prod        --secrets github-oauth-client-secret=<value> session-secret=<value>
   ```

   `deploy/azure.sh` references them as
   `GITHUB_OAUTH_CLIENT_SECRET=secretref:github-oauth-client-secret` and
   `SESSION_SECRET=secretref:session-secret`. Only `GITHUB_OAUTH_CLIENT_ID`
   and `DASHBOARD_AUTH_MODE` are plain values — the id is not a secret, since
   it travels in a redirect URL the browser follows.

4. Set `DASHBOARD_AUTH_MODE=app`.
5. Azure EasyAuth can be left **enabled** in allow-anonymous mode: in `app` mode
   the `X-MS-CLIENT-PRINCIPAL` header is ignored outright, so leaving it on
   changes nothing and keeps the rollback one variable away.

### Rolling back

```bash
az containerapp update -n codeguard-api -g codeguard-prod     --set-env-vars DASHBOARD_AUTH_MODE=easyauth
```

That is the whole rollback. No rebuild, no auth-config change, no GitHub App
edit. Everyone signed in through the app flow is signed out, because their
cookie stops being read; EasyAuth's own session is untouched and takes over
again. Leave `SESSION_SECRET` in place — removing it is not part of rolling
back, and a missing secret means the app flow cannot be turned on again without
re-generating one.

### Why the header is ignored in `app` mode

Under EasyAuth, identity is trustworthy because the Azure ingress **strips**
`X-MS-CLIENT-PRINCIPAL` from any request that arrives carrying one — verified
live, not assumed. That property is Azure's. Once sign-in is ours, nothing
strips it, so the header becomes attacker-controlled like any other and reading
it would hand anyone any identity. In `app` mode the only source of identity is
the signed session cookie.

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
