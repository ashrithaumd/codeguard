# Changelog

Notable changes, newest first. Anything requiring action from someone running
CodeGuard is marked **ACTION REQUIRED**.

## Unreleased

### Investigated — the dashboard's audit POST returns 403 in production

**Still open.** Not a CodeGuard bug, and nothing is queued or spent when it
happens: the request is refused before the application sees it.

`POST /dashboard/repos/{owner}/{repo}/audit` from a signed-in browser returns a
bare 403 with an empty body. The refusal comes from Azure's own auth
middleware, not from CodeGuard's CSRF check:

```
StatusCode 403, SubStatusCode 60, provider Microsoft-Azure-AppService-Middleware
1.17 ms, empty body, and no "CSRF:" line from the app at all
```

Characterised by probing, rather than reasoned about:

| Request | Result |
| --- | --- |
| `POST /health` (an `excludedPath`) | 405 from FastAPI — reaches the app |
| `POST /dashboard/search`, **signed in** | 403, empty — never reaches the app |
| `POST /dashboard/repos`, **signed in** | 403, empty — never reaches the app |
| `POST /dashboard/search`, **anonymous** | 405 — reaches the app |
| …anonymous with same-origin, foreign, or absent `Origin` | 405 in all three |

So the trigger is an **authenticated cookie session on a non-GET request**, not
the route, the body, the token or the Origin. CodeGuard's own CSRF check is
ruled out: it never runs, and it is scheme-agnostic by construction
(`_cross_site` compares `urlsplit(origin).netloc`, not the URL), which
`tests/api/test_csrf.py` now pins against production's header shape.

**`--proxy-convention Standard` was tried and did not fix it.** Recorded so
nobody tries it twice:

```
before:  httpSettings = null
applied: az containerapp auth update -n codeguard-api -g codeguard-prod \
             --proxy-convention Standard
after:   httpSettings = {"forwardProxy": {"convention": "Standard"}}
revert:  az containerapp auth update -n codeguard-api -g codeguard-prod \
             --proxy-convention NoProxy
```

The revert is applied. `excludedPaths` and `unauthenticatedClientAction` were
unchanged throughout. A revision restart was needed for the setting to be
picked up at all, and it changed neither the 403 nor the behaviour below.

### Noted — EasyAuth honours `X-Forwarded-Host` in the login redirect

Pre-existing, **not** introduced by the setting above and **not** removed by
reverting it — verified in both states:

```
$ curl -H 'X-Forwarded-Host: evil.example' .../.auth/login/github
location: https://github.com/login/oauth/authorize?...
          &redirect_uri=https%3A%2F%2Fevil.example%2F.auth%2Flogin%2Fgithub%2Fcallback
```

**Severity: low, and the reason matters.** A browser cannot be made to send
`X-Forwarded-Host` — it sends the real `Host`. So there is no link, form or
page that causes a victim's browser to produce this request; an attacker can
only send it themselves, redirecting their own browser and gaining nothing.
Anyone positioned to inject headers in front of the ingress already has more
than this.

Whether GitHub rejects the forged `redirect_uri` is **unverified**. GitHub
defers that validation until after sign-in, so an unauthenticated probe only
reaches its login redirect. It was not pursued further because this account has
already authorized the App: a signed-in visit to that authorize URL could have
GitHub issue a code straight to the forged host instead of prompting, which is
not a risk worth taking to confirm a mitigation.

### Fixed — identity was keyed on the GitHub display name

**ACTION REQUIRED if you set `DASHBOARD_AUDIT_PRINCIPALS`: it now takes numeric
GitHub user ids, not logins.** A login there is ignored rather than matched, so
an unchanged value means the audit button disappears. `gh api users/<login> --jq
.id` gives you the id; the api names any ignored entry in a startup warning.

The dashboard read `X-MS-CLIENT-PRINCIPAL-NAME`, which Azure EasyAuth builds
from the `claims/name` claim — the GitHub **display name**, not the login. Every
access decision therefore asked GitHub about a collaborator who does not exist.
Measured on the deployed build: 11 repositories installed, 11 fetched, **0
rendered, for everyone including the owner**.

It was not only an outage. A display name is free text, mutable and **not
unique**, and the collision is not hypothetical — the two accounts this
deployment is tested with share one:

| account | id | display name |
| --- | --- | --- |
| `ashrithaumd` | 183667058 | Ashritha Pola |
| `AshrithaPola` | 60956648 | Ashritha Pola |

Two different people, one identity string. It failed **closed**, because the
allow-list held a login that neither display name matched, so nobody gained
access and no credit was spent. The tempting repair — putting the display name
in the allow-list — would have made it fail **open**, handing operator rights
and the Anthropic bill to whoever else shared it.

Identity now comes from `urn:github:login` in the `X-MS-CLIENT-PRINCIPAL`
claims blob, with the immutable numeric id from `urn:github:id`. There is no
fallback to the display name: a request whose login claim is missing is treated
as signed out. The display name is shown in the nav and used for nothing else.

Repo access stays keyed on the login, because GitHub's collaborator endpoint is
keyed on username — and that path is self-correcting, since after a rename
EasyAuth reports the new login and GitHub answers for it. The allow-list is the
only place a name is *stored*, so it is the only place a rename matters: a
released login can be re-registered by somebody else, who would inherit the
grant. Hence ids there, and only ids.

The claim names were read off a live request rather than taken from
documentation, via a temporary diagnostic that logged claim *types* and
comparison booleans only, never values.

### Fixed — the test fixtures bypassed the migration lock

The three `pool` fixtures hand-rolled `bootstrap_schema`'s loop, which made
them the only migration runners not taking the advisory lock added above — and
the api's `TestClient` lifespan calls the real one against the same test
database. An unlocked copy racing a locked one produced `DeadlockDetected`
during fixture setup, reported against whichever unrelated test came next.
Exactly the failure the lock exists to prevent, reached by writing a second
implementation that opted out of it. All three now call `bootstrap_schema`.

### Added — SECURITY.md

The trust boundaries, the control at each one, the risks accepted rather than
fixed, and what is not implemented. The last two sections are the ones worth
reading: `style-src-attr 'unsafe-inline'`, the effectively single-tenant
dashboard, unescaped Markdown in outbound comments, the `/metrics` fail-open,
and the fact that the scanners themselves parse attacker-authored files in the
worker's own process tree with nothing but an unprivileged user between a parser
bug and the container.

### Changed — the worker no longer runs as root

**No action needed**, but worth knowing if you have customised the image. The
container now runs as uid 10001 with its own home directory. `/app` is
deliberately left root-owned and read-only to that user, so a process reviewing
untrusted code cannot modify the code reviewing it; `$HOME` is writable because
Semgrep and tiktoken both cache there and neither is graceful without it.

Before this, an audit ran as root — and an audit hands three parsers a
repository somebody else wrote.

### Fixed — output posted to GitHub is now neutralised

Every inbound path was guarded and the two biggest outbound ones were not: the
inline review comment body and the review body's "additional findings" list
interpolated finding text raw, as did the dismissed-findings block.

That matters because a GitHub comment has effects a dashboard page does not.
`@someone` in a finding message **notifies a real person from your App**, and
it needs no cooperation from the model at all — Bandit's hardcoded-secret
message quotes the matched string, so a payload in a string literal rides out
on a deterministic tool. `#1234` cross-references someone else's issue.
`</details>` escapes the collapsed block a dismissal sits in.

If you have run CodeGuard against a repository you do not control, it was
possible for that repository to make your App mention arbitrary GitHub users.
Nothing needs rotating and no credential was exposed; the consequence was
notifications sent in your name.

### Fixed — an audit no longer reports "clean" when it did not look

`No findings.` was printed whenever the finding list was empty, including when
files had been dropped by the budget, every AI verdict call had failed, or **no
scanner had run at all**. The last was invisible: the "tool unavailable"
meta-finding was silently filtered out of the audit path, so an audit in an
image without Bandit and Semgrep reported no findings over a repository full of
SQL injection. A run with no scanners now stores as `failed`, not `done`.

### Fixed — an audit is visible to its requester, not to anyone with repo access

The audit page and its poll endpoint authorized on repository access, while the
409-on-conflict path was written on the premise that an audit is visible only to
its requester. Nothing leaked — every audit so far was the operator's own — but
the rule is now what the code always claimed: requester, or an operator.

### Added — CSRF protection and security headers on the dashboard

The audit trigger was authorized by identity alone, and identity arrives in a
cookie, so a form on any page you visited while signed in could spend your
Anthropic credit and hold your one in-flight audit slot. Now Origin-checked and
token-checked. Every browser-facing response carries a CSP with a per-response
nonce, `frame-ancestors 'none'`, nosniff, `Referrer-Policy: no-referrer`, and
HSTS over HTTPS.

### Fixed — concurrent startup no longer deadlocks the schema migration

The api and the worker both run migrations at startup and a deploy starts them
together. Measured: six concurrent runs, four `DeadlockDetected` failures, each
of which fails a container start. Now serialised on a Postgres advisory lock.

### Fixed — credential redaction in audit targets

**ACTION REQUIRED — rotate the token if you have run `codeguard audit` with a
credentialed URL and `--post-issue`.**

`codeguard audit` accepts any target string, and
`https://<token>@github.com/owner/repo` is the ordinary way to hand git a
personal access token. That target was printed, stored and rendered
unredacted in seven places. Two of them fired on **success**, not only on
failure:

- the `Cloning <target>...` line on stderr — every remote audit
- the audit report's own first line, `# CodeGuard audit: <target>` — every
  successful remote audit
- `git clone failed: <git's stderr>`, and the `<target> is not a directory`
  error
- the `audits.report_markdown` / `audits.error` columns and the dashboard page
  that renders them
- the worker's log line for a failed audit
- **a GitHub Issue body, via `--post-issue`**

The last one is why this is marked action-required. An issue body on a public
repository is world-readable the moment it is created, is indexed, and survives
deletion in GitHub's own event stream. **If you have ever run
`codeguard audit <credentialed-url> --post-issue`, treat that token as
disclosed and rotate it.** Deleting the issue is not sufficient.

Git's own masking does not cover this. Verified against git directly: it masks
a credential in the *password* position and echoes one in the *username*
position verbatim.

    https://user:SECRET@host   ->  "Authentication failed for
                                    'https://github.com/owner/repo.git/'"   masked
    https://SECRET@host        ->  "could not read Password for
                                    'https://ghp_AAAA...@github.com'"       LEAKED

Fixed at the source in `run_audit`, so all three callers benefit — the CLI, the
MCP server's `audit_repo` tool, and the dashboard's `repo_audit` job. The
unredacted target now reaches the `git clone` subprocess and nothing else.
`post_issue` redacts its body again independently, because that sink is public
and permanent and should not depend on its caller.

`redact()` gained a pattern for the username-position shape
(`scheme://secret@host`), which the existing URL pattern missed because it
required a `user:secret@` colon.

**Checked for prior disclosure in this deployment:** 30 days of Log Analytics —
0 vendor-token matches, 0 URL-credential matches, and 0 `Cloning` lines at all.
No `audits` table existed yet. No credentialed URL or audit-report header in git
history. Nothing leaked here; nothing to rotate.

### Added — Repositories page and on-demand audits

`/dashboard/repos` lists every repository CodeGuard is installed on, with its
activity and cost, and is the signed-in landing view. Connecting and
disconnecting links out to GitHub's own installation settings.

Audits run as a `repo_audit` job on the existing queue. Gated to an explicit
allow-list, `DASHBOARD_AUDIT_PRINCIPALS`, which **defaults to nobody** — an
audit spends the operator's own Anthropic credit, so "any signed-in user" is
not a safe gate. One audit at a time per repository, enforced by a partial
unique index.

Two known limits, both stated in the UI: audit mode produces no fix
suggestions, and private repositories cannot be audited.

### Changed — reaper logging

Zero-row reaper sweeps log at DEBUG instead of INFO. Measured in production:
3,577 lines/hour, every one of them `swept 0 row(s)`. Sweeps that requeue or
dead-letter something, and sweeps slower than 5x the configured interval, stay
at INFO. `reaper_interval_seconds` is unchanged.

### Added — startup check for a missing API key

An unset `ANTHROPIC_API_KEY` now produces one line and exit code 2 at every
entry point, instead of a pydantic traceback. A key that is set but invalid is
unaffected and still takes the existing degraded path.

## Decisions

### The hosted dashboard stays single-tenant. Multi-tenancy is the Action. (2026-09-26)

**Closed as won't-do.** Recorded so it is not re-litigated.

The hosted dashboard resolves repositories from *one* installation — the
operator's. A different GitHub user signing in would see the operator's
repositories rather than their own. Making it per-user requires resolving
installations per authenticated user:

    GET /user/installations                        -> that user's installations
    GET /user/installations/{id}/repositories      -> repos in one, scoped to them

Both need a **user-to-server token issued by a GitHub App**. We cannot get one:

| | Client ID | |
|---|---|---|
| GitHub App `codeguard-review-bot` (4934663) | `Iv23liMt21lUXpodO0tx` | `Iv` = GitHub App |
| EasyAuth's GitHub provider | `Ov23liiicptHTowTyLLD` | `Ov` = **OAuth App** |

Different applications. An OAuth App token is rejected by those endpoints —
*"You must authenticate with an access token authorized to a GitHub App in order
to list installations"* — and there is no `login.tokenStore` configured, so
`X-MS-TOKEN-GITHUB-ACCESS-TOKEN` is never injected and no `login.scopes` are set.

Enabling it would mean: repointing EasyAuth at the GitHub App's client id and
secret, provisioning a blob container and managed identity for the token store,
widening OAuth scopes to `repo` and `read:org`, and **forcing every existing
user to re-consent to CodeGuard reading their private repository list**. That is
the same infrastructure-and-privacy escalation rejected earlier the same day for
per-user dashboard scoping, arriving from a different direction.

**The GitHub Action is the answer instead.** Each user runs it in their own
repository with their own Anthropic key: there is no installation to resolve, no
user token needed, and no consent to collect. Multi-tenancy falls out of the
execution model rather than being bolted onto a single-tenant dashboard.

Meanwhile the hosted dashboard is **safe rather than merely undisclosed**: every
row is access-checked per viewer, so a signed-in stranger sees nothing.
Single-tenant is now a capability limit, not a disclosure.

> **CORRECTION (2026-09-27).** That last sentence was presented as verified live
> and it was not. The evidence offered was that a second account saw zero
> repositories — but on the deployed build **every** account saw zero, including
> the owner, because the dashboard identified users by their GitHub *display
> name* rather than their login. A stranger seeing nothing and the owner seeing
> nothing were the same failure, so the observation distinguished nothing.
>
> The in-process tests covering this pass `principal="ashrithaumd"` directly,
> which **bypasses the header-to-principal step that was broken**. They are
> evidence about the access filter, not about the identity feeding it.
>
> The access filter itself is unchanged and still believed correct. What is no
> longer claimed is that the signed-in-stranger case has been verified
> end-to-end on the deployed system.

## Notes for future work

### The GitHub Action must use the sanitized path

A planned CodeGuard Action takes a repository target the same way the CLI does,
which means it inherits exactly the exposure fixed above — and an Action's logs
are attached to a workflow run, which on a public repository is world-readable.

The Action must call `run_audit`, which redacts internally, rather than
assembling its own clone command or its own report header. If it ever needs to
print or store a target itself, it passes it through `codeguard.redact.redact`
first. Any `${{ secrets.* }}` interpolated into a target URL is exactly the
username-position shape that git echoes verbatim.

`tests/cli/test_audit_credential_leak.py` is the regression suite; an Action
that routes through `run_audit` is covered by it already.
