# Changelog

Notable changes, newest first. Anything requiring action from someone running
CodeGuard is marked **ACTION REQUIRED**.

## Unreleased

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
