# Security

CodeGuard reads code it did not write, sends parts of it to a third party,
and posts the results back into a repository. This document is what that
means in practice: the boundaries, the controls at each one, and the risks
that are accepted rather than eliminated.

It describes the deployed system as of Stage 1. Where a control is
partial, it says so — a security document that only lists what works is
not usable for deciding whether to run this.

## Reporting a vulnerability

Open a GitHub issue if the problem is not itself sensitive.

If it is — anything that would let someone read another user's data, spend
the operator's Anthropic credit, or reach the worker's filesystem — GitHub
private vulnerability reporting is **not currently enabled** on this
repository (checked, rather than assumed). Until it is, open an issue
saying only that you have found something and asking for a private channel,
with no detail in the public text, and give it a few days before
disclosing.

There is no bounty. There is no SLA. This is a self-hosted project run by
one person; an honest statement of that is more useful than a policy
nobody is on call for.

## The trust boundaries

Five, and it is worth being explicit about which side of each one a given
piece of data is on.

| Boundary | Untrusted side | What crosses it |
| --- | --- | --- |
| A reviewed repository | everything in it | file contents, paths, `.codeguard.yml`, PR titles, dependency manifests |
| The Anthropic API | the model's response | JSON verdicts, prose, proposed replacements |
| GitHub, inbound | webhook payloads | events, before HMAC verification |
| GitHub, outbound | — | review bodies, inline comments, check summaries |
| The dashboard | a signed-in visitor | audit requests, filters, URLs |

**Repository content is attacker-controlled.** Not "might be" — the whole
point of the product is to review code somebody else wrote, so any
repository a pull request can be opened against is a repository an
attacker can put content into. Every control below follows from taking
that literally.

## Reviewing untrusted code

**Nothing from a repository is ever executed.** Static analysis only:
Bandit, Semgrep, Ruff and OSV read files; nothing is imported, no build
runs, no test suite runs, no `setup.py` is evaluated. Clones are hardened
against the ways git itself can be made to execute or reach outside the
tree — `core.hooksPath=/dev/null`, `protocol.file.allow=never`,
`protocol.ext.allow=never`, `--no-recurse-submodules`,
`GIT_LFS_SKIP_SMUDGE=1`, and a two-minute timeout. See
`codeguard/cli.py`.

**Symlinks cannot escape the clone.** Two layers, because one is not
enough: `core.symlinks=false` makes git materialise a link as an inert
text file containing its target path, and `_collect_repo_files` re-checks
on read — it skips symlinks, requires `is_file()`, and requires the
resolved path to stay under the resolved root. The first layer can be
wrong; the second catches a file created between the clone finishing and
the walk starting. Before both existed, a repository containing
`link -> /app/.env` had its contents read and sent to the model.

**Hard limits, enforced before the work rather than during it.** A
repository over 244 MB (`MAX_REPO_SIZE_KB`, 250,000 KB) is refused from
GitHub's own API answer, before anything is cloned. File and token ceilings bound what is scanned, and a
wall-clock deadline is checked at every point where stopping is safe —
including inside the per-chunk LLM loop, so a large repository cannot run
past the budget one chunk at a time. Every tool has its own timeout.

**The clone is always removed**, in a `finally`, on every path including
the timeout and crash paths.

**A repository with no Python is refused before any model call**, so a
tree of nothing but Markdown costs one clone and nothing else.

## Secrets

Redaction is **upstream**, not at render time. It was render-time only
once, which meant a secret found in a repository was stored unredacted in
`reviews.findings_json`, written to the worker's logs, returned by the
JSON endpoint — and sent to Anthropic in the prompt. See
`codeguard/redact.py`.

Two paths carry a secret, and the second is the larger one:

1. **Finding messages.** Bandit's `B105`/`B106`/`B107` messages quote the
   matched string, so "a secret is hardcoded here" contains the secret.
2. **The source itself.** The prompt includes file content, so
   `API_KEY = "sk-live-…"` reaches the model whether or not any scanner
   noticed it.

`redact_source` handles the second and is line-preserving: findings are
line-anchored, and the general-purpose `redact()` collapses a multi-line
PEM block onto one line, which would shift every line number below a key.

**Fingerprints are derived from the original message, not the redacted
one.** The fingerprint is `sha256(f"{file}:{rule_id}:{start_line}:{message}")`,
so redacting before hashing would change the fingerprint of every finding
that mentioned a secret and silently orphan every suppression stored
against it.

**A proposed fix containing the redaction mask is refused outright.** The
fix agent writes its replacement from text that was redacted before being
sent, so on a secret-bearing line it cannot see what it is replacing, and
`API_KEY = "[redacted]"` committed into a repository is worse than no
suggestion at all.

**Private repositories cannot be audited.** Not a permission limit but a
capability one: the audit clones over HTTPS, and a credentialed clone URL
would appear in the worker's logs and in stored error text.

## Prompt injection

Treated as a certainty, not a risk. The controls run in both directions,
and the outbound direction is the one that took longest to get right.

**Inbound.** `guardrails.neutralize_injections` strips instruction-shaped
spans before the prompt is assembled, replaces each with a marker, logs
its fingerprint and counts it. The review continues on what is left
rather than being skipped. Redaction runs first, so a secret is gone
before any other pass can log or fingerprint the text it appeared in.

**Architecturally.** The agents that decide anything are
verdict-contract agents: they are given findings a deterministic tool
already produced and may only confirm or dismiss them. A model cannot
invent a CRITICAL. Generative agents (quality, test) can raise findings
but are capped at MEDIUM and cannot gate a pull request. `.codeguard.yml`
is read for configuration and never placed in a prompt.

**Outbound, which is where an injection would actually escape.** The
interesting payload is not one that makes the model misbehave; it is one
that gets a string echoed into a GitHub comment, because a comment has
effects a dashboard page does not: `@someone` notifies a real person from
the operator's App, `#1234` cross-references their issue permanently, and
GitHub permits enough raw HTML that a message can forge structure —
a convincing "CodeGuard: no issues found" inside CodeGuard's own comment.
This needs no cooperation from the model at all: Bandit quotes the matched
string, so a payload in a string literal rides out on a deterministic
tool's message.

Everything posted goes through `codeguard/github/outbound.py`:
HTML-escaped, mentions and issue references defused, length bounded.
Model-authored dismissal reasons get the same treatment, and they need it
most — they are written inside a `<details>` block a `</details>` would
escape.

## The dashboard

**Identity** comes from Azure Container Apps' EasyAuth, which runs in
allow-anonymous mode: it annotates authenticated requests and passes
everything through, so **authorization is this application's job**. The
`X-MS-CLIENT-PRINCIPAL-NAME` header is trusted only because EasyAuth
strips it from requests that arrive without it — which holds only for
traffic through that ingress.

**Every row is access-checked, public repositories included.** A review of
public code may be public information; the *page* is not. Which
repositories someone chose to run a code reviewer over, with review counts
and costs, is a fact about the operator that no repository publishes. This
page leaked all nine of them, by name, to anonymous visitors on a public
URL, because the access check short-circuited to true on `not private`.

**404, never 403**, for anything a visitor may not see — a 403 confirms
existence, which is what a private repository is hiding. Error bodies are
byte-identical between "no such thing" and "not yours".

**An audit is visible to its requester, or to an operator.** Repository
access alone is not enough: a report quotes source and is also a record of
someone's activity. The operator is included because they pay for every
audit and have to diagnose the failed ones.

**Triggering an audit is gated to a named allow-list**
(`DASHBOARD_AUDIT_PRINCIPALS`), which defaults to **nobody**. An audit
clones a repository and spends Anthropic credit, so "any signed-in GitHub
user" is not an acceptable gate. Unset means nobody, for the same reason
`reviews.private` defaults to true: the unset case has to be the safe one.

**CSRF**, on the one state-changing route, with two independent checks
because each covers the other's weakness: an Origin/Referer check (script
cannot forge it, but some clients omit it) and a double-submit token in a
`SameSite=Strict`, `HttpOnly` cookie (an attacker's page cannot read it,
but a cookie-writing attacker on a sibling host could plant both halves —
and Container Apps serves this from `*.azurecontainerapps.io` alongside
other tenants' apps). See `codeguard/api/csrf.py`.

**One audit in flight per requester**, as a partial unique index rather
than a check in a route, so two tabs or a retried POST cannot produce two
clones and two bills.

**Security headers** on every browser-facing response, with a per-response
CSP nonce: `default-src 'none'`, `frame-ancestors 'none'`, no
`'unsafe-inline'` in `script-src`, nosniff, `Referrer-Policy: no-referrer`
(dashboard URLs carry owner, repo and PR number), and HSTS on HTTPS
requests only. `/webhook`, `/health`, `/ready` and `/metrics` are exempt:
machine clients, where a CSP protects nothing.

**`/metrics` is bearer-token authenticated.** It was publicly reachable on
the Container Apps ingress once, serving repository names, job counts and
cost. An unset token leaves it open — a deliberate fail-open so a missing
variable cannot break metrics collection everywhere at once — and startup
logs a warning when it is unset.

**Webhooks are HMAC-verified** with `compare_digest` before the payload is
parsed.

**Stored text is escaped, not rendered.** Jinja2 autoescape is on and no
template applies `|safe` to stored data. `summary_body` is Markdown that
GitHub rendered inside its own sanitiser; we do not inherit that, so it is
shown as escaped text.

## Accepted risks

These are live. Each is here because the cost of removing it is currently
judged higher than the risk, and that judgement is written down so it can
be disagreed with.

**`style-src-attr 'unsafe-inline'` in the CSP.** The bar charts set widths
and heights from computed numbers (`style="width: 41.3%"`), which no
stylesheet can express. Moving them to CSS custom properties would not
remove the need — `style="--w: 41.3%"` is still an inline style attribute
and needs the same permission. The directive permits inline style
*attributes* only: not `<style>` blocks, and nothing about script. The
values are numbers passed through Jinja's `|round`, never repository text.
Residual risk: an attacker who could already inject markup into a page
could style it. They would need an autoescape bypass first, at which point
this is not the binding constraint.

**The dashboard is effectively single-tenant.** Any signed-in GitHub user
who is a collaborator on a repository can see that repository's reviews.
There is no per-installation tenancy model. Closed as won't-do for this
stage: the deployment has one operator, and a real tenancy model is a
schema change, not a patch. Anyone running this for more than one
organisation should not rely on the dashboard for isolation.

**Markdown is not escaped in outbound comments.** `**bold**` in a finding
message renders bold. The goal is that our output cannot *act* — notify,
cross-link, execute — not that it cannot be styled; escaping every
metacharacter would make real findings unreadable (`*args`, `_private`,
backticked code) for no security gain.

**Model output is bounded, not verified.** A proposed fix is checked
against the file it claims to replace, refused if it would break parsing,
refused if it targets a line outside the diff, and refused if it contains
the redaction mask — but a suggestion that is confidently wrong in a way
none of those catch will still be offered. A human clicks "commit
suggestion".

**One Anthropic API key, one account.** Repository content is sent to
Anthropic's API. Zero-data-retention terms are not configured. An operator
for whom that is unacceptable should not run the AI agents at all
(`enable_ai_aware: false` and a `fix_threshold` above every severity get
close, but the honest answer is that this product's value is the model).

**The `metrics` fail-open above** is the one place in this codebase where
an unset variable weakens a control rather than strengthening it.

**The worker runs as a non-root user, and did not until Stage 1.** Before
that, an audit ran as root in the worker container. Nothing is known to
have exploited it, but for most of this project's life the controls above
were the only thing between a reviewed repository and the container's
filesystem, which is thinner than it should have been.

## What is not implemented

Stated so nobody infers it from silence.

- No rate limiting on the dashboard beyond the one-audit-per-user index.
- No audit log of who viewed what.
- No secret scanning as a *finding* — secrets are redacted, not reported.
- No SAST beyond what Bandit, Semgrep and Ruff provide; no dependency
  vulnerability database beyond OSV.
- No sandboxing of the scanners themselves. Bandit, Semgrep and Ruff parse
  attacker-controlled files in the worker's own process tree. A parser
  vulnerability in one of them is a real path in, and the non-root user is
  the only thing between that and the container.
- No signing or attestation of what is posted.
