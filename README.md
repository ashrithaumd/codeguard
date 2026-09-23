# CodeGuard

Self-hosted AI code reviewer for LLM applications. Bring your own Anthropic key.

It runs real scanners first (Bandit, Semgrep, Ruff, OSV), then has an LLM judge each finding in
context — confirm with a severity, or dismiss with a cited reason. The model never invents a
security finding a scanner didn't already produce. On top of that sits a custom Semgrep ruleset for
LLM-integration code itself: 27 rules mapped to the OWASP Top 10 for LLM Applications.

## What it actually posts

A real review comment from the hosted deployment on
[codeguard-playground#5](https://github.com/ashrithaumd/codeguard-playground/pull/5), anchored to
lines 2–3 so committing the suggestion replaces both:

> **[security / HIGH] B608**
>
> SQL injection vulnerability confirmed. The query uses string formatting (`'%s' % email`) to
> directly interpolate user input into the SQL statement, allowing an attacker to inject arbitrary
> SQL code. For example, an email value of `' OR '1'='1` would bypass authentication.
>
> <details><summary>Also flagged by 2 other agent(s)</summary>
>
> - [quality-agent] Use parameterized queries instead of string formatting.
> - [test-agent] SQL injection in `get_user_by_email` is not tested.
> </details>
>
> ````suggestion
> ```suggestion
>     query = "SELECT * FROM users WHERE email = ?"
>     cursor.execute(query, (email,))
> ```
> ````

Bandit found it, the security agent confirmed it and set the severity, the fix agent wrote the
replacement, and three agents' duplicate findings were folded into one comment. That review cost
**$0.0046** and took **13.5s**.

## Quickstart

**1. Audit a repo — the only thing you need is an Anthropic key.** No Docker, no Postgres, no
GitHub App.

```bash
pip install -e .
export ANTHROPIC_API_KEY=sk-ant-...
codeguard audit .                      # or a git URL
codeguard audit . --output report.md
```

Verified on a clean clone into a bare `python:3.12-slim`: `pip install -e .` pulls Semgrep, Bandit
and Ruff, and `codeguard audit` runs the scanners, the eval-hygiene checks and the verdict agents,
then writes a markdown report with findings, dismissals and cost. `ANTHROPIC_API_KEY` is the only
setting without a default — everything else is optional.

**2. MCP server** — same pipeline, from Claude Code or Cursor, against your uncommitted changes:

```bash
python -m codeguard.mcp.server          # stdio; exposes review_diff and audit_repo
```

**3. GitHub App** — reviews every pull request automatically and gates merges on a Check Run.
That's the full deployment: Postgres, a queue, a worker. See **[docs/github-app.md](docs/github-app.md)**
to set it up and **[docs/self-host.md](docs/self-host.md)** to run it.

## What it catches

27 Semgrep rules for LLM-integration code, in `rules/llm-security.yaml`, each carrying an `owasp`
metadata field. Examples:

- **LLM01 Prompt Injection** — untrusted input concatenated into a prompt; a LangChain
  `PromptTemplate.from_template(f"...")`, where the f-string interpolates at construction time and
  defeats the templating.
- **LLM05 Improper Output Handling** — model output flowing into `eval()`, a raw SQL `execute()`,
  or an HTML response; `PandasQueryEngine`, which evals model-written pandas.
- **LLM06 Excessive Agency** — a `PythonREPLTool` or `ShellTool` handed to an agent;
  `allow_dangerous_code=True`.

Coverage is LLM01/02/03/05/06/10. **LLM04, LLM07, LLM08 and LLM09 have no rules at all**, on
purpose — data poisoning is a property of where data came from and misinformation of whether output
is true, and neither is visible in a call shape. Rules for them would be keyword matches dressed up
as security checks.

## Numbers

Every figure below is from a real run. Labelled by what produced it.

**Live pull request** (hosted Azure deployment, `reviews` table, 2026-09-22 21:14 UTC): the PR #5
review above — **$0.004567**, 1,053 in / 138 out tokens, 13.47s, 3 inline comments, 1 fix
suggestion.

**Real repositories, Semgrep only** ($0, no LLM calls):

| Repo | Size | Findings | Triage |
|---|---|---|---|
| [langflow](https://github.com/langflow-ai/langflow) @ 1.12.3 | 4,104 files, ~847k lines | 33 | 11 true positives in reviewable code; 20 in `docs/`, which CodeGuard's own filter excludes; 2 false positives fixed |
| [simonw/llm](https://github.com/simonw/llm) @ 0.36 | 54 files, ~37k lines | 24 → **0** | all 24 were wrong, one root cause, fixed |
| this repo | — | 0 | — |

The langflow run is the better evidence, and not because of the true-positive count: **9 of the 11
are timeout/max-tokens hygiene**, and the sharper LLM01/LLM05 rules got no real-code hit either
way. What it did catch was a **false negative** — `from openai import OpenAI` then
`OpenAI(api_key="...")` matched nothing, because every hardcoded-key pattern required the `openai.`
module prefix. A rule that silently matches nothing looks exactly like a clean scan. That find is
worth more than the count.

Two caveats on simonw/llm's 0: **0 findings is not 0 false negatives**, and it is a carefully
written codebase — the 0 is partly a fact about Simon's code, not only about the rules.

**Fixture-based** (`evals/`, synthetic fixtures written for this project): Security precision 1.00 /
recall 1.00 / dismissal accuracy 1.00 across 3 live runs. **The AI-aware, Quality and Test agent
numbers are stale and deliberately not quoted here** — the ruleset went from 10 rules to 27, the
generative agents' contract changed, and two ground-truth entries were corrected on 2026-09-23. See
the staleness audit in [`evals/RESULTS.md`](evals/RESULTS.md) for exactly what changed and why
nothing was re-measured.

## Limitations

- **Injection handling removes matched spans from the prompt; it does not stop prompt injection.**
  Recognised patterns are stripped and replaced with a marker before the call is built, and the
  review continues on what is left. Obfuscated or encoded payloads pass the regex layer untouched —
  the remaining defence there is framing all PR content as data, which is not a proof.
- **The LangChain and LlamaIndex rules are symbol-verified, not behaviour-verified.** Symbols were
  introspected against real installs; the patterns have no real-code hit yet. `download_loader` is
  **gone** from current llama-index and matches nothing; `torch.load`'s `weights_only` and Django's
  `mark_safe` are **unverified** — neither package was installed. Each rule records its own status
  in a `verified` metadata field.
- **Hunk-scoped review can misjudge whole-function facts**, and dismissals are Bandit/Semgrep-only,
  never Ruff. Detail in [ARCHITECTURE.md](ARCHITECTURE.md#limitations).

## Docs

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — the pipeline agent by agent, guardrails, the queue,
  LangGraph, deployment, and the design decisions with their reasons.
- **[docs/github-app.md](docs/github-app.md)** — creating, permissioning and installing the App.
- **[docs/self-host.md](docs/self-host.md)** — local compose, tests, `.codeguard.yml`, environment
  variables, Azure.
- **[evals/RESULTS.md](evals/RESULTS.md)** — every measurement, including a wrong finding CodeGuard
  produced about its own code.

## Author

Built by **Ashritha** — [github.com/ashrithaumd](https://github.com/ashrithaumd) ·
ashritha@umd.edu
