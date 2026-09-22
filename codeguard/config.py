from functools import lru_cache
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from codeguard.severity import Severity


class Settings(BaseSettings):
    """Deployment config. One instance, process-wide, loaded once from
    the environment (and .env in dev). Never varies per repo — a repo
    cannot influence any field here, only the ceiling fields below."""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    anthropic_api_key: str
    # Optional (default ""), not required — `codeguard audit` and the
    # MCP server both call get_settings() (every review node does, for
    # its own *_agent_model/timeout fields) but neither one ever calls
    # codeguard.queue.db.create_pool() or touches the GitHub App at all
    # for their core operation, so requiring a real Postgres URL and
    # App ID just to run a standalone analysis tool would be pure
    # friction — same "shared Settings, different entry points have
    # different needs" reasoning as github_webhook_secret below.
    database_url: str = ""
    github_app_id: str = ""
    # Optional (default ""), not because it's unimportant — api's webhook
    # route depends on it for every signature check — but because
    # Settings is one shared class loaded by both api and worker, and
    # worker has no webhook endpoint to verify: it never reads this
    # field at all. Requiring it unconditionally would force the
    # worker's own deployment to carry a copy of a secret it has no
    # use for, purely to satisfy validation.
    github_webhook_secret: str = ""
    # Local dev: a file path (secrets/*.pem, gitignored) — see .env.example.
    # Azure: Container Apps secrets are env-vars, not mounted files, so
    # github_private_key (the PEM content itself) takes
    # precedence when set; build_app_jwt() falls back to reading
    # github_private_key_path only when it's empty. Both default to ""
    # rather than being required, since exactly one of the two must be
    # set and pydantic-settings has no built-in "exactly one of" — see
    # build_app_jwt()'s own check for the actual enforcement.
    github_private_key_path: str = ""
    github_private_key: str = ""

    # Bearer token guarding /metrics. Empty = unauthenticated, which is
    # what local compose and the Prometheus container rely on, and is
    # also what production ran with until this was added — the endpoint
    # was publicly reachable on the Container Apps ingress and served
    # repo names, job counts and cost to anyone who asked. It is NOT
    # behind EasyAuth, deliberately: EasyAuth would redirect Prometheus'
    # scrape to a login page, so a token it can send as a header is the
    # only gate that works for a machine client.
    #
    # Defaulting to "" rather than being required follows
    # github_webhook_secret above: a local run must not need a secret to
    # start. api/main.py logs a warning at startup when it is unset, so
    # "open in production" is loud rather than silent.
    metrics_auth_token: str = ""

    # Dev-only override for the identity EasyAuth injects
    # (X-MS-CLIENT-PRINCIPAL-NAME). Lets the dashboard's signed-in paths
    # be exercised locally, where no EasyAuth sits in front. Read ONLY
    # when dashboard_trust_dev_principal is also true, so setting a
    # username alone can never spoof identity in a deployment that
    # forgot to unset it.
    dashboard_dev_principal: str = ""
    dashboard_trust_dev_principal: bool = False

    # Global hard ceilings — operator-controlled, override-able via env
    # vars, but never per-repo. A repo's RepoConfig can only ask for
    # *less* than these, never more. See effective_budget().
    max_files_per_pr_ceiling: int = 50
    max_tokens_per_pr_ceiling: int = 200_000
    max_wall_clock_s_ceiling: int = 300

    # `codeguard audit` scans a whole repo, not one PR's worth of
    # changed hunks — an unbounded audit against a large
    # public repo is exactly the "must not run away" cost risk a PR
    # review's own ceilings were never sized for. A separate, lower
    # ceiling (not a config knob on the PR-review path at all) means
    # tightening audit's cost profile can never accidentally loosen a
    # real PR review's, and vice versa. See effective_budget()'s
    # `ceiling` parameter for how this actually gets applied instead of
    # the PR-review ceiling.
    audit_max_files_ceiling: int = 30
    audit_max_tokens_ceiling: int = 100_000
    audit_max_wall_clock_s_ceiling: int = 180

    # Queue / connection pool. Small per-process max_size is deliberate:
    # Azure Database for PostgreSQL Flexible Server has a hard total
    # connection cap, and this pool size is per *replica* — at
    # `--scale worker=N`, total worker connections alone are
    # N * queue_pool_max_size, before the api service's own pool or
    # Postgres's reserved superuser connections. Each worker only ever
    # holds ~1 connection at a time given batch_size=1, so this can stay
    # small without hurting throughput.
    queue_pool_min_size: int = 1
    queue_pool_max_size: int = 5
    # "prefer" (not "require") so local docker-compose Postgres — which
    # has no SSL configured at all — keeps working over plaintext.
    # Azure Flexible Server does offer SSL, so "prefer" already upgrades
    # automatically there; set DB_SSLMODE=require via env in that
    # deployment specifically to make it mandatory rather than best-effort.
    db_sslmode: str = "prefer"

    # Lease / heartbeat. Startup validation (see codeguard/worker/main.py)
    # enforces heartbeat_interval_seconds well below lease_seconds.
    lease_seconds: int = 30
    heartbeat_interval_seconds: int = 10
    reaper_interval_seconds: float = 1.0
    max_delivery_attempts: int = 5
    base_backoff_seconds: float = 1.0
    max_backoff_delay_seconds: float = 60.0
    queue_batch_size: int = 1
    queue_poll_interval_seconds: float = 1.0
    worker_metrics_port: int = 9000

    # A GitHub review with hundreds of inline comments is unusable and
    # can hit GitHub's own API limits. Above this many inlineable
    # findings, the top-N by severity go inline; the rest are listed in
    # the review's summary body instead of being dropped.
    max_inline_comments: int = 25

    # Model per-agent, never hardcoded in the node itself — AI-aware,
    # Security, Quality, Test, and Fix each get their own *_agent_model
    # fields here rather than sharing one, so cost/quality tuning per
    # agent doesn't require touching node code.
    ai_aware_agent_model: str = "claude-sonnet-4-5"
    ai_aware_agent_max_tokens: int = 2048
    ai_aware_agent_timeout_s: float = 30.0

    # Fail-safe: when False, the AI-aware agent's "dismissed"
    # verdicts are ignored entirely — every Semgrep finding it doesn't
    # explicitly confirm still gets posted, via the same unaddressed-
    # rule_id fallback that already covers a finding the model just
    # never mentions. An operator worried about the agent talking
    # itself out of a real issue can flip this without touching a
    # prompt or redeploying rules.
    ai_aware_dismissals_enabled: bool = True

    # The generic per-file/per-hunk agents. Security shares the
    # AI-aware node's Sonnet tier and verdict contract (it interprets a
    # deterministic tool's real candidates — Bandit's, not Semgrep's).
    # Quality/Test are generative, not verifying — Haiku tier, since
    # they're the highest-volume calls (one per hunk, not per file) and
    # a terse structured-findings task doesn't need Sonnet-level
    # reasoning. Fix is Sonnet (writing a correct patch matters more
    # than cost there); Summary is Haiku (one short paragraph).
    security_agent_model: str = "claude-sonnet-4-5"
    security_agent_max_tokens: int = 1024
    security_agent_timeout_s: float = 30.0
    # Its own fail-safe, independent of ai_aware_dismissals_enabled — an
    # operator might trust one agent's dismissals and not the other's;
    # see nodes.py's _apply_verdicts for what this actually gates.
    security_agent_dismissals_enabled: bool = True

    quality_agent_model: str = "claude-haiku-4-5-20251001"
    quality_agent_max_tokens: int = 512
    quality_agent_timeout_s: float = 20.0

    test_agent_model: str = "claude-haiku-4-5-20251001"
    test_agent_max_tokens: int = 512
    test_agent_timeout_s: float = 20.0

    fix_agent_model: str = "claude-sonnet-4-5"
    fix_agent_max_tokens: int = 1024
    fix_agent_timeout_s: float = 30.0

    summary_agent_model: str = "claude-haiku-4-5-20251001"
    summary_agent_max_tokens: int = 256
    summary_agent_timeout_s: float = 15.0

    # Quality/Test are the only ungrounded agents — no deterministic
    # tool sits in front of them, so they're the only source of
    # findings this pipeline invents from scratch rather than verifies.
    # Three controls bound the noise that can introduce: a hard
    # per-hunk cap (the worst single hunk can still only produce this
    # many findings, sorted by severity/confidence before the cut — see
    # nodes.py's _parse_direct_findings), a severity ceiling (an LLM's
    # opinion on naming/structure is never HIGH/CRITICAL — clamped down
    # to this even if the model reports higher), and a confidence-gated
    # inline/summary split so a low-confidence finding still gets
    # reported, just not inline (see summarize()). 0.5 was validated
    # against 132 real findings from dogfooding two real repos (see
    # evals/RESULTS.md): it demotes only the bottom ~8% by
    # confidence, and manual review of exactly those demoted findings
    # showed them to be the genuinely vaguest/most nitpicky ones, not
    # ones that should have stayed inline — kept unchanged rather than
    # moved without evidence either direction was actually better.
    quality_test_max_findings_per_hunk: int = 3
    quality_test_max_severity: Severity = Severity.MEDIUM
    quality_test_min_inline_confidence: float = 0.5

    @field_validator("quality_test_max_severity", mode="before")
    @classmethod
    def _parse_quality_test_max_severity(cls, v):
        """Same string-to-Severity parsing as RepoConfig.fix_threshold —
        an operator setting this via env var writes QUALITY_TEST_MAX_SEVERITY=medium,
        a string, not the IntEnum value."""
        if isinstance(v, str) and not v.isdigit():
            try:
                return Severity[v.upper()]
            except KeyError:
                pass
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()  # raises at first call if required env vars are missing


class RepoConfig(BaseModel):
    """Per-repo review policy, loaded from `.codeguard.yml`.

    SECURITY: this file is always read from the PR's base branch — the
    branch being merged into — never from the PR head or a fork. PR
    content is untrusted input; if a PR could edit its own
    .codeguard.yml, an attacker could raise their own budget or disable
    the AI-aware agent immediately before submitting the thing it would
    have caught. The loader must enforce reading from the base branch;
    nothing in this schema can override that.

    Fields below are *requests*. What actually gets enforced for a given
    PR is the tighter of this and Settings' global ceilings — see
    effective_budget().
    """
    fix_threshold: Severity = Severity.HIGH
    enable_ai_aware: bool = True
    max_files_per_pr: int = 15
    # Validated against real numbers, not a guess (see evals/RESULTS.md's
    # tuning section). A real 15-file, budget-capped
    # PR (both codeguard's and DocuMind's dogfood runs landed right at
    # this ceiling) costs ~$0.15-0.24 and ~110-165s wall clock across
    # every agent combined — this hunk-content budget is what's fed
    # into ingestion, not total LLM token usage, which fans out several
    # times higher across the per-file/per-hunk agent calls that
    # actually read it. That real cost/latency is acceptable for what
    # it buys (60-70 real findings per dogfooded PR), so 40_000 stays
    # the default rather than being changed without evidence it's
    # actually too high or too low.
    max_tokens_per_pr: int = 40_000
    max_wall_clock_s: int = 120
    ignored_paths: list[str] = Field(default_factory=list)
    # The GitHub Check Run's conclusion — "failure" (blocks a
    # merge, if the repo turns this into a required check in its branch
    # protection rules) when ANY confirmed finding (across every agent,
    # same set fix_threshold reads) is >= this severity, else "success".
    # Deliberately its own field, not reusing fix_threshold: a repo
    # might want fixes proposed at HIGH but only actually GATE a merge
    # at CRITICAL — conflating the two would force one severity to serve
    # both a "trust this enough to auto-suggest a fix" decision and a
    # "trust this enough to block a human's merge" decision, which are
    # different bars. Defaults conservative (CRITICAL only) since this
    # is a new, unproven-in-the-wild feature — a repo can tighten it
    # once they trust the false-positive rate for their own codebase.
    gate_threshold: Severity = Severity.CRITICAL

    @field_validator("fix_threshold", "gate_threshold", mode="before")
    @classmethod
    def _parse_severity_string(cls, v):
        """A human writing .codeguard.yml writes `fix_threshold: high`,
        a string — Severity itself is an IntEnum (see severity.py's own
        docstring). Case-insensitive; anything not a valid name falls
        through to pydantic's own validation, so a real typo still
        raises clearly rather than being silently swallowed here.
        """
        if isinstance(v, str) and not v.isdigit():
            try:
                return Severity[v.upper()]
            except KeyError:
                pass
        return v


class Budget(BaseModel):
    """What's actually enforced for one PR review: always min(repo
    request, global ceiling) per dimension."""
    max_files: int
    max_tokens: int
    max_wall_clock_s: int


def effective_budget(repo: RepoConfig, settings: Settings, ceiling: Budget | None = None) -> Budget:
    """`ceiling=None` (every real PR review's own call site) builds the
    default from Settings' PR-review global ceilings — Budget(max_files=
    settings.max_files_per_pr_ceiling, max_tokens=settings.max_tokens_per_pr_ceiling,
    max_wall_clock_s=settings.max_wall_clock_s_ceiling) — unchanged
    behavior for every existing caller. `codeguard audit` passes its
    own explicit, lower ceiling instead, built from the audit_*_ceiling
    settings — see Settings' own docstring on those fields for why this
    is a separate ceiling dimension rather than one PR review and audit
    both tune together.
    """
    if ceiling is None:
        ceiling = Budget(
            max_files=settings.max_files_per_pr_ceiling,
            max_tokens=settings.max_tokens_per_pr_ceiling,
            max_wall_clock_s=settings.max_wall_clock_s_ceiling,
        )
    return Budget(
        max_files=min(repo.max_files_per_pr, ceiling.max_files),
        max_tokens=min(repo.max_tokens_per_pr, ceiling.max_tokens),
        max_wall_clock_s=min(repo.max_wall_clock_s, ceiling.max_wall_clock_s),
    )
