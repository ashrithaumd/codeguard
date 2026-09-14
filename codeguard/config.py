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
    database_url: str
    github_app_id: str
    github_webhook_secret: str
    github_private_key_path: str

    # Global hard ceilings — operator-controlled, override-able via env
    # vars, but never per-repo. A repo's RepoConfig can only ask for
    # *less* than these, never more. See effective_budget().
    max_files_per_pr_ceiling: int = 50
    max_tokens_per_pr_ceiling: int = 200_000
    max_wall_clock_s_ceiling: int = 300

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

    # GitHub review reviews with hundreds of inline comments are
    # unusable and can hit GitHub's own API limits. Above this many
    # inlineable findings, the top-N by severity go inline; the rest
    # are listed in the review's summary body instead of being dropped.
    max_inline_comments: int = 25

    # Model per-agent, never hardcoded in the node itself — Phase 6's
    # AI-aware agent is the first real LLM call; Phase 7's Security/
    # Quality/Test/Fix agents get their own *_agent_model fields here
    # rather than sharing one, so cost/quality tuning per agent doesn't
    # require touching node code.
    ai_aware_agent_model: str = "claude-sonnet-4-5"
    ai_aware_agent_max_tokens: int = 2048
    ai_aware_agent_timeout_s: float = 30.0


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
    have caught. The loader (Phase 3) must enforce reading from the base
    branch; nothing in this schema can override that.

    Fields below are *requests*. What actually gets enforced for a given
    PR is the tighter of this and Settings' global ceilings — see
    effective_budget().
    """
    fix_threshold: Severity = Severity.HIGH
    enable_ai_aware: bool = True
    max_files_per_pr: int = 15
    # TODO(Phase 9): tune this default against real eval-harness token
    # counts once we have precision/recall/cost numbers, not a guess.
    max_tokens_per_pr: int = 40_000
    max_wall_clock_s: int = 120
    ignored_paths: list[str] = Field(default_factory=list)

    @field_validator("fix_threshold", mode="before")
    @classmethod
    def _parse_severity_string(cls, v):
        """A human writing .codeguard.yml writes `fix_threshold: high`,
        a string — Severity itself is an IntEnum (see severity.py's own
        docstring: this exact parsing was deliberately deferred to
        Phase 3, when a real YAML loader would finally exist to need it).
        Case-insensitive; anything not a valid name falls through to
        pydantic's own validation, so a real typo still raises clearly
        rather than being silently swallowed here.
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


def effective_budget(repo: RepoConfig, settings: Settings) -> Budget:
    return Budget(
        max_files=min(repo.max_files_per_pr, settings.max_files_per_pr_ceiling),
        max_tokens=min(repo.max_tokens_per_pr, settings.max_tokens_per_pr_ceiling),
        max_wall_clock_s=min(repo.max_wall_clock_s, settings.max_wall_clock_s_ceiling),
    )
