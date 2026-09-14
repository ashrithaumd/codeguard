from functools import lru_cache
from pydantic import BaseModel, Field
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
