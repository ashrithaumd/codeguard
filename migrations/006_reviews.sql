-- One row per completed review. The per-review aggregates the pipeline
-- already computes — cost, tokens, latency, budget outcome, what was
-- dropped, the posted body — lived only in final_state: logged at INFO,
-- counted into Prometheus, then discarded. "What did the review of PR #7
-- at commit abc123 actually cost, and what did it say?" was unanswerable
-- after the fact. This is that record.
--
-- Additive to Prometheus, not a replacement. Prometheus remains
-- authoritative for fleet-wide rates (codeguard_agent_cost_usd_total,
-- agent_call_duration_seconds); this table answers the different question
-- of per-review, attributable, joinable-to-findings-and-feedback history.
--
-- Append-only, keyed by job_id: one GitHub delivery -> one job -> one
-- review. A `synchronize` on the same PR is a new delivery, so it gets
-- its own row rather than overwriting. The history is the point —
-- comparing review 2 against review 1 of the same PR is what makes the
-- hunk-cache payoff visible (far lower tokens_in on the re-review),
-- which nothing can currently show. head_sha says which commit each row
-- reviewed; "current state of PR #N" is ORDER BY created_at DESC LIMIT 1,
-- since there is no such thing as *the* review of a PR, only the latest.
--
-- ============================ SECURITY =====================================
-- EVERY TEXT/JSONB FIELD IN THIS TABLE MUST BE HTML-ESCAPED BEFORE IT IS
-- RENDERED ANYWHERE. No exceptions, no "this one is ours".
--
-- Nothing here newly persists untrusted content — summary_body is output
-- CodeGuard already published to GitHub, and findings_json holds the same
-- tool messages that already went into a PR comment. But RENDERING it in a
-- page we serve is a new surface. codeguard/tools/models.py's Finding
-- carries an explicit warning that `message` is tool-generated yet can echo
-- fragments of the scanned code (Bandit's hardcoded-secret message
-- literally includes the matched string) — i.e. text a PR author controls.
-- codeguard/pipeline/nodes.py's _build_findings_block already treats it as
-- untrusted on the way INTO a prompt for exactly that reason.
--
-- GitHub renders those strings in its own sandbox with its own sanitiser.
-- A dashboard we write does not inherit that. `file`, `rule_id` and
-- `message` inside findings_json/dismissed_json, the `reason` strings in
-- filtered_files_json and verdict_call_failures_json, the `path` values
-- throughout, and summary_body are all attacker-influenceable via PR
-- content. Escape on output, always.
-- ==========================================================================
CREATE TABLE IF NOT EXISTS reviews (
    -- Not an FK to jobs: matches posted_comments.job_id and dead_letters.id,
    -- which both carry a job reference without a constraint. Dead-lettered
    -- jobs are DELETEd from `jobs`, so an FK would need ON DELETE semantics
    -- for a case that cannot arise here (a review row only exists when the
    -- job succeeded) at the cost of a constraint that could block cleanup.
    job_id                      UUID PRIMARY KEY,
    owner                       TEXT NOT NULL,
    repo                        TEXT NOT NULL,
    pr_number                   INTEGER NOT NULL,
    head_sha                    TEXT NOT NULL,
    action                      TEXT NOT NULL,   -- 'opened' | 'synchronize'

    -- What the human actually saw. check_conclusion is NULL when no Check
    -- Run was created (start_check_run returned nothing). gate/fix
    -- thresholds are the RESOLVED RepoConfig values, stored so a row stays
    -- interpretable without re-reading a .codeguard.yml that has since
    -- changed.
    summary_body                TEXT NOT NULL,
    check_conclusion            TEXT,
    gate_threshold              TEXT NOT NULL,
    fix_threshold               TEXT NOT NULL,

    -- Scalars, so a dashboard aggregates without traversing JSONB.
    --
    -- The four finding buckets are a TRUST classification derived from
    -- Finding.source_tool, which already encodes it: _apply_verdicts builds
    -- a NEW Finding with source_tool=<agent> when a verdict confirms one,
    -- while the unaddressed-rule backfill and the failed-call fallback both
    -- re-emit the RAW findings with their original tool name.
    --
    --   verdict_confirmed  security, ai_aware      an LLM judged it in context
    --   generative         quality-agent, test-agent  an LLM invented it (capped MEDIUM)
    --   deterministic      ruff, osv, eval-hygiene    no verdict layer exists for this source
    --   unverified         bandit, semgrep, unknown   a verdict layer EXISTS but this
    --                                                 finding bypassed it
    --
    -- "deterministic" vs "unverified" is the distinction worth keeping:
    -- Ruff/OSV/eval-hygiene are never routed to an agent by design
    -- (route_to_file_reviews: "lint/style output needs no interpretation"),
    -- so their being unverified means nothing went wrong. A raw `bandit`
    -- finding is different — review_security claims every file's Bandit
    -- findings, so one arriving raw means a call failed or the model left
    -- a rule_id unaddressed.
    --
    -- HONEST LIMIT: `unverified` mixes three causes and cannot fully
    -- separate them. Semgrep passes through by design on non-AI-touching
    -- files and whenever enable_ai_aware is off; a verdict call may have
    -- failed; or the model may have left a rule_id unaddressed (logged as
    -- a WARNING, not recorded in state). verdict_call_failures_json
    -- identifies the failure subset only. Do not read this column as
    -- "things that went wrong".
    --
    -- An unrecognised source_tool is classified `unverified` — the
    -- conservative default, since claiming verification we cannot prove is
    -- the worse error.
    files_seen                  INT NOT NULL,
    files_reviewed              INT NOT NULL,
    findings_total              INT NOT NULL,
    findings_verdict_confirmed  INT NOT NULL,
    findings_generative         INT NOT NULL,
    findings_deterministic      INT NOT NULL,
    findings_unverified         INT NOT NULL,
    dismissed_count             INT NOT NULL,
    inline_count                INT NOT NULL,
    fix_suggestion_count        INT NOT NULL,

    -- Budget outcome. budget_exceeded is currently computed and then shown
    -- nowhere — not in the PR comment (a 40-file PR truncated to 15 reads
    -- as a complete review), not in any store. filtered_files_json holds
    -- every drop with its reason, budget and non-budget alike (non-Python,
    -- docs, pure deletion), since which filter dropped what is exactly the
    -- question this is meant to answer.
    budget_exceeded             BOOLEAN NOT NULL DEFAULT FALSE,
    filtered_files_json         JSONB NOT NULL DEFAULT '[]'::jsonb,  -- [{path, reason}]

    -- Economics. duration_s is the review handler's own wall clock,
    -- measured inside handle_pull_request_review — deliberately NOT
    -- process_job's JOB_PROCESSING_SECONDS, which is the caller's timer and
    -- also covers ack and this very write.
    tokens_in                   INT NOT NULL DEFAULT 0,
    tokens_out                  INT NOT NULL DEFAULT 0,
    estimated_cost_usd          DOUBLE PRECISION NOT NULL DEFAULT 0,
    duration_s                  DOUBLE PRECISION NOT NULL DEFAULT 0,
    node_latencies_json         JSONB NOT NULL DEFAULT '[]'::jsonb,  -- [{node, file, seconds}]

    -- Detail, for drill-in. Same Pydantic-JSON convention as
    -- hunk_findings.findings_json. fix_suggestions_json is JSONB rather
    -- than its own table because nothing queries across reviews on it and
    -- the volume is near-zero (fix_threshold defaults to HIGH; both
    -- evals/RESULTS.md dogfood repos produced zero). Promote it to a table
    -- keyed (job_id, fingerprint) the moment "was this suggestion
    -- accepted?" becomes a question — FixSuggestion already carries the
    -- fingerprint that posted_finding_comments and finding_feedback key on,
    -- so that is a real join waiting to happen, just not yet.
    findings_json               JSONB NOT NULL DEFAULT '[]'::jsonb,
    dismissed_json              JSONB NOT NULL DEFAULT '[]'::jsonb,
    fix_suggestions_json        JSONB NOT NULL DEFAULT '[]'::jsonb,
    verdict_call_failures_json  JSONB NOT NULL DEFAULT '[]'::jsonb,  -- [{path, agent, reason}]

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The buckets partition findings_total exactly. The writer builds them
    -- by partitioning one list, with an explicit fallback bucket, so this
    -- holds by construction — it is here to catch a future writer that
    -- stops doing that, and to make the invariant readable in the schema
    -- rather than only in a test. tests/queue/test_reviews.py asserts the
    -- per-source_tool mapping itself, which this constraint cannot see.
    CONSTRAINT reviews_bucket_sum CHECK (
        findings_verdict_confirmed + findings_generative
        + findings_deterministic + findings_unverified = findings_total
    )
);

-- Drill-in: one PR's review history, newest first.
CREATE INDEX IF NOT EXISTS reviews_pr_idx ON reviews (owner, repo, pr_number, created_at DESC);
-- Listing: one repo's recent reviews.
CREATE INDEX IF NOT EXISTS reviews_repo_idx ON reviews (owner, repo, created_at DESC);
-- Global recent / time-series rollups.
CREATE INDEX IF NOT EXISTS reviews_created_idx ON reviews (created_at DESC);
