-- On-demand repository audits, triggered from the dashboard rather than
-- by a webhook.
--
-- A separate table from `reviews` even though both record "CodeGuard
-- looked at some code and cost money". They answer different questions
-- and have different lifecycles: a review is one pass over one push and
-- is immutable once written, while an audit is a request that moves
-- through queued -> running -> done|failed and is WRITTEN THREE TIMES.
-- Folding them together would put a mutable status machine into the
-- table the dashboard's economics queries aggregate over, and would
-- mean every reviews query had to learn to exclude rows that are not
-- finished yet.
--
-- The job row in `jobs` is the unit of WORK; this is the unit of
-- REQUEST. They are 1:1 but deliberately separate, for the same reason
-- 006 keeps `reviews` out of `jobs`: the queue's row is deleted or
-- dead-lettered on failure and carries no room for a report, while the
-- thing a user has a URL open on must survive whatever the queue does.
CREATE TABLE IF NOT EXISTS audits (
    id                  UUID PRIMARY KEY,
    owner               TEXT NOT NULL,
    repo                TEXT NOT NULL,

    -- The GitHub login that asked for it, from EasyAuth's principal
    -- header. Recorded rather than derived so "who spent this money"
    -- stays answerable after the allow-list changes.
    requested_by        TEXT NOT NULL,

    -- Recorded at request time from the repo's own visibility, exactly
    -- as reviews.private is, and for the same reason (see 007): a render
    -- time lookup is a lookup that can fail, and a failing visibility
    -- lookup has no safe guess. Same TRUE default, same direction.
    private             BOOLEAN NOT NULL DEFAULT TRUE,

    status              TEXT NOT NULL DEFAULT 'queued'
                          CHECK (status IN ('queued', 'running', 'done', 'failed')),

    -- The queue row that does the work. Nullable because the audit row
    -- is inserted FIRST -- the unique index below is what decides
    -- whether this request is allowed to exist at all, so it has to be
    -- committed before a job is enqueued. A row with job_id still NULL
    -- is one whose enqueue failed, and the reaper's max_attempts never
    -- applies to it because no job was ever created.
    job_id              UUID,

    -- Result. All null until the worker finishes.
    --
    -- report_markdown is the rendered audit report, stored whole. It is
    -- bounded by the audit's own file and token budgets (effective_budget
    -- caps files and tokens per run), so this is tens of KB, not
    -- unbounded -- the same reasoning that lets reviews.summary_body be
    -- a TEXT column rather than a blob reference.
    report_markdown     TEXT,
    exit_code           INT,

    -- Why it failed, in the user's words not a stack trace. run_audit
    -- already returns (exit_code, error_message) precisely so a caller
    -- can show the real reason -- git clone failed, target is not a
    -- repository -- instead of an empty report with no explanation.
    -- The UI requirement that "a failed audit must say why" is the
    -- reason that return shape exists at all.
    error               TEXT,

    -- Economics, same columns and same meaning as reviews', so the two
    -- can be summed without reconciling units.
    tokens_in           INT NOT NULL DEFAULT 0,
    tokens_out          INT NOT NULL DEFAULT 0,
    estimated_cost_usd  DOUBLE PRECISION NOT NULL DEFAULT 0,
    duration_s          DOUBLE PRECISION NOT NULL DEFAULT 0,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ
);

-- ONE audit in flight per repo, enforced by the database rather than by
-- a SELECT-then-INSERT in the route.
--
-- This is the whole concurrency answer. Two browser tabs, or a
-- double-clicked button, or a retried POST all race the same check; a
-- partial unique index makes the second one fail on INSERT, which the
-- route turns into "you already have one running, here it is" rather
-- than a second job spending a second lot of money on the same repo.
--
-- Partial on the in-flight states specifically, so a repo can be
-- audited any number of times over its life -- the constraint is on
-- CONCURRENCY, not on history.
CREATE UNIQUE INDEX IF NOT EXISTS audits_one_in_flight_per_repo
    ON audits (owner, repo) WHERE status IN ('queued', 'running');

-- The repositories page joins the newest audit per repo.
CREATE INDEX IF NOT EXISTS audits_repo_created_idx
    ON audits (owner, repo, created_at DESC);

-- The poll endpoint reads by id; the list page reads newest-first.
CREATE INDEX IF NOT EXISTS audits_created_idx
    ON audits (created_at DESC);
