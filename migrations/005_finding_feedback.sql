-- Phase 10 feedback loop. fingerprint (Finding.fingerprint) is the
-- cross-PR identity: the same weakness reported on two different PRs
-- in the same repo carries the same fingerprint, so a suppression or
-- a feedback signal recorded against it applies wherever that exact
-- finding would otherwise recur.

-- Maps a GitHub comment CodeGuard itself posted back to the finding it
-- was about — populated once, right after post_review() succeeds, by
-- parsing the hidden `<!-- codeguard-fingerprint:... -->` marker
-- worker/main.py appends to every inline comment body (see
-- _findings_to_review_comments). This is what lets a threaded REPLY to
-- one of our comments (pull_request_review_comment's `in_reply_to_id`)
-- be traced back to a specific fingerprint.
CREATE TABLE IF NOT EXISTS posted_finding_comments (
    owner        TEXT NOT NULL,
    repo         TEXT NOT NULL,
    comment_id   BIGINT NOT NULL,
    pr_number    INTEGER NOT NULL,
    fingerprint  TEXT NOT NULL,
    posted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, repo, comment_id)
);

-- Every recognized feedback signal, kept even after a fingerprint is
-- suppressed — this is the audit trail, not just current state.
-- fingerprint is NULL when the comment couldn't be tied to a specific
-- finding (an issue_comment isn't threaded to any inline comment at
-- all — see codeguard/api/routes/webhooks.py's own notes on this).
CREATE TABLE IF NOT EXISTS finding_feedback (
    id            BIGSERIAL PRIMARY KEY,
    owner         TEXT NOT NULL,
    repo          TEXT NOT NULL,
    fingerprint   TEXT,
    pr_number     INTEGER NOT NULL,
    comment_id    BIGINT NOT NULL,
    commenter     TEXT NOT NULL,
    signal        TEXT NOT NULL,  -- 'positive' | 'negative' | 'false_positive'
    body          TEXT NOT NULL,
    source_event  TEXT NOT NULL, -- 'pull_request_review_comment' | 'issue_comment'
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finding_feedback_repo_fingerprint_idx
    ON finding_feedback (owner, repo, fingerprint);

-- A fingerprint marked false_positive by a repo maintainer's reply —
-- checked by worker/main.py before every future review in that repo
-- (see codeguard/queue/feedback.py's fetch_suppressed_fingerprints)
-- so the same finding never resurfaces there again. Scoped to
-- (owner, repo): a coincidentally-identical fingerprint in a different
-- repo is unaffected.
CREATE TABLE IF NOT EXISTS suppressed_findings (
    owner          TEXT NOT NULL,
    repo           TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    reason         TEXT NOT NULL,
    suppressed_by  TEXT NOT NULL,
    suppressed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, repo, fingerprint)
);
