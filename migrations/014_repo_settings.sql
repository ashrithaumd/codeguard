-- Per-repository settings, starting with the "PR reviews" switch.
--
-- ON: every pull_request delivery (opened / synchronize) is queued for the
-- normal automatic review. OFF: the delivery is acknowledged and dropped --
-- no job, no LLM call, no check run, no comment. Full audits are unaffected;
-- they only ever start from the dashboard's Run audit button.
--
-- A repository with NO row is OFF. That is the safe direction for a switch
-- that controls spend, and it is what makes "new repositories default to
-- OFF" true without anything having to notice that a repository is new.
--
-- IDEMPOTENT, like every migration here: bootstrap_schema() applies every
-- migrations/*.sql on EVERY api and worker startup.

CREATE TABLE IF NOT EXISTS repo_settings (
    owner               TEXT NOT NULL,
    repo                TEXT NOT NULL,
    pr_reviews_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by          TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Case-insensitive, like GitHub's own names: "AshrithaUMD/RelIQueue" and
-- "ashrithaumd/reliqueue" are one repository. Keyed by name, the same as
-- reviews and audits; a renamed repository starts OFF under its new name,
-- which costs nothing.
CREATE UNIQUE INDEX IF NOT EXISTS repo_settings_owner_repo
    ON repo_settings (lower(owner), lower(repo));

-- ---------------------------------------------------------------------
-- Seed: ON for every repository that has had a REAL review.
-- ---------------------------------------------------------------------
-- Before this table existed every installed repository was reviewed, so a
-- repository with reviews is one somebody was relying on; turning it OFF on
-- deploy would silently stop its reviews.
--
-- Sample data is excluded. scripts/seed_demo.py labels every row it writes:
-- pr_title starts "[SAMPLE]" and summary_body starts "SAMPLE DATA", and its
-- predecessor wrote under the fake owner "codeguard-fixtures". Either label
-- is enough to exclude a row.
--
-- Safe to re-run on every startup: ON CONFLICT DO NOTHING never touches an
-- existing row, so a switch the operator turned OFF stays OFF.
INSERT INTO repo_settings (owner, repo, pr_reviews_enabled, updated_by)
SELECT DISTINCT ON (lower(owner), lower(repo)) owner, repo, TRUE, 'migration 014'
FROM reviews
WHERE pr_title NOT LIKE '[SAMPLE]%'
  AND summary_body NOT LIKE 'SAMPLE DATA%'
  AND owner <> 'codeguard-fixtures'
ORDER BY lower(owner), lower(repo), created_at DESC
ON CONFLICT DO NOTHING;
